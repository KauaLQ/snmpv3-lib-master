#include "include/SNMPPacket.h"
#include "USM.h" // <<< 1. INCLUIR USM.h PARA ACESSO A ESTRUTURAS E FUNÇÕES

#define SNMP_PARSE_ERROR_AT_STATE(STATE) ((int)STATE * -1) - 10 + SNMP_PACKET_PARSE_ERROR_OFFSET

#define ASN_TYPE_FOR_STATE_SNMPVERSION  INTEGER
#define ASN_TYPE_FOR_STATE_COMMUNITY    STRING
#define ASN_TYPE_FOR_STATE_REQUESTID    INTEGER
#define ASN_TYPE_FOR_STATE_ERRORSTATUS  INTEGER
#define ASN_TYPE_FOR_STATE_ERRORID      INTEGER
#define ASN_TYPE_FOR_STATE_VARBINDS     STRUCTURE
#define ASN_TYPE_FOR_STATE_VARBIND      STRUCTURE

#define STR_IMPL_(x) #x      //stringify argument
#define STR(x) STR_IMPL_(x)  //indirection to expand argument macros

#define ASSERT_ASN_TYPE_AT_STATE(value, TYPE, STATE) \
    if(!value || value->_type != TYPE) { \
        SNMP_LOGW("Expecting value to be " STR(TYPE) " for " #STATE); \
        return SNMP_PARSE_ERROR_GENERIC; \
    }

#define ASSERT_ASN_STATE_TYPE(value, STATE) \
    if(!value || value->_type != ASN_TYPE_FOR_STATE_##STATE) { \
        SNMP_LOGW("Expecting " STR(ASN_TYPE_FOR_STATE_##STATE) " for " #STATE " failed: %d\n", value->_type); \
        return SNMP_PARSE_ERROR_AT_STATE(STATE); \
    }

#define ASSERT_ASN_PARSING_TYPE_RANGE(value, LOW_TYPE, HIGH_TYPE) \
    if(!value || !(value->_type >= LOW_TYPE && value->_type <= HIGH_TYPE)){ \
        SNMP_LOGW("Expecting vartype for PDU failed: %d\n", value->_type); \
        return SNMP_PARSE_ERROR_GENERIC; \
    }

SNMPPacket::~SNMPPacket(){
    delete this->packet;
}

// <<< 2. A MÁQUINA DE ESTADOS parsePacket FOI EXPANDIDA PARA v3
SNMP_PACKET_PARSE_ERROR SNMPPacket::parsePacket(ComplexType *structure, enum SNMPParsingState state) {
    for(const auto& value : structure->values){
        if(state == DONE) break;

        switch(state) {

            case SNMPVERSION:
                ASSERT_ASN_STATE_TYPE(value, SNMPVERSION);
                this->snmpVersionPtr = std::static_pointer_cast<IntegerType>(value);
                this->snmpVersion = (SNMP_VERSION) this->snmpVersionPtr.get()->_value;
                if (this->snmpVersion >= SNMP_VERSION_MAX) {
                    SNMP_LOGW("Invalid SNMP Version: %d\n", this->snmpVersion);
                    return SNMP_PARSE_ERROR_AT_STATE(SNMPVERSION);
                };

                // <<< BIFURCAÇÃO DA LÓGICA AQUI
                if (this->snmpVersion == SNMP_VERSION_3) {
                    state = MSGGLOBALDATA;
                } else {
                    state = COMMUNITY;
                }
            break;

            case COMMUNITY: // Caminho antigo (v1/v2c)
                ASSERT_ASN_STATE_TYPE(value, COMMUNITY);
                this->communityStringPtr = std::static_pointer_cast<OctetType>(value);
                this->communityString = this->communityStringPtr.get()->_value;
                state = PDU;
            break;
            
            // <<< 3. NOVOS ESTADOS PARA PARSING DO CABEÇALHO v3
            case MSGGLOBALDATA:
            {
                // <<< SUBSTITUA ESTE BLOCO INTEIRO >>>
                ASSERT_ASN_TYPE_AT_STATE(value, STRUCTURE, MSGGLOBALDATA);
                auto globalData = static_cast<ComplexType*>(value.get());

                // VERIFICAÇÃO ROBUSTA: Garantir que temos todos os 4 campos necessários
                if (globalData->values.size() < 4) {
                    SNMP_LOGW("msgGlobalData: esperava 4 campos, mas encontrou %d", globalData->values.size());
                    return SNMP_PARSE_ERROR_AT_STATE(MSGGLOBALDATA);
                }

                // VERIFICAÇÃO ROBUSTA: Garantir que cada campo é do tipo correto antes de usar
                if (globalData->values[0]->_type != INTEGER ||
                    globalData->values[1]->_type != INTEGER ||
                    globalData->values[2]->_type != STRING  ||
                    globalData->values[3]->_type != INTEGER) {
                    SNMP_LOGW("msgGlobalData: um ou mais campos com tipo inesperado.");
                    return SNMP_PARSE_ERROR_AT_STATE(MSGGLOBALDATA);
                }

                // Agora que verificamos, podemos acessar os valores com segurança
                this->msgID = static_cast<IntegerType*>(globalData->values[0].get())->_value;
                this->msgMaxSize = static_cast<IntegerType*>(globalData->values[1].get())->_value;
                
                auto msgFlagsOctet = static_cast<OctetType*>(globalData->values[2].get());
                if (msgFlagsOctet->_value.length() != 1) {
                    SNMP_LOGW("msgGlobalData: msgFlags deveria ter 1 byte.");
                    return SNMP_PARSE_ERROR_AT_STATE(MSGGLOBALDATA);
                }
                this->msgFlags = (uint8_t)msgFlagsOctet->_value[0];
                
                this->msgSecurityModel = static_cast<IntegerType*>(globalData->values[3].get())->_value;
                
                state = MSGSECURITYPARAMETERS;
                break;
            }

            case MSGSECURITYPARAMETERS:
            {
                SNMP_LOGD("Entrando no parsing de MSGSECURITYPARAMETERS...");
                // <<< INÍCIO DA CORREÇÃO DEFINITIVA (BASEADA NA SUA ANÁLISE) >>>
                ASSERT_ASN_TYPE_AT_STATE(value, STRING, MSGSECURITYPARAMETERS);
                auto secParamsOctetString = std::static_pointer_cast<OctetType>(value);

                SNMP_LOGD("msgSecurityParameters contém %d bytes:", secParamsOctetString->_value.length());
                for (size_t i = 0; i < secParamsOctetString->_value.length(); ++i) {
                    SNMP_LOGD("Byte %02d: 0x%02X", i, (uint8_t)secParamsOctetString->_value[i]);
                }

                // ETAPA 1: Decodificação Recursiva
                // O conteúdo (value) da Octet String é outra estrutura BER.
                // Vamos criar um novo objeto ComplexType para decodificar esse conteúdo.
                SNMP_LOGD("Tentando decodificar BER interna dos securityParameters...");
                ComplexType innerSecParamsStructure(STRUCTURE);
                SNMP_BUFFER_PARSE_ERROR decodeResult = innerSecParamsStructure.fromBuffer(
                    (const uint8_t*)secParamsOctetString->_value.data(),
                    secParamsOctetString->_value.length()
                );

                SNMP_LOGD("Resultado do fromBuffer: %d", decodeResult);
                
                if (decodeResult <= 0) {
                    SNMP_LOGW("Falha ao decodificar a estrutura BER interna dos securityParameters.");
                    // Usamos o erro -21 que você observou, que provavelmente indica falha estrutural.
                    // Você pode criar um erro mais específico se preferir.
                    return -21; 
                }

                // ETAPA 2: Extração Segura dos Campos
                // Agora, `innerSecParamsStructure.values` contém os campos de segurança decodificados.
                const auto& fields = innerSecParamsStructure.values;

                // Um pacote de descoberta válido tem pelo menos 4 campos. Um pacote autenticado tem mais.
                if (fields.size() < 4) {
                    SNMP_LOGW("Estrutura de securityParameters inválida: esperava pelo menos 4 campos, encontrou %d", fields.size());
                    return -21;
                }

                // Extrai os campos fazendo a verificação de tipo para cada um
                if(fields[0]->_type != STRING) return -21;
                auto engID = std::static_pointer_cast<OctetType>(fields[0]);
                memcpy(this->securityParameters.msgAuthoritativeEngineID, engID->_value.data(), engID->_value.length());
                this->securityParameters.msgAuthoritativeEngineIDLength = engID->_value.length();

                if(fields[1]->_type != INTEGER) return -21;
                this->securityParameters.msgAuthoritativeEngineBoots = std::static_pointer_cast<IntegerType>(fields[1])->_value;
                
                if(fields[2]->_type != INTEGER) return -21;
                this->securityParameters.msgAuthoritativeEngineTime = std::static_pointer_cast<IntegerType>(fields[2])->_value;

                if(fields[3]->_type != STRING) return -21;
                auto uName = std::static_pointer_cast<OctetType>(fields[3]);
                memcpy(this->securityParameters.msgUserName, uName->_value.data(), uName->_value.length());
                this->securityParameters.msgUserNameLength = uName->_value.length();

                // Os parâmetros de autenticação e privacidade são opcionais
                if (fields.size() > 4 && fields[4]->_type == STRING) {
                    auto authParams = std::static_pointer_cast<OctetType>(fields[4]);
                    memcpy(this->securityParameters.msgAuthenticationParameters, authParams->_value.data(), authParams->_value.length());
                    this->securityParameters.msgAuthenticationParametersLength = authParams->_value.length();
                }
                if (fields.size() > 5 && fields[5]->_type == STRING) {
                    auto privParams = std::static_pointer_cast<OctetType>(fields[5]);
                    memcpy(this->securityParameters.msgPrivacyParameters, privParams->_value.data(), privParams->_value.length());
                    this->securityParameters.msgPrivacyParametersLength = privParams->_value.length();
                }
                
                state = SCOPEDPDU;
                // <<< FIM DA CORREÇÃO DEFINITIVA >>>
                break;
            }
            
            case SCOPEDPDU:
            {
                SNMP_LOGD("Entrando no SCOPEDPDU...");
                SNMP_LOGD("SCOPEDPDU: tipo ASN inesperado: 0x%02X", value->_type);
                // A ScopedPDU pode ser um OCTET STRING (se criptografada) ou uma ESTRUTURA (se em texto plano)
                if (value->_type == STRING) { // Criptografada
                    this->scopedPDUPtr = std::static_pointer_cast<OctetType>(value);
                    this->packetPDUType = (ASN_TYPE)0; // Indicamos que a PDU não foi analisada
                } else if ((uint8_t)value->_type >= ASN_PDU_TYPE_MIN_VALUE && (uint8_t)value->_type <= ASN_PDU_TYPE_MAX_VALUE) { // Texto plano
                    this->packetPDUType = value->_type;
                    return this->parsePacket(static_cast<ComplexType*>(value.get()), REQUESTID);
                } else {
                    SNMP_LOGD("Aqui é o erro?...");
                    return SNMP_PARSE_ERROR_GENERIC;
                }
                state = DONE; // Fim do parsing do pacote externo
                break;
            }

            case PDU:
                ASSERT_ASN_PARSING_TYPE_RANGE(value, ASN_PDU_TYPE_MIN_VALUE, ASN_PDU_TYPE_MAX_VALUE)
                this->packetPDUType = value->_type;
                return this->parsePacket(static_cast<ComplexType*>(value.get()), REQUESTID);

            case REQUESTID:
                ASSERT_ASN_STATE_TYPE(value, REQUESTID);
                this->requestIDPtr = std::static_pointer_cast<IntegerType>(value);
                this->requestID = this->requestIDPtr.get()->_value;
                state = ERRORSTATUS;
            break;

            case ERRORSTATUS:
                ASSERT_ASN_STATE_TYPE(value, ERRORSTATUS);
                this->errorStatus.errorStatus = (SNMP_ERROR_STATUS) static_cast<IntegerType *>(value.get())->_value;
                state = ERRORID;
            break;

            case ERRORID:
                ASSERT_ASN_STATE_TYPE(value, ERRORID);
                this->errorIndex.errorIndex = static_cast<IntegerType*>(value.get())->_value;
                state = VARBINDS;
            break;

            case VARBINDS:
                ASSERT_ASN_STATE_TYPE(value, VARBINDS);
                // we have a varbind structure, lets dive into it.
                return this->parsePacket(static_cast<ComplexType*>(value.get()), VARBIND);

            case VARBIND:
            {
                ASSERT_ASN_STATE_TYPE(value, VARBIND);
                // we are in a single varbind

                auto varbindValues = std::static_pointer_cast<ComplexType>(value);

                if (varbindValues->values.size() != 2) {
                    SNMP_LOGW("Expecting VARBIND TO CONTAIN 2 OBEJCTS; %lu\n",
                              varbindValues ? varbindValues->values.size() : 0);
                    return SNMP_PARSE_ERROR_AT_STATE(VARBIND);
                };

                auto vbOid = varbindValues->values[0];
                ASSERT_ASN_TYPE_AT_STATE(vbOid, OID, VARBIND);

                auto vbValue = varbindValues->values[1];
                this->varbindList.emplace_back(
                    std::static_pointer_cast<OIDType>(vbOid),
                    vbValue
                );
            }
            break;

            case DONE:
                SNMP_LOGD("Entrando no DONE...");
                return true;
        }
    }
    return SNMP_ERROR_OK;
}

// <<< 4. NOVA FUNÇÃO PARA ANALISAR A SCOPEDPDU (CHAMADA APÓS DESCRIPTOGRAFIA)
SNMP_PACKET_PARSE_ERROR SNMPPacket::parseScopedPDU(unsigned char* buf, size_t len) {
    SNMP_LOGD("Parsing ScopedPDU from decrypted buffer.");
    ComplexType scopedPDUStructure(STRUCTURE);
    
    SNMP_BUFFER_PARSE_ERROR decodeResult = scopedPDUStructure.fromBuffer(buf, len);
    if (decodeResult <= 0) {
        SNMP_LOGW("Failed to parse decrypted ScopedPDU buffer.");
        return SNMP_PARSE_ERROR_GENERIC;
    }

    // A ScopedPDU tem seu próprio contexto, engineID, etc.
    // ComplexType* contextData = static_cast<ComplexType*>(scopedPDUStructure.values[0].get());
    // ... parse contextEngineID, contextName ...
    
    // O último elemento da ScopedPDU é a PDU real (GetRequest, etc.)
    auto pduValue = scopedPDUStructure.values.back();
    this->packetPDUType = pduValue->_type;

    // Reutilizamos nossa máquina de estados para analisar a PDU interna, começando pelo REQUESTID
    return this->parsePacket(static_cast<ComplexType*>(pduValue.get()), REQUESTID);
}

SNMP_PACKET_PARSE_ERROR SNMPPacket::parseFrom(unsigned char* buf, size_t max_len){
    SNMP_LOGD("Parsing %ld bytes\n", max_len);
    if(buf[0] != 0x30) {
        SNMP_LOGD("First byte error\n");
        return SNMP_PARSE_ERROR_MAGIC_BYTE;
    }

    packet = new ComplexType(STRUCTURE);

    SNMP_BUFFER_PARSE_ERROR decodePacket = packet->fromBuffer(buf, max_len);
    if(decodePacket <= 0){
        SNMP_LOGD("failed to fromBuffer\n");
        return decodePacket;
    }

    // we now have a full ASN.1 packet in SNMPPacket
    return parsePacket(packet, SNMPVERSION);
}

// <<< 5. FUNÇÃO build() ATUALIZADA PARA CHAMAR A LÓGICA v3
bool SNMPPacket::build(){
    // Delete the existing packet if we've built it before
    delete this->packet;
    this->packet = nullptr;

    if (this->snmpVersion == SNMP_VERSION_3) {
        // A construção do pacote v3 é mais complexa e será orquestrada
        // pela função serialiseIntoV3, que lida com criptografia e autenticação.
        // Esta função de build genérica não é mais suficiente para v3.
        // Retornamos true, mas o trabalho real será em serialiseIntoV3.
        return true;
    }

    // Caminho antigo para v1/v2c
    this->packet = new ComplexType(STRUCTURE);
    this->packet->addValueToList(std::make_shared<IntegerType>(this->snmpVersion));
    this->packet->addValueToList(std::make_shared<OctetType>(this->communityString.c_str()));

    auto snmpPDU = std::make_shared<ComplexType>(this->packetPDUType);
    snmpPDU->addValueToList(std::make_shared<IntegerType>(this->requestID));
    snmpPDU->addValueToList(std::make_shared<IntegerType>(this->errorStatus.errorStatus));
    snmpPDU->addValueToList(std::make_shared<IntegerType>(this->errorIndex.errorIndex));

    auto varBindList = this->generateVarBindList();
    if(!varBindList) return false;
    
    snmpPDU->addValueToList(varBindList);
    this->packet->addValueToList(snmpPDU);

    return true;
}

// <<< 6. NOVA FUNÇÃO PARA SERIALIZAR PACOTES v3 (chamada pela SNMPResponse)
int SNMPPacket::serialiseIntoV3(uint8_t* buf, size_t max_len, USM& usm) {
    // 1. Gerar a ScopedPDU em texto plano
    auto scopedPDU = std::make_shared<ComplexType>(STRUCTURE);
    // Adicionar contextEngineID, contextName... (simplificado por enquanto)
    scopedPDU->addValueToList(std::make_shared<OctetType>("")); 
    scopedPDU->addValueToList(std::make_shared<OctetType>("")); 

    auto pdu = std::make_shared<ComplexType>(this->packetPDUType);
    pdu->addValueToList(std::make_shared<IntegerType>(this->requestID));
    pdu->addValueToList(std::make_shared<IntegerType>(this->errorStatus.errorStatus));
    pdu->addValueToList(std::make_shared<IntegerType>(this->errorIndex.errorIndex));
    pdu->addValueToList(this->generateVarBindList());
    scopedPDU->addValueToList(pdu);

    uint8_t scopedPDUBuf[512];
    int scopedPDULen = scopedPDU->serialise(scopedPDUBuf, 512);

    // 2. Criptografar a ScopedPDU se necessário
    // ... Lógica de criptografia aqui usando o USM ...
    // byte encryptedBuf[512];
    // int encryptedLen = usm.encryptPDU(...);
    
    // 3. Construir o pacote v3 completo
    delete this->packet;
    this->packet = new ComplexType(STRUCTURE);
    this->packet->addValueToList(std::make_shared<IntegerType>(this->snmpVersion));
    // Adicionar msgGlobalData
    // Adicionar msgSecurityParameters
    // Adicionar a ScopedPDU (criptografada ou não)
    
    // 4. Serializar o pacote completo
    int finalLen = this->packet->serialise(buf, max_len);

    // 5. Autenticar o pacote serializado (USM calcula HMAC sobre o buffer final)
    // usm.authenticateOutgoingMsg(...);
    
    return finalLen;
}

int SNMPPacket::serialiseInto(uint8_t* buf, size_t max_len){
    if(this->build()){
        return this->packet->serialise(buf, max_len);
    }
    return 0;
}

void SNMPPacket::setCommunityString(const std::string &CommunityString){
    // poison any cached containers we have
    this->communityStringPtr = nullptr;
    this->communityString = CommunityString;
}

void SNMPPacket::setRequestID(snmp_request_id_t RequestId){
    this->requestIDPtr = nullptr;
    this->requestID = RequestId;
}

bool SNMPPacket::setPDUType(ASN_TYPE responseType){
    if(responseType >= ASN_PDU_TYPE_MIN_VALUE && responseType <= ASN_PDU_TYPE_MAX_VALUE){
        //TODO: check that we're a valid response type
        this->packetPDUType = responseType;
        return true;
    }
    return false;
}

void SNMPPacket::setVersion(SNMP_VERSION SnmpVersion){
    this->snmpVersionPtr = nullptr;
    this->snmpVersion = SnmpVersion;
}

std::shared_ptr<ComplexType> SNMPPacket::generateVarBindList(){
    SNMP_LOGD("generateVarBindList from SNMPPacket");
    // This is for normal packets where our response values have already been built, not traps
    auto varBindList = std::make_shared<ComplexType>(STRUCTURE);

    for(const auto& varBindItem : varbindList){
        auto varBind = std::make_shared<ComplexType>(STRUCTURE);

        varBind->addValueToList(varBindItem.oid);
        varBind->addValueToList(varBindItem.value);

        varBindList->addValueToList(varBind);
    }

    return varBindList;
}

snmp_request_id_t SNMPPacket::generate_request_id(){
    //NOTE: do not generate 0
    snmp_request_id_t request_id = 0;
    while(request_id == 0){
        request_id |= rand();
        request_id <<= 8;
        request_id |= rand();
    }
    return request_id;
}
