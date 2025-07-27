#include "include/SNMPResponse.h"
#include "USM.h" // <<< 1. INCLUIR USM.h PARA ACESSO ÀS FUNÇÕES CRIPTOGRÁFICAS

// <<< 2. IMPLEMENTAR A NOVA FUNÇÃO setV3User
void SNMPResponse::setV3User(SNMPV3User* user) {
    this->_v3_user = user;
}


// As funções existentes permanecem as mesmas
bool SNMPResponse::addResponse(const VarBind& response){
    this->varbindList.emplace_back(response);
    return true;
}

bool SNMPResponse::addErrorResponse(const VarBind& response){
    int index = this->varbindList.size() + 1;
    this->varbindList.emplace_back(response);
    
    if(response.errorStatus != NO_ERROR){
        this->errorStatus.errorStatus = response.errorStatus;
        this->errorIndex.errorIndex = index;
    }
    return true;
}

bool SNMPResponse::setGlobalError(SNMP_ERROR_STATUS error, int index, int override){
    if(this->errorStatus.errorStatus == NO_ERROR || (this->errorStatus.errorStatus != NO_ERROR && override)){
        this->errorStatus.errorStatus = error;
        this->errorIndex.errorIndex = index;
    }
    return true;
}

// IMPLEMENTAÇÃO FINAL DE buildV3ReportPacket
int SNMPResponse::buildV3ReportPacket(uint8_t* buf, size_t max_len, USM& usm) {
    SNMP_LOGD("Building SNMPv3 Report Packet.");

    delete this->packet;
    this->packet = new ComplexType(STRUCTURE);

    // 1. Versão
    this->packet->addValueToList(std::make_shared<IntegerType>(SNMP_VERSION_3));

    // 2. Cabeçalho Global (msgGlobalData)
    auto globalData = std::make_shared<ComplexType>(STRUCTURE);
    // Para reports, o msgID pode ser 0 ou o da requisição. 0 é mais seguro.
    globalData->addValueToList(std::make_shared<IntegerType>(0));
    globalData->addValueToList(std::make_shared<IntegerType>(1500)); // Nosso MaxSize
    uint8_t msgFlags = 0x04; // Apenas a flag "reportable"
    globalData->addValueToList(std::make_shared<OctetType>(std::string((char*)&msgFlags, 1)));
    globalData->addValueToList(std::make_shared<IntegerType>(3)); // USM Security Model
    this->packet->addValueToList(globalData);

    // 3. Parâmetros de Segurança (msgSecurityParameters) - CRUCIAL para a descoberta
    // Esta é a informação que o cliente precisa para sincronizar.
    auto secParamsStruct = std::make_shared<ComplexType>(STRUCTURE);
    secParamsStruct->addValueToList(std::make_shared<OctetType>(std::string((char*)usm.getEngineID(), usm.getEngineIDLength())));
    secParamsStruct->addValueToList(std::make_shared<IntegerType>(usm.getEngineBoots()));
    secParamsStruct->addValueToList(std::make_shared<IntegerType>(usm.getEngineTime()));
    secParamsStruct->addValueToList(std::make_shared<OctetType>(std::string("", 0))); // userName vazio
    secParamsStruct->addValueToList(std::make_shared<OctetType>(std::string("", 0))); // auth parameters vazio
    secParamsStruct->addValueToList(std::make_shared<OctetType>(std::string("", 0))); // priv parameters vazio

    uint8_t secParamsBuf[128];
    int secParamsLen = secParamsStruct->serialise(secParamsBuf, 128);
    // Os parâmetros de segurança são empacotados como uma Octet String
    this->packet->addValueToList(std::make_shared<OctetType>(std::string((char*)secParamsBuf, secParamsLen)));

    // 4. ScopedPDU contendo o Report-PDU
    auto scopedPDU = std::make_shared<ComplexType>(STRUCTURE);
    scopedPDU->addValueToList(std::make_shared<OctetType>(std::string("", 0))); // contextEngineID vazio
    scopedPDU->addValueToList(std::make_shared<OctetType>(std::string("", 0))); // contextName vazio

    auto reportPDU = std::make_shared<ComplexType>(ReportPDU);
    reportPDU->addValueToList(std::make_shared<IntegerType>(0)); // requestID é 0
    reportPDU->addValueToList(std::make_shared<IntegerType>(NO_ERROR));
    reportPDU->addValueToList(std::make_shared<IntegerType>(0));
    auto varBindList = std::make_shared<ComplexType>(STRUCTURE);
    auto varBind = std::make_shared<ComplexType>(STRUCTURE);
    varBind->addValueToList(std::make_shared<OIDType>(OID_usmStatsUnknownUserNames));
    // O valor para este OID é um Counter32 indicando o número de ocorrências
    varBind->addValueToList(std::make_shared<Counter32>(1));
    varBindList->addValueToList(varBind);
    reportPDU->addValueToList(varBindList);
    scopedPDU->addValueToList(reportPDU);
    
    this->packet->addValueToList(scopedPDU);

    // Serializa o pacote completo e retorna
    return this->packet->serialise(buf, max_len);
}


// IMPLEMENTAÇÃO FINAL DE serialiseIntoV3
int SNMPResponse::serialiseIntoV3(uint8_t* buf, size_t max_len, USM& usm) {
    if (this->errorStatus.errorStatus == UNKNOWN_USER_NAME) {
        return this->buildV3ReportPacket(buf, max_len, usm);
    }

    if (!_v3_user) {
        SNMP_LOGW("Tentativa de serializar pacote v3 sem um usuário válido!");
        return -1;
    }

    // --- TÓPICO 1: Gerar a ScopedPDU em texto plano ---
    auto pdu = std::make_shared<ComplexType>(this->packetPDUType);
    pdu->addValueToList(std::make_shared<IntegerType>(this->requestID));
    pdu->addValueToList(std::make_shared<IntegerType>(this->errorStatus.errorStatus));
    pdu->addValueToList(std::make_shared<IntegerType>(this->errorIndex.errorIndex));
    pdu->addValueToList(this->generateVarBindList());

    auto scopedPDU = std::make_shared<ComplexType>(STRUCTURE);
    scopedPDU->addValueToList(std::make_shared<OctetType>(std::string((char*)usm.getEngineID(), usm.getEngineIDLength())));
    scopedPDU->addValueToList(std::make_shared<OctetType>(std::string("", 0))); // contextName vazio
    scopedPDU->addValueToList(pdu);

    uint8_t scopedPDUBuf[512];
    int scopedPDULen = scopedPDU->serialise(scopedPDUBuf, 512);

    // --- TÓPICO 2: Criptografar a ScopedPDU, se necessário ---
    uint8_t finalScopedPDUBytes[512];
    int finalScopedPDULen = scopedPDULen;
    uint8_t privacyParameters[8] = {0}; // "Salt" para a criptografia

    if (_v3_user->securityLevel == AUTH_PRIV) {
        // Gera um "salt" aleatório para o IV da criptografia
        for(int i = 0; i < 8; i++) {
            privacyParameters[i] = rand();
        }
        finalScopedPDULen = usm.encryptPDU(*_v3_user, scopedPDUBuf, scopedPDULen, finalScopedPDUBytes, privacyParameters);
    } else {
        memcpy(finalScopedPDUBytes, scopedPDUBuf, scopedPDULen);
    }

    if (finalScopedPDULen <= 0 && _v3_user->securityLevel == AUTH_PRIV) {
        SNMP_LOGW("Falha ao criptografar PDU!");
        return -1;
    }

    // --- TÓPICO 3: Construir o pacote v3 completo (com cabeçalhos) ---
    delete this->packet;
    this->packet = new ComplexType(STRUCTURE);

    this->packet->addValueToList(std::make_shared<IntegerType>(SNMP_VERSION_3));

    // Construir msgGlobalData
    auto globalData = std::make_shared<ComplexType>(STRUCTURE);
    globalData->addValueToList(std::make_shared<IntegerType>(this->requestID));
    globalData->addValueToList(std::make_shared<IntegerType>(1500)); // Nosso MaxSize
    uint8_t msgFlags = (_v3_user->securityLevel == AUTH_PRIV) ? 0x03 : 0x01; // authFlag | privFlag
    msgFlags |= 0x04; // Adiciona a flag 'reportable'
    globalData->addValueToList(std::make_shared<OctetType>(std::string((char*)&msgFlags, 1)));
    globalData->addValueToList(std::make_shared<IntegerType>(3)); // USM Security Model
    this->packet->addValueToList(globalData);

    // Construir msgSecurityParameters
    uint8_t authParamPlaceholder[12] = {0}; // Placeholder para o HMAC
    auto authParamPtr = std::make_shared<OctetType>(std::string((char*)authParamPlaceholder, 12));

    auto secParamsStruct = std::make_shared<ComplexType>(STRUCTURE);
    secParamsStruct->addValueToList(std::make_shared<OctetType>(std::string((char*)usm.getEngineID(), usm.getEngineIDLength())));
    secParamsStruct->addValueToList(std::make_shared<IntegerType>(usm.getEngineBoots()));
    secParamsStruct->addValueToList(std::make_shared<IntegerType>(usm.getEngineTime()));
    secParamsStruct->addValueToList(std::make_shared<OctetType>(std::string(_v3_user->userName)));
    secParamsStruct->addValueToList(authParamPtr); // Adiciona o placeholder
    secParamsStruct->addValueToList(std::make_shared<OctetType>(std::string((char*)privacyParameters, _v3_user->securityLevel == AUTH_PRIV ? 8 : 0)));

    uint8_t secParamsBuf[128];
    int secParamsLen = secParamsStruct->serialise(secParamsBuf, 128);
    this->packet->addValueToList(std::make_shared<OctetType>(std::string((char*)secParamsBuf, secParamsLen)));

    // Adicionar ScopedPDU (criptografada ou não)
    this->packet->addValueToList(std::make_shared<OctetType>(std::string((char*)finalScopedPDUBytes, finalScopedPDULen)));

    // --- TÓPICOS 4 & 5: Serializar e Autenticar ---
    // Serializa o pacote com o placeholder de autenticação zerado
    int finalPacketLen = this->packet->serialise(buf, max_len);

    if (_v3_user->securityLevel >= AUTH_NO_PRIV) {
        // O USM calcula o HMAC sobre todo o buffer serializado
        uint8_t hmac_result[20]; // SHA pode ter até 20 bytes
        usm.authenticateOutgoingMsg(*_v3_user, buf, finalPacketLen, hmac_result);

        // Agora, precisamos sobrescrever o placeholder no buffer final com o HMAC real.
        // Esta é a parte mais delicada. Uma forma robusta é modificar o objeto em memória e reserializar.
        authParamPtr->_value = std::string((char*)hmac_result, 12);
        
        // Reserializa o pacote AGORA COM O HMAC CORRETO no lugar do placeholder
        finalPacketLen = this->packet->serialise(buf, max_len);
    }
    
    return finalPacketLen;
}