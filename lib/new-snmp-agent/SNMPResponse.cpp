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

// <<< IMPLEMENTAÇÃO FINAL E GENERALIZADA DE buildV3ReportPacket >>>
int SNMPResponse::buildV3ReportPacket(uint8_t* buf, size_t max_len, USM& usm) {
    SNMP_LOGD("Building SNMPv3 Report Packet. Reason: %d", this->errorStatus.errorStatus);

    delete this->packet;
    this->packet = new ComplexType(STRUCTURE);
    
    // 1. Versão
    this->packet->addValueToList(std::make_shared<IntegerType>(SNMP_VERSION_3));

    // 2. Cabeçalho Global
    auto globalData = std::make_shared<ComplexType>(STRUCTURE);
    globalData->addValueToList(std::make_shared<IntegerType>(this->requestID)); 
    globalData->addValueToList(std::make_shared<IntegerType>(1500));
    uint8_t msgFlags = 0x04; // Apenas a flag "reportable"
    globalData->addValueToList(std::make_shared<OctetType>(std::string((char*)&msgFlags, 1)));
    globalData->addValueToList(std::make_shared<IntegerType>(3));
    this->packet->addValueToList(globalData);

    // 3. Parâmetros de Segurança
    auto secParamsStruct = std::make_shared<ComplexType>(STRUCTURE);
    secParamsStruct->addValueToList(std::make_shared<OctetType>(std::string((char*)usm.getEngineID(), usm.getEngineIDLength())));
    secParamsStruct->addValueToList(std::make_shared<IntegerType>(usm.getEngineBoots()));
    secParamsStruct->addValueToList(std::make_shared<IntegerType>(usm.getEngineTime()));
    secParamsStruct->addValueToList(std::make_shared<OctetType>(std::string("", 0)));
    secParamsStruct->addValueToList(std::make_shared<OctetType>(std::string("", 0)));
    secParamsStruct->addValueToList(std::make_shared<OctetType>(std::string("", 0)));
    
    // --- Serializa initial dos securityParameters, mas guardamos a OctetType para permitir atualização posterior ---
    uint8_t secParamsBuf[128];
    int secParamsLen = secParamsStruct->serialise(secParamsBuf, sizeof(secParamsBuf));
    SNMP_LOGD("secParams serialised len=%d", secParamsLen);
    SNMP_LOGD("secParams HEX:");
    for (int i=0;i<secParamsLen;i++) SNMP_LOGD("%02X", secParamsBuf[i]);

    // Guardar o OctetType que contém os bytes serializados — iremos atualizá-lo depois
    auto secParamsOct = std::make_shared<OctetType>(std::string((char*)secParamsBuf, secParamsLen));
    this->packet->addValueToList(secParamsOct);

    // 4. ScopedPDU contendo o Report-PDU
    auto scopedPDU = std::make_shared<ComplexType>(STRUCTURE);
    scopedPDU->addValueToList(std::make_shared<OctetType>(std::string("", 0)));
    scopedPDU->addValueToList(std::make_shared<OctetType>(std::string("", 0)));

    auto reportPDU = std::make_shared<ComplexType>(ReportPDU);
    reportPDU->addValueToList(std::make_shared<IntegerType>(0));
    reportPDU->addValueToList(std::make_shared<IntegerType>(NO_ERROR));
    reportPDU->addValueToList(std::make_shared<IntegerType>(0));
    
    auto varBindList = std::make_shared<ComplexType>(STRUCTURE);
    auto varBind = std::make_shared<ComplexType>(STRUCTURE);
    
    // <<< LÓGICA GENERALIZADA: ESCOLHE O OID CORRETO PARA O REPORT >>>
    if (this->errorStatus.errorStatus == UNKNOWN_USER_NAME) {
        varBind->addValueToList(std::make_shared<OIDType>(OID_usmStatsUnknownUserNames));
    } else { // ENGINE_DISCOVERY_REPORT
        varBind->addValueToList(std::make_shared<OIDType>(OID_usmStatsUnknownEngineIDs));
    }
    varBind->addValueToList(std::make_shared<Counter32>(1));
    varBindList->addValueToList(varBind);
    reportPDU->addValueToList(varBindList);
    scopedPDU->addValueToList(reportPDU);
    
    this->packet->addValueToList(scopedPDU);

    return this->packet->serialise(buf, max_len);
}

// <<< IMPLEMENTAÇÃO FINAL DE serialiseIntoV3 >>>
int SNMPResponse::serialiseIntoV3(uint8_t* buf, size_t max_len, USM& usm) {
    // Verifica se precisa construir um pacote de Report
    if (this->errorStatus.errorStatus == UNKNOWN_USER_NAME || this->errorStatus.errorStatus == ENGINE_DISCOVERY_REPORT) {
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

    uint8_t finalScopedPDUBytes[512];
    int finalScopedPDULen = scopedPDULen;
    uint8_t privacyParameters[8] = {0};

    auto privParamPtr = std::make_shared<OctetType>(std::string((char*)privacyParameters, _v3_user->securityLevel == AUTH_PRIV ? 8 : 0));

    if (_v3_user->securityLevel == AUTH_PRIV) {
        finalScopedPDULen = usm.encryptPDU(*_v3_user, scopedPDUBuf, scopedPDULen, finalScopedPDUBytes, privacyParameters);
        if (finalScopedPDULen <= 0) {
            SNMP_LOGW("Falha ao criptografar PDU!");
            return -1;
        }
        privParamPtr->_value = std::string((char*)privacyParameters, 8);
    } else {
        memcpy(finalScopedPDUBytes, scopedPDUBuf, scopedPDULen);
    }

    // --- TÓPICO 2: Construir o pacote v3 completo ---
    delete this->packet;
    this->packet = new ComplexType(STRUCTURE);

    this->packet->addValueToList(std::make_shared<IntegerType>(SNMP_VERSION_3));

    // Construir msgGlobalData
    auto globalData = std::make_shared<ComplexType>(STRUCTURE);
    globalData->addValueToList(std::make_shared<IntegerType>(this->requestID));
    globalData->addValueToList(std::make_shared<IntegerType>(1500));

    uint8_t msgFlags = 0x00;
    if (_v3_user->securityLevel >= AUTH_NO_PRIV) msgFlags |= 0x01; // authFlag
    if (_v3_user->securityLevel == AUTH_PRIV)   msgFlags |= 0x02; // privFlag

    // Só marcar 'reportable' se for request confirmado
    if (this->packetPDUType == GetRequestPDU ||
        this->packetPDUType == GetNextRequestPDU ||
        this->packetPDUType == GetBulkRequestPDU ||
        this->packetPDUType == SetRequestPDU) {
        msgFlags |= 0x04;
    }

    globalData->addValueToList(std::make_shared<OctetType>(std::string((char*)&msgFlags, 1)));
    globalData->addValueToList(std::make_shared<IntegerType>(3));
    this->packet->addValueToList(globalData);

    // Construir msgSecurityParameters
    uint8_t authParamPlaceholder[12] = {0};
    auto authParamPtr = std::make_shared<OctetType>(std::string((char*)authParamPlaceholder, 12));

    auto secParamsStruct = std::make_shared<ComplexType>(STRUCTURE);
    secParamsStruct->addValueToList(std::make_shared<OctetType>(std::string((char*)usm.getEngineID(), usm.getEngineIDLength())));
    secParamsStruct->addValueToList(std::make_shared<IntegerType>(usm.getEngineBoots()));
    secParamsStruct->addValueToList(std::make_shared<IntegerType>(usm.getEngineTime()));
    secParamsStruct->addValueToList(std::make_shared<OctetType>(std::string(_v3_user->userName)));
    secParamsStruct->addValueToList(authParamPtr);
    secParamsStruct->addValueToList(privParamPtr);

    uint8_t secParamsBuf[128];
    int secParamsLen = secParamsStruct->serialise(secParamsBuf, sizeof(secParamsBuf));
    auto secParamsOct = std::make_shared<OctetType>(std::string((char*)secParamsBuf, secParamsLen));
    this->packet->addValueToList(secParamsOct);

    // Adicionar ScopedPDU
    if (_v3_user->securityLevel == AUTH_PRIV) {
        this->packet->addValueToList(std::make_shared<OctetType>(std::string((char*)finalScopedPDUBytes, finalScopedPDULen)));
    } else {
        this->packet->addValueToList(scopedPDU);
    }

    // --- TÓPICO 3: Serializar e autenticar ---
    int finalPacketLen = this->packet->serialise(buf, max_len);

    if (_v3_user->securityLevel >= AUTH_NO_PRIV) {
        uint8_t hmac_result[20];
        usm.authenticateOutgoingMsg(*_v3_user, buf, finalPacketLen, hmac_result);
        authParamPtr->_value = std::string((char*)hmac_result, 12);

        int secParamsLen2 = secParamsStruct->serialise(secParamsBuf, sizeof(secParamsBuf));
        if (secParamsLen2 > 0) {
            secParamsOct->_value = std::string((char*)secParamsBuf, secParamsLen2);
        }

        finalPacketLen = this->packet->serialise(buf, max_len);
    }

    return finalPacketLen;
}