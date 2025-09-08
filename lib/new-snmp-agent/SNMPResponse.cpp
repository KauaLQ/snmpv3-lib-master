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
    
    // Se não for um report, continua com a lógica normal
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

    SNMP_LOGD("ScopedPDU serialized len=%d", scopedPDULen);
    SNMP_LOGD("ScopedPDU HEX:");
    for (int i=0;i<scopedPDULen;i++) SNMP_LOGD("%02X", scopedPDUBuf[i]);

    // --- TÓPICO 2: Criptografar a ScopedPDU, se necessário ---
    uint8_t finalScopedPDUBytes[512];
    int finalScopedPDULen = scopedPDULen;
    uint8_t privacyParameters[8] = {0}; // "Salt" para a criptografia

    // Declare privParamPtr here so it is available for both encryption and security parameters
    auto privParamPtr = std::make_shared<OctetType>(std::string((char*)privacyParameters, _v3_user->securityLevel == AUTH_PRIV ? 8 : 0));

    if (_v3_user->securityLevel == AUTH_PRIV) {
        // <<< ALTERE ESTA CHAMADA >>>
        // Agora a função preenche o privacyParameters (salt) para nós
        finalScopedPDULen = usm.encryptPDU(*_v3_user, scopedPDUBuf, scopedPDULen, finalScopedPDUBytes, privacyParameters);
        
        // Debug: mostrar privacyParameters gerados
        SNMP_LOGD("privacyParameters generated by encryptPDU:");
        for (int i=0;i<8;i++) SNMP_LOGD("%02X", privacyParameters[i]);

        // Se securityLevel == AUTH_PRIV, atualizamos o valor do OctetType que representa msgPrivacyParameters
        if (_v3_user->securityLevel == AUTH_PRIV) {
            privParamPtr->_value = std::string((char*)privacyParameters, 8);
        }

        SNMP_LOGD("FinalScopedPDU len=%d (encrypted=%d)", finalScopedPDULen, _v3_user->securityLevel==AUTH_PRIV);
        SNMP_LOGD("FinalScopedPDU HEX:");
        for (int i=0;i<finalScopedPDULen;i++) SNMP_LOGD("%02X", finalScopedPDUBytes[i]);
    } else {
        memcpy(finalScopedPDUBytes, scopedPDUBuf, scopedPDULen);
        SNMP_LOGD("FinalScopedPDU len=%d (encrypted=%d)", finalScopedPDULen, _v3_user->securityLevel==AUTH_PRIV);
        SNMP_LOGD("FinalScopedPDU HEX:");
        for (int i=0;i<finalScopedPDULen;i++) SNMP_LOGD("%02X", finalScopedPDUBytes[i]);
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
    // Em vez de criar um OctetType temporário para privacy, criamos e guardamos o ponteiro
    secParamsStruct->addValueToList(privParamPtr);
    // Em vez de criar um OctetType temporário para privacy, criamos e guardamos o ponteiro
    // auto privParamPtr = std::make_shared<OctetType>(std::string((char*)privacyParameters, _v3_user->securityLevel == AUTH_PRIV ? 8 : 0));
    secParamsStruct->addValueToList(privParamPtr);

    // --- Serializa initial dos securityParameters, mas guardamos a OctetType para permitir atualização posterior ---
    uint8_t secParamsBuf[128];
    int secParamsLen = secParamsStruct->serialise(secParamsBuf, sizeof(secParamsBuf));
    SNMP_LOGD("secParams serialised len=%d", secParamsLen);
    SNMP_LOGD("secParams HEX:");
    for (int i=0;i<secParamsLen;i++) SNMP_LOGD("%02X", secParamsBuf[i]);

    // Guardar o OctetType que contém os bytes serializados — iremos atualizá-lo depois
    auto secParamsOct = std::make_shared<OctetType>(std::string((char*)secParamsBuf, secParamsLen));
    this->packet->addValueToList(secParamsOct);

    // Adicionar ScopedPDU (criptografada ou não)
    this->packet->addValueToList(std::make_shared<OctetType>(std::string((char*)finalScopedPDUBytes, finalScopedPDULen)));

    // --- TÓPICOS 4 & 5: Serializar e Autenticar ---
    // Serializa o pacote com o placeholder de autenticação (zeros)
    int finalPacketLen = this->packet->serialise(buf, max_len);
    SNMP_LOGD("Packet pre-HMAC serialised len=%d", finalPacketLen);
    SNMP_LOGD("Packet pre-HMAC HEX:");
    for (int i=0;i<finalPacketLen;i++) SNMP_LOGD("%02X", buf[i]);

    // <<< A ETAPA FINAL E CRUCIAL ESTÁ AQUI >>>
    if (_v3_user->securityLevel >= AUTH_NO_PRIV) {
        SNMP_LOGD("Autenticando pacote de saída...");

        // A biblioteca BER precisa nos dizer onde o campo de autenticação foi escrito.
        // Como isso é complexo, vamos usar uma abordagem robusta: recalcular o offset.
        // Esta lógica assume uma estrutura BER relativamente fixa, o que é o nosso caso.
        // [Seq][Len][Ver][...][GlobalData][...][SecurityParams(OctetString)][ScopedPDU]
        // Precisamos encontrar o ponteiro para o campo authParams dentro da SecurityParams Octet String.

        // Uma forma mais simples que implementamos foi modificar o objeto em memória e reserializar.
        
        // Vamos usar a abordagem que já está implementada:
        uint8_t hmac_result[20]; // SHA pode ter até 20 bytes
        
        // A função authenticateOutgoingMsg agora retorna o HMAC em hmac_result
        usm.authenticateOutgoingMsg(*_v3_user, buf, finalPacketLen, hmac_result);

        // Atualiza o valor do placeholder em memória com o HMAC real
        authParamPtr->_value = std::string((char*)hmac_result, 12);

        // Re-serializa a estrutura de securityParameters (agora com authParamPtr atualizado) e atualiza o OctetType que foi adicionado ao packet
        int secParamsLen2 = secParamsStruct->serialise(secParamsBuf, sizeof(secParamsBuf));
        if (secParamsLen2 > 0) {
            secParamsOct->_value = std::string((char*)secParamsBuf, secParamsLen2);
            SNMP_LOGD("Updated secParams HEX after HMAC insertion:");
            for (int i=0;i<secParamsLen2;i++) SNMP_LOGD("%02X", secParamsBuf[i]);
        } else {
            SNMP_LOGW("Failed to reserialise secParams after HMAC update");
        }
        
        // Reserializa o pacote COMPLETO, agora com o HMAC correto no lugar
        SNMP_LOGD("Reserializando pacote com HMAC final...");
        finalPacketLen = this->packet->serialise(buf, max_len);

        SNMP_LOGD("HMAC used (12 bytes):");
        for (int i=0;i<12;i++) SNMP_LOGD("%02X", (uint8_t)hmac_result[i]);

        SNMP_LOGD("Packet post-HMAC serialised len=%d", finalPacketLen);
        SNMP_LOGD("Packet post-HMAC HEX:");
        for (int i=0;i<finalPacketLen;i++) SNMP_LOGD("%02X", buf[i]);

        // Quick self-parse test: try to decode with BER to make sure it's structurally valid
        ComplexType sanity(STRUCTURE);
        int check = sanity.fromBuffer(buf, finalPacketLen);
        SNMP_LOGD("Self-parse sanity check returned: %d", check);
    }
    
    return finalPacketLen;
}