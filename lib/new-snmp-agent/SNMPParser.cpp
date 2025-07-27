#include "include/SNMPParser.h"
#include "USM.h" // <<< 1. INCLUIR O HEADER DO USM
#include <string>

// A função auxiliar para v1/v2c permanece a mesma
static SNMP_PERMISSION getPermissionOfRequest(const SNMPPacket& request, const std::string& _community, const std::string& _readOnlyCommunity){
    SNMP_PERMISSION requestPermission = SNMP_PERM_NONE;
    SNMP_LOGD("community string in packet: %s\n", request.communityString.c_str());

    if(!_readOnlyCommunity.empty() && _readOnlyCommunity == request.communityString) {
        requestPermission = SNMP_PERM_READ_ONLY;
    }
    if(_community == request.communityString) {
        requestPermission = SNMP_PERM_READ_WRITE;
    }
    return requestPermission;
}


// <<< 2. A FUNÇÃO handlePacket PRECISA SER ATUALIZADA
SNMP_ERROR_RESPONSE handlePacket(
    uint8_t* buffer, int packetLength, int* responseLength, int max_packet_size, 
    std::deque<ValueCallback*> &callbacks, 
    const std::string& _community, const std::string& _readOnlyCommunity,
    USM& usm, SNMPV3User* v3_users, int num_v3_users, // Parâmetros novos
    informCB informCallback, void* ctx)
{
    SNMPPacket request;

    SNMP_PACKET_PARSE_ERROR parseResult = request.parseFrom(buffer, packetLength);

    if(parseResult <= 0){
        SNMP_LOGW("Received Error code: %d when attempting to parse\n", parseResult);
        return SNMP_REQUEST_INVALID;
    }

    SNMP_LOGD("Valid SNMP Packet! Version: %d", request.snmpVersion);

    SNMPV3User* requestUser = nullptr;
    SNMP_PERMISSION requestPermission = SNMP_PERM_NONE;

    if (request.snmpVersion == SNMP_VERSION_3) {
        SNMP_LOGD("Handling SNMPv3 packet.");

        // <<< ALTERAÇÃO AQUI: Lidar com o pacote de descoberta >>>
        // Se o msgUserName estiver vazio, é um pacote de descoberta.
        if (request.securityParameters.msgUserNameLength == 0) {
            SNMP_LOGD("SNMPv3 Discovery packet received. Sending report.");
            SNMPResponse response = SNMPResponse(request);
            
            // Configura a resposta como um 'report' com o EngineID
            // Precisaremos de um novo método em SNMPResponse para criar um report,
            // mas por enquanto, vamos sinalizar o erro de usuário desconhecido, que
            // já deve ser tratado pela pilha Net-SNMP para gerar um 'report'.
            response.setGlobalError(UNKNOWN_USER_NAME, 0, true);
            
            // A função serialiseIntoV3 precisará ser inteligente para não precisar de um
            // usuário para gerar um pacote de erro/report.
            *responseLength = response.serialiseIntoV3(buffer, max_packet_size, usm); // Pode precisar de ajustes
            
            if(*responseLength <= 0){
                SNMP_LOGW("Failed to build discovery report packet");
                return SNMP_FAILED_SERIALISATION;
            }
            
            // Retornamos um valor positivo para que o loop principal envie o buffer de resposta
            return SNMP_ERROR_PACKET_SENT;
        }

        // 4a. Encontrar o usuário v3 (com a correção)
        for (int i = 0; i < num_v3_users; i++) {
            // <<< CORREÇÃO 1: Usar memcmp e comparar os comprimentos
            if (strlen(v3_users[i].userName) == request.securityParameters.msgUserNameLength &&
                memcmp(v3_users[i].userName, request.securityParameters.msgUserName, request.securityParameters.msgUserNameLength) == 0) {
                requestUser = &v3_users[i];
                break;
            }
        }
        if (!requestUser) {
            // NOTE: A conversão para const char* aqui é apenas para logging e pode ser arriscada se não houver um terminador nulo.
            // Uma forma mais segura seria imprimir os bytes em hexadecimal.
            SNMP_LOGW("SNMPv3 User not found."); 
            return SNMP_REQUEST_INVALID_COMMUNITY; 
        }

        // 4b. Autenticar a mensagem usando o USM
        if (!usm.authenticateIncomingMsg(*requestUser, buffer, packetLength, request.securityParameters.msgAuthenticationParameters)) {
            SNMP_LOGW("SNMPv3 Authentication failed for user %s.", requestUser->userName);
            return SNMP_REQUEST_INVALID_COMMUNITY;
        }

        // 4c. Descriptografar a PDU se necessário
        if (requestUser->securityLevel == AUTH_PRIV) {
            byte decryptedPDU[256]; 

            // <<< CORREÇÃO 2: Acessar a PDU e seu comprimento através do scopedPDUPtr
            if (request.scopedPDUPtr) {
                int decryptedPDULen = usm.decryptPDU(*requestUser, 
                                                    (const uint8_t*)request.scopedPDUPtr->_value.data(), // Ponteiro para os dados
                                                    request.scopedPDUPtr->_value.length(), // Comprimento
                                                    decryptedPDU, 
                                                    request.securityParameters.msgPrivacyParameters);

                if (decryptedPDULen <= 0) {
                    SNMP_LOGW("SNMPv3 Decryption failed.");
                    return SNMP_REQUEST_INVALID;
                }
                // Analisa a PDU interna que agora está em texto plano
                request.parseScopedPDU(decryptedPDU, decryptedPDULen);

            } else {
                 SNMP_LOGW("AUTH_PRIV packet but no ScopedPDU found to decrypt.");
                 return SNMP_REQUEST_INVALID;
            }
        }

        // 4d. Determinar permissões com base no usuário v3
        if (request.packetPDUType == SetRequestPDU) {
            requestPermission = SNMP_PERM_READ_WRITE;
        } else {
            requestPermission = SNMP_PERM_READ_ONLY;
        }

    } else { // Caminho antigo para SNMPv1 e v2c
        SNMP_LOGD("Handling SNMPv1/v2c packet.");
        requestPermission = getPermissionOfRequest(request, _community, _readOnlyCommunity);
        if(requestPermission == SNMP_PERM_NONE){
            SNMP_LOGW("Invalid communitystring provided: %s, no response to give\n", request.communityString.c_str());
            return SNMP_REQUEST_INVALID_COMMUNITY;
        }
    }
    // ===================================================================================
    // FIM DA BIFURCAÇÃO DA LÓGICA
    // ===================================================================================

    // Se a requisição for um GetResponse para um Inform que enviamos, a lógica é a mesma
    if(request.packetPDUType == GetResponsePDU){
        SNMP_LOGD("Received GetResponse! probably as a result of a recent InformTrap: %lu", request.requestID);
        if(informCallback){
            informCallback(ctx, request.requestID, !request.errorStatus.errorStatus);
        } else {
            SNMP_LOGW("Not sure what to do with Inform\n");
        }
        return SNMP_INFORM_RESPONSE_OCCURRED;
    }
    
    // this will take the required stuff from request - like requestID, version etc
    SNMPResponse response = SNMPResponse(request);

    // <<< 5. PARA SNMPv3, ASSOCIAR A RESPOSTA AO USUÁRIO
    if (request.snmpVersion == SNMP_VERSION_3) {
        response.setV3User(requestUser); // Você precisará adicionar este método em SNMPResponse
    }

    std::deque<VarBind> outResponseList;
    bool pass = false;
    SNMP_ERROR_RESPONSE handleStatus = SNMP_NO_ERROR;
    SNMP_ERROR_STATUS globalError = GEN_ERR;

    // ===================================================================================
    // <<< 6. A LÓGICA DE PROCESSAMENTO DA PDU (SWITCH CASE) PERMANECE A MESMA!
    // Porque neste ponto, a `request` já foi normalizada (autenticada, descriptografada, etc)
    // ===================================================================================
    switch(request.packetPDUType){
        case GetRequestPDU:
        case GetNextRequestPDU:
            pass = handleGetRequestPDU(callbacks, request.varbindList, outResponseList, request.snmpVersion, request.packetPDUType == GetNextRequestPDU);
            handleStatus = request.packetPDUType == GetRequestPDU ? SNMP_GET_OCCURRED : SNMP_GETNEXT_OCCURRED;
        break;
        case GetBulkRequestPDU:
            if(request.snmpVersion != SNMP_VERSION_2C && request.snmpVersion != SNMP_VERSION_3){
                SNMP_LOGD("Received GetBulkRequest in unsupported version");
                pass = false;
                globalError = GEN_ERR;
            } else {
                pass = handleGetBulkRequestPDU(callbacks, request.varbindList, outResponseList, request.errorStatus.nonRepeaters, request.errorIndex.maxRepititions);
                handleStatus = SNMP_GETBULK_OCCURRED;
            }
        break;
        case SetRequestPDU:
            if(requestPermission != SNMP_PERM_READ_WRITE){
                SNMP_LOGD("Attempting to perform a SET without required permissions");
                pass = false;
                globalError = NO_ACCESS;
            } else {
                pass = handleSetRequestPDU(callbacks, request.varbindList, outResponseList, request.snmpVersion);
                handleStatus = SNMP_SET_OCCURRED;
            }
        break;
        default:
            SNMP_LOGD("Not sure what to do with SNMP PDU of type: %d\n", request.packetPDUType);
            handleStatus = SNMP_UNKNOWN_PDU_OCCURRED;
            pass = false;
        break;
    }

    if(pass){
        for(const auto& item : outResponseList){
            if(item.errorStatus != NO_ERROR){
                response.addErrorResponse(item);
            } else {
                response.addResponse(item);
            }
        }
    } else {
        SNMP_LOGD("Handled error when building request, error: %d, sending error PDU", globalError);
        response.setGlobalError(globalError, 0, true);
        handleStatus = SNMP_ERROR_PACKET_SENT;
    }

    memset(buffer, 0, max_packet_size);

    // ===================================================================================
    // <<< 7. BIFURCAÇÃO DA LÓGICA DE SERIALIZAÇÃO DA RESPOSTA
    // ===================================================================================
    if (response.snmpVersion == SNMP_VERSION_3) {
        // Você precisará criar a função `serialiseIntoV3` em SNMPResponse.cpp
        // Ela usará o USM para criptografar e autenticar a resposta.
        *responseLength = response.serialiseIntoV3(buffer, max_packet_size, usm);
    } else {
        // O caminho antigo para v1/v2c
        *responseLength = response.serialiseInto(buffer, max_packet_size);
    }
    
    if(*responseLength <= 0){
        SNMP_LOGD("Failed to build response packet");
        return SNMP_FAILED_SERIALISATION;
    }

    return handleStatus;
}