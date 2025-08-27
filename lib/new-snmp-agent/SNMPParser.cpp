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

        // 1. VERIFICAÇÃO DE DESCOBERTA DE ENGINE ID
        // Checa se o EngineID no pacote está vazio OU se não bate com o nosso.
        // Ambos os casos exigem um Report como resposta.
        if (request.securityParameters.msgAuthoritativeEngineIDLength == 0 ||
            memcmp(request.securityParameters.msgAuthoritativeEngineID, usm.getEngineID(), usm.getEngineIDLength()) != 0) {
            
            SNMP_LOGD("Engine Discovery request or Mismatched EngineID. Sending report.");
            SNMPResponse response(request);
            
            // Sinaliza para a SNMPResponse construir um report de descoberta de engine
            response.setGlobalError(ENGINE_DISCOVERY_REPORT, 0, true);
            
            *responseLength = response.serialiseIntoV3(buffer, max_packet_size, usm);
            
            if(*responseLength <= 0){
                SNMP_LOGW("Failed to build engine discovery report packet");
                return SNMP_FAILED_SERIALISATION;
            }
            // Retorna um valor positivo para que o loop principal envie a resposta
            return SNMP_ERROR_PACKET_SENT;
        }
        
        // 2. VERIFICAÇÃO DE DESCOBERTA DE USUÁRIO
        // Se o EngineID bateu, mas o usuário veio vazio, é uma descoberta de usuário.
        if (request.securityParameters.msgUserNameLength == 0) {
            SNMP_LOGD("User Discovery packet received. Sending report.");
            SNMPResponse response(request);

            // Sinaliza para a SNMPResponse construir um report de usuário desconhecido
            response.setGlobalError(UNKNOWN_USER_NAME, 0, true);
            
            *responseLength = response.serialiseIntoV3(buffer, max_packet_size, usm);
            
            if(*responseLength <= 0){
                SNMP_LOGW("Failed to build user discovery report packet");
                return SNMP_FAILED_SERIALISATION;
            }
            return SNMP_ERROR_PACKET_SENT;
        }

        // 3. PACOTE NORMAL - AUTENTICAÇÃO E PROCESSAMENTO
        // Se chegamos aqui, o EngineID bateu e temos um nome de usuário.
        // Encontrar o usuário v3
        for (int i = 0; i < num_v3_users; i++) {
            if (strlen(v3_users[i].userName) == request.securityParameters.msgUserNameLength &&
                memcmp(v3_users[i].userName, request.securityParameters.msgUserName, request.securityParameters.msgUserNameLength) == 0) {
                requestUser = &v3_users[i];
                break;
            }
        }
        
        if (!requestUser) {
            SNMP_LOGW("SNMPv3 User not found: %s", request.securityParameters.msgUserName);
            // Este caso agora é menos provável de acontecer se o cliente for compatível,
            // mas mantemos como segurança.
            return SNMP_REQUEST_INVALID_COMMUNITY;
        }

        // Autenticar e Descriptografar (lógica que já tínhamos)
        if (!usm.authenticateIncomingMsg(*requestUser, request.securityParameters, buffer, packetLength)) {
            SNMP_LOGW("SNMPv3 Authentication failed for user %s.", requestUser->userName);
            return SNMP_REQUEST_INVALID_COMMUNITY;
        }

        if (requestUser->securityLevel == AUTH_PRIV) {
            byte decryptedPDU[512]; 
            if (request.scopedPDUPtr) {
                int decryptedPDULen = usm.decryptPDU(*requestUser, 
                                                    (const uint8_t*)request.scopedPDUPtr->_value.data(),
                                                    request.scopedPDUPtr->_value.length(),
                                                    decryptedPDU, 
                                                    request.securityParameters);
                if (decryptedPDULen <= 0) {
                    SNMP_LOGW("SNMPv3 Decryption failed.");
                    return SNMP_REQUEST_INVALID;
                }
                request.parseScopedPDU(decryptedPDU, decryptedPDULen);
            } else {
                 SNMP_LOGW("AUTH_PRIV packet but no ScopedPDU found to decrypt.");
                 return SNMP_REQUEST_INVALID;
            }
        }

        // Determinar permissões
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

    // Ensure we respond with a GetResponse PDU
    response.setPDUType(GetResponsePDU);
    SNMP_LOGD("Response PDUType set to GetResponse (0xA2)");

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

    SNMP_LOGD("Built response length = %d", *responseLength);
    // hex dump of response
    SNMP_LOGD("Response HEX dump:");
    for (int i=0;i<*responseLength;i++) SNMP_LOGD("%02X", buffer[i]);

    return handleStatus;
}