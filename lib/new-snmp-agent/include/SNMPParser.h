#ifndef SNMP_PARSER_h
#define SNMP_PARSER_h

#include "include/defs.h"

#include "include/SNMPPacket.h"
#include "include/SNMPResponse.h"
#include "include/ValueCallbacks.h"
#include "USM.h" // <<< 1. INCLUIR O HEADER DO USM

#include <deque>

typedef void (*informCB)(void* ctx, snmp_request_id_t, bool);

// As assinaturas das funções auxiliares de PDU não precisam de alteração
bool handleGetRequestPDU(std::deque<ValueCallback*> &callbacks, std::deque<VarBind>& varbindList, std::deque<VarBind>& outResponseList, SNMP_VERSION version, bool isGetNextRequest);
bool handleSetRequestPDU(std::deque<ValueCallback*> &callbacks, std::deque<VarBind>& varbindList, std::deque<VarBind>& outResponseList, SNMP_VERSION version);
bool handleGetBulkRequestPDU(std::deque<ValueCallback*> &callbacks, std::deque<VarBind>& varbindList, std::deque<VarBind>& outResponseList, unsigned int nonRepeaters, unsigned int maxRepititions);


// <<< 2. ASSINATURA DA FUNÇÃO handlePacket ATUALIZADA
// A função agora aceita parâmetros para o processamento do SNMPv3.
SNMP_ERROR_RESPONSE handlePacket(
    uint8_t* buffer, int packetLength, int* responseLength, int max_packet_size, 
    std::deque<ValueCallback*> &callbacks, 
    // Parâmetros para v1/v2c
    const std::string& _community, const std::string& _readOnlyCommunity,
    // Novos parâmetros para v3
    USM& usm, SNMPV3User* v3_users, int num_v3_users,
    // Callback (mantendo os valores padrão)
    informCB informCallback = nullptr, void* ctx = nullptr
);


#endif // SNMP_PARSER_h