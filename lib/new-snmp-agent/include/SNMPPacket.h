#ifndef SNMPPacket_h
#define SNMPPacket_h

#include "VarBinds.h"
#include "defs.h"
#include <vector>
#include <math.h>
#include <string>
#include "USM.h" // <<< CORREÇÃO 1: Usar aspas para includes do projeto

enum SNMPParsingState {
    SNMPVERSION,
    MSGGLOBALDATA,
    MSGSECURITYPARAMETERS,
    SCOPEDPDU,
    COMMUNITY,
    PDU,
    REQUESTID,
    ERRORSTATUS,
    ERRORID,
    VARBINDS,
    VARBIND,
    DONE
};

typedef int SNMP_PACKET_PARSE_ERROR;

#define SNMP_PARSE_ERROR_MAGIC_BYTE -2 + SNMP_PACKET_PARSE_ERROR_OFFSET
#define SNMP_PARSE_ERROR_GENERIC -1 + SNMP_PACKET_PARSE_ERROR_OFFSET

union ErrorStatus {
  SNMP_ERROR_STATUS errorStatus;
  int nonRepeaters;
};

union ErrorIndex {
  int errorIndex;
  int maxRepititions;
};

// <<< CORREÇÃO 2: Definição da estrutura de parâmetros de segurança do v3
// Deve ser declarada ANTES de ser usada na classe SNMPPacket.
struct SNMPV3SecurityParameters {
    uint8_t msgAuthoritativeEngineID[32];
    uint8_t msgAuthoritativeEngineIDLength = 0;
    uint32_t msgAuthoritativeEngineBoots = 0;
    uint32_t msgAuthoritativeEngineTime = 0;
    uint8_t msgUserName[33];
    uint8_t msgUserNameLength = 0;
    uint8_t msgAuthenticationParameters[12];
    uint8_t msgAuthenticationParametersLength = 0;
    uint8_t msgPrivacyParameters[8];
    uint8_t msgPrivacyParametersLength = 0;
};


class SNMPPacket {
  public:
    SNMPPacket(){};
    // <<< CORREÇÃO 3: Construtor de cópia completo
    explicit SNMPPacket(const SNMPPacket& packet){
        // Campos v1/v2c
        this->setRequestID(packet.requestID);
        this->setVersion(packet.snmpVersion);
        this->setCommunityString(packet.communityString);

        if(packet.requestIDPtr) this->requestIDPtr = packet.requestIDPtr;
        if(packet.snmpVersionPtr) this->snmpVersionPtr = packet.snmpVersionPtr;
        if(packet.communityStringPtr) this->communityStringPtr = packet.communityStringPtr;
        
        // Campos v3
        this->msgID = packet.msgID;
        this->msgMaxSize = packet.msgMaxSize;
        this->msgFlags = packet.msgFlags;
        this->msgSecurityModel = packet.msgSecurityModel;
        this->securityParameters = packet.securityParameters; // Copia a estrutura inteira
        if(packet.scopedPDUPtr) this->scopedPDUPtr = packet.scopedPDUPtr;
    };

    virtual ~SNMPPacket();

    static snmp_request_id_t generate_request_id();
    
    SNMP_PACKET_PARSE_ERROR parseFrom(uint8_t* buf, size_t max_len);
    int serialiseInto(uint8_t* buf, size_t max_len);

    SNMP_PACKET_PARSE_ERROR parseScopedPDU(unsigned char* buf, size_t len);
    virtual int serialiseIntoV3(uint8_t* buf, size_t max_len, USM& usm);

    void setCommunityString(const std::string &CommunityString);
    void setRequestID(snmp_request_id_t);
    bool setPDUType(ASN_TYPE);
    void setVersion(SNMP_VERSION);

    bool reuse = false;

    std::shared_ptr<IntegerType> requestIDPtr = nullptr;
    std::shared_ptr<IntegerType> snmpVersionPtr = nullptr;
    std::shared_ptr<OctetType> communityStringPtr = nullptr;

    snmp_request_id_t requestID = 0;
    SNMP_VERSION snmpVersion = (SNMP_VERSION)0;
    std::string communityString;

    ASN_TYPE packetPDUType;
    std::deque<VarBind> varbindList;
    union ErrorStatus errorStatus = { NO_ERROR };
    union ErrorIndex errorIndex = {0};

    ComplexType* packet = nullptr;

    // Membros para os cabeçalhos SNMPv3
    uint32_t msgID = 0;
    uint32_t msgMaxSize = 0;
    uint8_t  msgFlags = 0;
    uint32_t msgSecurityModel = 0;
    SNMPV3SecurityParameters securityParameters;
    std::shared_ptr<OctetType> scopedPDUPtr = nullptr;
    
  protected:
    virtual bool build();
    virtual std::shared_ptr<ComplexType> generateVarBindList();
  private:
    SNMP_PACKET_PARSE_ERROR parsePacket(ComplexType* structure, enum SNMPParsingState state);
};


#endif // SNMPPacket_h