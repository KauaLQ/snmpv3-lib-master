#ifndef SNMPResponse_h
#define SNMPResponse_h

#include "VarBinds.h"
#include "SNMPPacket.h"
#include "defs.h"
#include "ValueCallbacks.h"
#include <vector>

#if 0
class ResponseVarBind : public VarBind {
  public:
    explicit ResponseVarBind(OIDType* oid, ASN_TYPE type): VarBind(oid, type, nullptr){};
    explicit ResponseVarBind(VarBind* vb): VarBind(vb->oid->clone(), vb->type, nullptr){};
    explicit ResponseVarBind(ValueCallback* cb): VarBind(cb->OID->clone(), cb->type, nullptr){};
    SNMP_ERROR_STATUS errorStatus = NO_ERROR;
};
#endif

class SNMPResponse : public SNMPPacket {
  public:
    explicit SNMPResponse(const SNMPPacket& request): SNMPPacket(request){
      this->setPDUType(GetResponsePDU);
    };

    bool addResponse(const VarBind& response);
    bool addErrorResponse(const VarBind& response);

    bool setGlobalError(SNMP_ERROR_STATUS error, int index, int overwrite); // Overwrite existing varbindError?
    
    void setV3User(SNMPV3User* user);

    int serialiseIntoV3(uint8_t* buf, size_t max_len, USM& usm) override;

  // Em SNMPResponse.h, dentro da classe
  private:
    SNMPV3User* _v3_user = nullptr;
    int buildV3ReportPacket(uint8_t* buf, size_t max_len, USM& usm); // Função auxiliar para construir o pacote de report
};

#endif