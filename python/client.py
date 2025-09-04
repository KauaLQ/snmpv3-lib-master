from pysnmp.hlapi import *

iterator = getCmd(
    SnmpEngine(),
    UsmUserData(
        'esp32user',             # usuário SNMPv3
        'myauthpass',            # senha de autenticação
        'myprivpass',            # senha de privacidade
        authProtocol=usmHMACSHAAuthProtocol,  # SHA (HMAC-SHA1-96)
        privProtocol=usmAesCfb128Protocol        # sem privacidade
    ),
    UdpTransportTarget(('10.0.0.113', 161)),
    ContextData(),
    ObjectType(ObjectIdentity('1.3.6.1.4.1.12345.1.0'))
)

errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

if errorIndication:
    print("[ERRO]", errorIndication)

elif errorStatus:
    print("[ERRO] %s at %s" % (
        errorStatus.prettyPrint(),
        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'
    ))

else:
    for oid, val in varBinds:
        print("[RESULTADO]", oid.prettyPrint(), "=", val.prettyPrint())