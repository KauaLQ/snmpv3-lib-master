# from pysnmp.hlapi import *

# iterator = getCmd(
#     SnmpEngine(),
#     UsmUserData(
#         'esp32user',             # usuário SNMPv3
#         'myauthpass',            # senha de autenticação
#         'myprivpass',            # senha de privacidade
#         authProtocol=usmHMACSHAAuthProtocol,  # SHA (HMAC-SHA1-96)
#         privProtocol=usmAesCfb128Protocol        # sem privacidade
#     ),
#     UdpTransportTarget(('192.168.5.113', 161)),
#     ContextData(),
#     ObjectType(ObjectIdentity('1.3.6.1.4.1.12345.1.0'))
# )

# errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

# if errorIndication:
#     print("[ERRO]", errorIndication)

# elif errorStatus:
#     print("[ERRO] %s at %s" % (
#         errorStatus.prettyPrint(),
#         errorIndex and varBinds[int(errorIndex) - 1][0] or '?'
#     ))

# else:
#     for oid, val in varBinds:
#         print("[RESULTADO]", oid.prettyPrint(), "=", val.prettyPrint())

# import time

# while True:
#     iterator = getCmd(
#         SnmpEngine(),
#         UsmUserData(
#             'esp32user',
#             'myauthpass',
#             'myprivpass',
#             authProtocol=usmHMACSHAAuthProtocol,
#             privProtocol=usmAesCfb128Protocol
#         ),
#         UdpTransportTarget(('192.168.5.113', 161), timeout=3, retries=3),
#         ContextData(),
#         ObjectType(ObjectIdentity('1.3.6.1.4.1.12345.1.0'))
#     )

#     errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

#     if errorIndication:
#         print("[ERRO]", errorIndication)

#     elif errorStatus:
#         print("[ERRO] %s at %s" % (
#             errorStatus.prettyPrint(),
#             errorIndex and varBinds[int(errorIndex) - 1][0] or '?'
#         ))

#     else:
#         for oid, val in varBinds:
#             print("[RESULTADO]", oid.prettyPrint(), "=", val.prettyPrint())

#     time.sleep(2)  # espera 2 segundos entre as requisições

from pysnmp.hlapi import *
from pysnmp import debug

# Ativa logs de debug no console
debug.setLogger(debug.Debug('msgproc'))

iterator = getCmd(
    SnmpEngine(),
    UsmUserData(
        'esp32user',
        'myauthpass',
        None,  # sem privacidade (ajuste se precisar)
        authProtocol=usmHMACSHAAuthProtocol,
        privProtocol=usmNoPrivProtocol
    ),
    UdpTransportTarget(('192.168.5.113', 161), timeout=5, retries=1),
    ContextData(),
    ObjectType(ObjectIdentity('1.3.6.1.4.1.12345.1.0'))
)

try:
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

except Exception as e:
    print("[EXCEÇÃO]", e)