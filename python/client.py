from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen

print("[INFO] Iniciando script SNMPv3...")

# Cria instância do SNMP engine
snmpEngine = engine.SnmpEngine()

print("[INFO] Configurando usuário SNMPv3...")

# Adiciona usuário SNMPv3
config.addV3User(
    snmpEngine,
    "esp32user",
    config.usmHMACSHAAuthProtocol,
    "myauthpass",
    config.usmAesCfb128Protocol,
    "myprivpass",
)

config.addTargetParams(snmpEngine, "my-creds", "esp32user", "authPriv")

# Configuração do transporte
print("[INFO] Configurando transporte para 10.0.0.113:161...")
config.addTransport(
    snmpEngine, udp.domainName, udp.UdpSocketTransport().openClientMode()
)

config.addTargetAddr(
    snmpEngine, "my-router", udp.domainName, ("10.0.0.113", 161), "my-creds"
)

# Callback para resposta
def cbFun(
    snmpEngine,
    sendRequestHandle,
    errorIndication,
    errorStatus,
    errorIndex,
    varBinds,
    cbCtx,
):
    print("[INFO] Resposta recebida:")
    if errorIndication:
        print("[ERRO] Indicação de erro:", errorIndication)
    elif errorStatus:
        print(
            "[ERRO] {} at {}".format(
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
            )
        )
    else:
        for oid, val in varBinds:
            print(f"[RESULTADO] {oid.prettyPrint()} = {val.prettyPrint()}")
    print("[INFO] Finalizando dispatcher...")

# Envio da requisição GET
print("[INFO] Enviando requisição SNMP GET para OID .1.3.6.1.4.1.12345.1.0...")

cmdgen.GetCommandGenerator().sendVarBinds(
    snmpEngine,
    "my-router",
    None,
    "",  # contextEngineId e contextName vazios
    [((1, 3, 6, 1, 4, 1, 12345, 1, 0), None)],
    cbFun,
)

print("[INFO] Aguardando resposta do agente SNMP...")
snmpEngine.transportDispatcher.runDispatcher()

print("[INFO] Encerrando transporte e script.")

config.delTransport(snmpEngine, udp.domainName).closeTransport()