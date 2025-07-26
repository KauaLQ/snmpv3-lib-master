#include <Arduino.h>
#include <WiFi.h>
#include "SNMP_Agent.h" // Inclui a biblioteca da nossa nova pasta

// --- Configurações de Wi-Fi ---
const char* ssid = "CLEUDO";
const char* password = "91898487";

// --- Configuração do Agente SNMP ---
SNMPAgent agent;
WiFiUDP udp; // Objeto UDP para o SNMP

// Variável de exemplo que queremos expor via SNMP
int uptime_minutes = 0;

void setup() {
  Serial.begin(115200);
  Serial.println("\nIniciando Agente SNMPv3...");

  // Conectar ao Wi-Fi
  WiFi.begin(ssid, password);
  Serial.print("Conectando ao Wi-Fi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConectado!");
  Serial.print("Endereço IP: ");
  Serial.println(WiFi.localIP());

  // --- Configuração do SNMPv3 ---
  // Adiciona um usuário com o nível de segurança mais alto (authPriv)
  // Usuário: esp32user
  // Senha de Autenticação: myauthpass
  // Senha de Privacidade (Criptografia): myprivpass
  bool userAdded = agent.addUser("esp32user", 
                                 AUTH_PRIV,        // Nível de segurança: Autenticação e Privacidade
                                 AUTH_PROTOCOL_SHA,// Protocolo de Autenticação: SHA
                                 "myauthpass",     // Senha de Autenticação
                                 PRIV_PROTOCOL_AES,// Protocolo de Privacidade: AES
                                 "myprivpass");    // Senha de Privacidade
  
  if (userAdded) {
    Serial.println("Usuário SNMPv3 'esp32user' adicionado com sucesso.");
  } else {
    Serial.println("Falha ao adicionar usuário SNMPv3.");
  }

  // Adiciona um OID de teste para leitura (ex: .1.3.6.1.4.1.12345.1.0)
  // Este OID irá retornar o valor da nossa variável 'uptime_minutes'
  agent.addIntegerHandler(".1.3.6.1.4.1.12345.1.0", &uptime_minutes);

  // Inicializa o agente SNMP
  agent.setUDP(&udp);
  agent.begin(); // O USM é inicializado aqui dentro

  Serial.println("Agente SNMP iniciado e pronto para receber requisições.");
}

void loop() {
  // Processa pacotes SNMP recebidos
  agent.loop();

  // Apenas para ter um valor dinâmico para testar
  static unsigned long last_millis = 0;
  if (millis() - last_millis > 60000) {
    uptime_minutes++;
    last_millis = millis();
  }
}