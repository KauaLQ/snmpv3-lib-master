#include "USM.h"
#include "SNMPPacket.h" // Para acessar SNMPV3SecurityParameters
#include <WiFi.h> // Para obter o endereço MAC
#include <Preferences.h> // <<< ADICIONE ESTA LINHA
#include <cstring>

// Includes da mbedTLS
#include "mbedtls/md.h"
#include "mbedtls/des.h"
#include "mbedtls/aes.h"

// Construtor
USM::USM() : _engineIDLength(0), _engineBoots(1), _startTime(0) {
    memset(_engineID, 0, sizeof(_engineID));
}

// Inicializa o módulo
void USM::begin() {
    Preferences preferences;

    // Inicia o armazenamento "snmp-agent" em modo de leitura/escrita
    preferences.begin("snmp-agent", false); 

    // Lê o último valor de engineBoots salvo. Se não existir, o padrão é 0.
    _engineBoots = preferences.getUInt("engineBoots", 0);
    _engineBoots++; // Incrementa o contador de boots a cada reinicialização
    
    // Salva o novo valor de volta na NVS
    preferences.putUInt("engineBoots", _engineBoots);
    preferences.end();
    
    Serial.printf("SNMP EngineBoots: %d\n", _engineBoots);

    // O resto da função continua como antes
    const uint32_t enterpriseNumber = 32473;
    _engineID[0] = 0x80;
    _engineID[1] = 0x00;
    _engineID[2] = (enterpriseNumber >> 16) & 0xFF;
    _engineID[3] = (enterpriseNumber >> 8) & 0xFF;
    _engineID[4] = enterpriseNumber & 0xFF;
    
    byte mac[6];
    WiFi.macAddress(mac);
    memcpy(&_engineID[5], mac, 6);
    _engineIDLength = 11;

    _startTime = millis() / 1000;

    Serial.print("USM Initialized. EngineID: ");
    for (int i = 0; i < _engineIDLength; i++) {
        Serial.printf("%02X", _engineID[i]);
    }
    Serial.println();
}

uint32_t USM::getEngineTime() const {
    return (millis() / 1000) - _startTime;
}

// Algoritmo Password-to-Key (RFC 3414, Seção A.2)
// <<< FUNÇÃO passwordToKey DEFINITIVA E CORRIGIDA >>>
bool USM::passwordToKey(SNMPV3User& user) {
    const mbedtls_md_info_t* md_info;
    
    // --- Configuração para Chave de Autenticação ---
    if (user.authProtocol == AUTH_PROTOCOL_SHA) {
        md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    } else {
        md_info = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    }
    if (!md_info) return false;

    const char* password = user.authPassword;
    size_t pass_len = strlen(password);
    size_t digest_len = mbedtls_md_get_size(md_info);
    byte digest[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_context_t ctx;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md_info, 0); // Hash puro

    // Etapa 1: Expansão da senha para 1MB
    mbedtls_md_starts(&ctx);
    uint32_t count = 0;
    while (count < 1048576) {
        mbedtls_md_update(&ctx, (const byte*)password, pass_len);
        count += pass_len;
    }
    mbedtls_md_finish(&ctx, digest);

    // Etapa 2: Localização da chave com o EngineID
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, digest, digest_len);
    mbedtls_md_update(&ctx, this->_engineID, this->_engineIDLength);
    mbedtls_md_update(&ctx, digest, digest_len);
    mbedtls_md_finish(&ctx, user.authKey);
    Serial.println("Generated localized Auth Key.");

    // --- Configuração para Chave de Privacidade ---
    if (user.securityLevel == AUTH_PRIV) {
        password = user.privPassword;
        pass_len = strlen(password);
        byte temp_priv_key[MBEDTLS_MD_MAX_SIZE];

        // Reusa o mesmo md_info da autenticação
        mbedtls_md_starts(&ctx);
        count = 0;
        while (count < 1048576) {
            mbedtls_md_update(&ctx, (const byte*)password, pass_len);
            count += pass_len;
        }
        mbedtls_md_finish(&ctx, digest);

        mbedtls_md_starts(&ctx);
        mbedtls_md_update(&ctx, digest, digest_len);
        mbedtls_md_update(&ctx, this->_engineID, this->_engineIDLength);
        mbedtls_md_update(&ctx, digest, digest_len);
        mbedtls_md_finish(&ctx, temp_priv_key);
        memcpy(user.privKey, temp_priv_key, 16); // Chave de privacidade é sempre 128 bits
        Serial.println("Generated localized Priv Key.");
    }

    mbedtls_md_free(&ctx);
    return true;
}

// Autentica uma mensagem que será ENVIADA
bool USM::authenticateOutgoingMsg(const SNMPV3User& user, const byte* packet, uint16_t packet_len, byte* hmac_output) {
    if (user.securityLevel == NO_AUTH_NO_PRIV) return true;
    const mbedtls_md_info_t* md_info = (user.authProtocol == AUTH_PROTOCOL_SHA) ? mbedtls_md_info_from_type(MBEDTLS_MD_SHA1) : mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    int hash_size = mbedtls_md_get_size(md_info);
    mbedtls_md_hmac(md_info, user.authKey, hash_size, packet, packet_len, hmac_output);
    return true;
}

// Autentica uma mensagem RECEBIDA
bool USM::authenticateIncomingMsg(const SNMPV3User& user, const SNMPV3SecurityParameters& params, const byte* packet, uint16_t packet_len) {
    if (user.securityLevel == NO_AUTH_NO_PRIV) return true;

    // 1. VERIFICAÇÃO DA JANELA DE TEMPO (Time Window)
    // Os valores agora estão em host-order, a comparação direta é correta.
    if (ntohl(params.msgAuthoritativeEngineBoots) != this->_engineBoots) {
        Serial.printf("Authentication failed: EngineBoots mismatch. Expected: %d, Got: %d\n", this->_engineBoots, ntohl(params.msgAuthoritativeEngineBoots));
        return false;
    }
    if (abs((long)this->getEngineTime() - (long)ntohl(params.msgAuthoritativeEngineTime)) > 150) {
        Serial.println("Authentication failed: Message out of time window.");
        return false;
    }

    // 2. VERIFICAÇÃO DO HMAC (Abordagem Definitiva com memmem)
    const mbedtls_md_info_t* md_info = (user.authProtocol == AUTH_PROTOCOL_SHA) ? mbedtls_md_info_from_type(MBEDTLS_MD_SHA1) : mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    int hash_size = mbedtls_md_get_size(md_info);

    // Procura a sequência de bytes da assinatura HMAC recebida dentro do pacote completo.
    // A função memmem não é padrão em todas as toolchains, mas geralmente está disponível.
    void* auth_params_location = memmem(
        packet,                                  // Buffer onde procurar
        packet_len,                              // Tamanho do buffer
        params.msgAuthenticationParameters,      // O que procurar (a assinatura)
        params.msgAuthenticationParametersLength // Tamanho da assinatura
    );

    // Se não encontrarmos a assinatura dentro do pacote, algo está muito errado.
    if (auth_params_location == nullptr) {
        Serial.println("Authentication failed: Could not locate auth signature within the packet buffer.");
        return false;
    }

    // Agora temos o ponteiro exato. Preparamos o buffer para nosso próprio cálculo.
    byte temp_packet[MAX_SNMP_PACKET_LENGTH];
    memcpy(temp_packet, packet, packet_len);

    // Calculamos o offset usando o ponteiro que encontramos
    int auth_params_offset = (byte*)auth_params_location - packet;

    // Zeramos o campo de autenticação na nossa cópia
    memset(temp_packet + auth_params_offset, 0, params.msgAuthenticationParametersLength);

    // Calculamos o HMAC sobre a cópia modificada
    byte calculated_hmac[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_hmac(md_info, user.authKey, hash_size, temp_packet, packet_len, calculated_hmac);

    // Comparamos o resultado com a assinatura original
    if (memcmp(calculated_hmac, params.msgAuthenticationParameters, params.msgAuthenticationParametersLength) == 0) {
        Serial.println("Authentication successful.");
        return true;
    } else {
        Serial.println("Authentication failed: Wrong Digest (HMAC).");
        Serial.print("HMAC Recebido:  ");
        for(int i=0; i<12; i++) Serial.printf("%02X", params.msgAuthenticationParameters[i]);
        Serial.println();
        Serial.print("HMAC Calculado: ");
        for(int i=0; i<12; i++) Serial.printf("%02X", calculated_hmac[i]);
        Serial.println();
        return false;
    }
}

// Criptografa uma PDU
int USM::encryptPDU(const SNMPV3User& user, const byte* pdu, uint16_t pdu_len, byte* encrypted_pdu, byte* out_privacy_params) {
    if (user.securityLevel != AUTH_PRIV) return 0;

    if (user.privProtocol == PRIV_PROTOCOL_AES) {
        // 1. GERAR O "SALT" (privacy_params) - PONTO CRÍTICO FALTANTE
        uint64_t salt = ++_privSaltCounter;
        for (int i = 0; i < 8; i++) {
            out_privacy_params[7 - i] = (salt >> (i * 8)) & 0xFF;
        }
        
        // 2. CONSTRUIR O VETOR DE INICIALIZAÇÃO (IV) - CORREÇÃO CRÍTICA
        // IV (16 bytes) = engineBoots(4) || engineTime(4) || privParams(8)
        uint8_t iv[16];
        uint32_t boots_n = htonl(this->_engineBoots);
        uint32_t time_n = htonl(this->getEngineTime());
        memcpy(iv, &boots_n, 4);
        memcpy(iv + 4, &time_n, 4);
        memcpy(iv + 8, out_privacy_params, 8);

        // 3. USAR AES-CFB-128 (NÃO CBC) - CORREÇÃO CRÍTICA
        mbedtls_aes_context aes_ctx;
        mbedtls_aes_init(&aes_ctx);
        mbedtls_aes_setkey_enc(&aes_ctx, user.privKey, 128);

        size_t iv_off = 0; // mbedtls gerencia o offset do IV
        mbedtls_aes_crypt_cfb128(&aes_ctx, MBEDTLS_AES_ENCRYPT, pdu_len, &iv_off, iv, pdu, encrypted_pdu);
        
        mbedtls_aes_free(&aes_ctx);
        return pdu_len; // CFB não usa padding, o tamanho de saída é igual ao de entrada
    }
    return 0;
}

// Descriptografa uma PDU
int USM::decryptPDU(const SNMPV3User& user, const byte* encrypted_pdu, uint16_t encrypted_len, byte* decrypted_pdu, const SNMPV3SecurityParameters& params) {
    if (user.securityLevel != AUTH_PRIV) return 0;

    if (user.privProtocol == PRIV_PROTOCOL_AES) {
        // 1. CONSTRUIR O VETOR DE INICIALIZAÇÃO (IV) - CORREÇÃO CRÍTICA
        // Para descriptografar, usamos os valores que vieram no pacote
        uint8_t iv[16];
        uint32_t boots_n = htonl(params.msgAuthoritativeEngineBoots);
        uint32_t time_n = htonl(params.msgAuthoritativeEngineTime);
        memcpy(iv, &boots_n, 4);
        memcpy(iv + 4, &time_n, 4);
        memcpy(iv + 8, params.msgPrivacyParameters, 8);
        
        // 2. USAR AES-CFB-128 (NÃO CBC) - CORREÇÃO CRÍTICA
        mbedtls_aes_context aes_ctx;
        mbedtls_aes_init(&aes_ctx);
        mbedtls_aes_setkey_enc(&aes_ctx, user.privKey, 128); // CFB usa a chave de encriptação para ambos os modos

        size_t iv_off = 0;
        mbedtls_aes_crypt_cfb128(&aes_ctx, MBEDTLS_AES_DECRYPT, encrypted_len, &iv_off, iv, encrypted_pdu, decrypted_pdu);
        
        mbedtls_aes_free(&aes_ctx);
        return encrypted_len;
    }
    return 0;
}