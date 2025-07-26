#include "USM.h"
#include <WiFi.h> // Para obter o endereço MAC

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
    // Gera o EngineID baseado no endereço MAC, conforme RFC 3411
    // Formato: 0x80 (bit mais significativo) + 0x000004fb (IANA PEN para ESP-IDF, fictício) + 0x01 (formato MAC) + 6 bytes do MAC
    
    // PEN (Private Enterprise Number) - Você pode usar um seu se tiver.
    // Usaremos um fictício para exemplo: 1.3.6.1.4.1.32473 (exemplo da Espressif)
    const uint32_t enterpriseNumber = 32473;

    _engineID[0] = 0x80;
    _engineID[1] = 0x00;
    _engineID[2] = (enterpriseNumber >> 16) & 0xFF;
    _engineID[3] = (enterpriseNumber >> 8) & 0xFF;
    _engineID[4] = enterpriseNumber & 0xFF;
    
    // Obter endereço MAC
    byte mac[6];
    WiFi.macAddress(mac);

    memcpy(&_engineID[5], mac, 6);
    _engineIDLength = 11; // 5 bytes do prefixo + 6 do MAC

    // Inicializa contadores de tempo
    _startTime = millis() / 1000;
    // _engineBoots deveria ser lido da memória não volátil (NVS) se a persistência for necessária.
    // Para simplificar, iniciamos sempre em 1.
    _engineBoots = 1;

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
bool USM::passwordToKey(SNMPV3User& user) {
    const mbedtls_md_info_t* md_info;
    if (user.authProtocol == AUTH_PROTOCOL_SHA) {
        md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    } else {
        md_info = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    }

    if (!md_info) return false;

    // 1. Expande a senha para 1MB
    byte digest[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md_info, 1); // HMAC

    const char* password = user.authPassword;
    size_t pass_len = strlen(password);
    byte password_buf[64] = {0};
    uint32_t count = 0;
    const uint32_t one_mb = 1048576;
    
    mbedtls_md_hmac_starts(&ctx, (const byte*)password, pass_len);

    while (count < one_mb) {
        memcpy(password_buf, password, pass_len);
        memset(password_buf + pass_len, 0, 64 - pass_len);
        mbedtls_md_hmac_update(&ctx, password_buf, 64);
        count += 64;
    }
    mbedtls_md_hmac_finish(&ctx, digest);

    // 2. Localiza a chave usando o EngineID
    mbedtls_md_hmac_starts(&ctx, digest, mbedtls_md_get_size(md_info));
    mbedtls_md_hmac_update(&ctx, _engineID, _engineIDLength);
    mbedtls_md_hmac_update(&ctx, digest, mbedtls_md_get_size(md_info));
    mbedtls_md_hmac_finish(&ctx, user.authKey);

    mbedtls_md_free(&ctx);

    Serial.println("Generated localized Auth Key.");

    // Se o nível for AUTH_PRIV, gera a chave de privacidade da mesma forma
    if (user.securityLevel == AUTH_PRIV) {
        // ... (Repete o processo para a privPassword) ...
        // Este é um exercício idêntico ao anterior, apenas com a senha de privacidade
        // Para brevidade, você pode criar uma função auxiliar
        // Aqui está a implementação completa para clareza:
        const char* privPassword = user.privPassword;
        size_t priv_pass_len = strlen(privPassword);
        
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, md_info, 1); // HMAC

        count = 0;
        mbedtls_md_hmac_starts(&ctx, (const byte*)privPassword, priv_pass_len);
        while (count < one_mb) {
            memcpy(password_buf, privPassword, priv_pass_len);
            memset(password_buf + priv_pass_len, 0, 64 - priv_pass_len);
            mbedtls_md_hmac_update(&ctx, password_buf, 64);
            count += 64;
        }
        mbedtls_md_hmac_finish(&ctx, digest);

        mbedtls_md_hmac_starts(&ctx, digest, mbedtls_md_get_size(md_info));
        mbedtls_md_hmac_update(&ctx, _engineID, _engineIDLength);
        mbedtls_md_hmac_update(&ctx, digest, mbedtls_md_get_size(md_info));
        
        // A chave de privacidade é truncada para 16 bytes (128 bits) para AES/DES
        byte temp_priv_key[MBEDTLS_MD_MAX_SIZE];
        mbedtls_md_hmac_finish(&ctx, temp_priv_key);
        memcpy(user.privKey, temp_priv_key, 16);

        mbedtls_md_free(&ctx);
        Serial.println("Generated localized Priv Key.");
    }
    
    return true;
}

// Autentica uma mensagem que será ENVIADA
bool USM::authenticateOutgoingMsg(const SNMPV3User& user, byte* packet, uint16_t packet_len, byte* auth_params_ptr) {
    if (user.securityLevel == NO_AUTH_NO_PRIV) return true;

    const mbedtls_md_info_t* md_info;
    int hash_size;
    if (user.authProtocol == AUTH_PROTOCOL_SHA) {
        md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
        hash_size = 20;
    } else {
        md_info = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
        hash_size = 16;
    }
    
    // Zera o campo de autenticação antes de calcular o HMAC
    memset(auth_params_ptr, 0, 12);

    byte hmac_result[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_hmac(md_info, user.authKey, hash_size, packet, packet_len, hmac_result);

    // Copia os 12 primeiros bytes do HMAC para o pacote
    memcpy(auth_params_ptr, hmac_result, 12);

    return true;
}

// Autentica uma mensagem RECEBIDA
bool USM::authenticateIncomingMsg(const SNMPV3User& user, const byte* packet, uint16_t packet_len, const byte* received_auth_params) {
    if (user.securityLevel == NO_AUTH_NO_PRIV) return true;

    const mbedtls_md_info_t* md_info;
    int hash_size;
    if (user.authProtocol == AUTH_PROTOCOL_SHA) {
        md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
        hash_size = 20;
    } else {
        md_info = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
        hash_size = 16;
    }
    
    // Cria uma cópia do pacote para zerar o campo de autenticação
    byte* temp_packet = (byte*)malloc(packet_len);
    if (!temp_packet) return false;
    memcpy(temp_packet, packet, packet_len);

    // Calcula a posição do auth_params dentro da cópia do pacote
    int auth_params_offset = received_auth_params - packet;
    memset(temp_packet + auth_params_offset, 0, 12);
    
    byte calculated_hmac[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_hmac(md_info, user.authKey, hash_size, temp_packet, packet_len, calculated_hmac);

    free(temp_packet);

    // Compara o HMAC calculado com o recebido
    if (memcmp(calculated_hmac, received_auth_params, 12) == 0) {
        Serial.println("Authentication successful.");
        return true;
    } else {
        Serial.println("Authentication failed!");
        return false;
    }
}

// Criptografa uma PDU
int USM::encryptPDU(const SNMPV3User& user, const byte* pdu, uint16_t pdu_len, byte* encrypted_pdu, const byte* privacy_params) {
    if (user.securityLevel != AUTH_PRIV) return 0;

    if (user.privProtocol == PRIV_PROTOCOL_AES) {
        mbedtls_aes_context aes_ctx;
        byte iv[16];

        // Constrói o IV (Vetor de Inicialização) para AES-128
        // IV = engineBoots (4 bytes) + engineTime (4 bytes) + privacyParams (8 bytes)
        uint32_t boots = htonl(getEngineBoots());
        uint32_t time = htonl(getEngineTime());
        memcpy(iv, &boots, 4);
        memcpy(iv + 4, &time, 4);
        memcpy(iv + 8, privacy_params, 8);

        mbedtls_aes_init(&aes_ctx);
        mbedtls_aes_setkey_enc(&aes_ctx, user.privKey, 128); // AES-128

        // O comprimento da PDU a ser criptografada DEVE ser um múltiplo de 16 (tamanho do bloco AES)
        // A sua lógica de codificação BER da PDU precisa garantir isso, adicionando padding se necessário.
        if (pdu_len % 16 != 0) {
            Serial.println("Error: PDU length for AES encryption is not a multiple of 16.");
            return -1;
        }

        mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, pdu_len, iv, pdu, encrypted_pdu);
        mbedtls_aes_free(&aes_ctx);
        
        return pdu_len;
    }
    // TODO: Adicionar implementação para DES se for necessário
    // else if (user.privProtocol == PRIV_PROTOCOL_DES) { ... }
    
    return 0;
}

// Descriptografa uma PDU
int USM::decryptPDU(const SNMPV3User& user, const byte* encrypted_pdu, uint16_t encrypted_len, byte* decrypted_pdu, const byte* privacy_params) {
    if (user.securityLevel != AUTH_PRIV) return 0;

    if (user.privProtocol == PRIV_PROTOCOL_AES) {
        mbedtls_aes_context aes_ctx;
        byte iv[16];

        // Constrói o IV da mesma forma que na criptografia
        uint32_t boots = htonl(_engineBoots); // Usar os dados do pacote recebido
        uint32_t time = htonl(getEngineTime()); // Usar os dados do pacote recebido
        memcpy(iv, &boots, 4);
        memcpy(iv + 4, &time, 4);
        memcpy(iv + 8, privacy_params, 8);

        mbedtls_aes_init(&aes_ctx);
        mbedtls_aes_setkey_dec(&aes_ctx, user.privKey, 128);

        if (encrypted_len % 16 != 0) {
            Serial.println("Error: Encrypted data length for AES decryption is not a multiple of 16.");
            return -1;
        }

        mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, encrypted_len, iv, encrypted_pdu, decrypted_pdu);
        mbedtls_aes_free(&aes_ctx);
        
        return encrypted_len;
    }
    // TODO: Adicionar implementação para DES
    
    return 0;
}