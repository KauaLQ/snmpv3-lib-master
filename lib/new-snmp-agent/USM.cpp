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

    const mbedtls_md_info_t* md_info = (user.authProtocol == AUTH_PROTOCOL_SHA)
        ? mbedtls_md_info_from_type(MBEDTLS_MD_SHA1)
        : mbedtls_md_info_from_type(MBEDTLS_MD_MD5);

    int digest_len = mbedtls_md_get_size(md_info);
    byte full_hmac[MBEDTLS_MD_MAX_SIZE];

    // Calcula o HMAC completo (16 bytes para MD5, 20 bytes para SHA-1)
    mbedtls_md_hmac(md_info, user.authKey, digest_len, packet, packet_len, full_hmac);

    // Copia apenas os 12 primeiros bytes (HMAC-96) para o campo do pacote
    memcpy(hmac_output, full_hmac, 12);

    return true;
}

// ----------------- HELPERS (p/ authenticateIncomingMsg) -----------------

// procura uma sub-sequência 'needle' dentro de 'haystack', retorna offset ou -1
static int findSubsequence(const byte* haystack, int haystack_len, const byte* needle, int needle_len) {
    if (!haystack || !needle || needle_len <= 0 || haystack_len < needle_len) return -1;
    for (int i = 0; i <= haystack_len - needle_len; ++i) {
        if (memcmp(haystack + i, needle, needle_len) == 0) return i;
    }
    return -1;
}

// Retorna offset do começo do conteúdo do OCTET STRING que contém os auth params,
// procurando preferencialmente próximo ao engineID.
// Retorna -1 se não encontrar.
static int findAuthParamsOffsetNearEngineID(const byte* packet, int packet_len,
                                            const byte* engineID, int engineIDLen,
                                            const byte* authParams, int authParamsLen) {
    if (!packet || packet_len <= 0) return -1;

    // 1) tenta localizar engineID no pacote
    int startSearch = 0;
    int foundEngineOffset = -1;
    if (engineID && engineIDLen > 0) {
        foundEngineOffset = findSubsequence(packet, packet_len, engineID, engineIDLen);
        if (foundEngineOffset >= 0) {
            // vamos começar a busca dos OCTET STRING a partir do engineID
            startSearch = foundEngineOffset;
        }
    }

    // 2) itera pelos possíveis OCTET STRING (tag 0x04) a partir de startSearch até o fim
    for (int pos = startSearch; pos + 2 < packet_len; ++pos) {
        if (packet[pos] != 0x04) continue; // tag OCTET STRING
        // decodifica comprimento BER
        int lenPos = pos + 1;
        if (lenPos >= packet_len) continue;
        uint8_t lb = packet[lenPos];
        int lenBytes = 1;
        int lenVal = 0;
        if ((lb & 0x80) == 0) {
            lenVal = lb;
            lenBytes = 1;
        } else {
            int n = lb & 0x7F;
            if (lenPos + n >= packet_len) continue;
            lenVal = 0;
            for (int i = 0; i < n; ++i) {
                lenVal = (lenVal << 8) | packet[lenPos + 1 + i];
            }
            lenBytes = 1 + n;
        }
        int valueOffset = pos + 1 + lenBytes;
        if (valueOffset + lenVal > packet_len) continue;

        // se o comprimento bate com authParamsLen e o conteúdo coincide, retornamos offset
        if (lenVal == authParamsLen) {
            if (memcmp(packet + valueOffset, authParams, authParamsLen) == 0) {
                return valueOffset;
            }
        }
    }

    // último recurso: procura em todo o buffer por authParams (fallback)
    int fallback = findSubsequence(packet, packet_len, authParams, authParamsLen);
    return fallback; // pode ser -1 se não encontrar
}

// ----------------- authenticateIncomingMsg (substitua a existente por esta) -----------------

bool USM::authenticateIncomingMsg(const SNMPV3User& user, const SNMPV3SecurityParameters& params, const byte* packet, uint16_t packet_len) {
    if (user.securityLevel == NO_AUTH_NO_PRIV) return true;

    // 0) sanity checks
    if (!packet || packet_len == 0) {
        Serial.println("Authentication failed: empty packet.");
        return false;
    }

    // 1) Verificação da janela de tempo
    uint32_t incomingBoots = ntohl(params.msgAuthoritativeEngineBoots);
    uint32_t incomingTime  = ntohl(params.msgAuthoritativeEngineTime);

    if (incomingBoots != this->_engineBoots) {
        Serial.printf("Authentication failed: EngineBoots mismatch. Expected: %d, Got: %d\n", this->_engineBoots, incomingBoots);
        return false;
    }
    if (abs((long)this->getEngineTime() - (long)incomingTime) > 150) {
        Serial.println("Authentication failed: Message out of time window.");
        return false;
    }

    // 2) Setup do algoritmo de hash/HMAC
    const mbedtls_md_info_t* md_info = (user.authProtocol == AUTH_PROTOCOL_SHA)
        ? mbedtls_md_info_from_type(MBEDTLS_MD_SHA1)
        : mbedtls_md_info_from_type(MBEDTLS_MD_MD5);

    if (!md_info) {
        Serial.println("Authentication failed: md_info NULL.");
        return false;
    }

    int digest_len = mbedtls_md_get_size(md_info);
    Serial.printf("Auth protocol: %s, digest_len: %d, authParamLen (pkt): %d\n",
        (user.authProtocol==AUTH_PROTOCOL_SHA) ? "SHA1":"MD5",
        digest_len,
        params.msgAuthenticationParametersLength);

    // 3) imprime a chave derivada (authKey) para debugging (remover depois)
    Serial.print("Derived authKey: ");
    for (int i = 0; i < digest_len; ++i) {
        Serial.printf("%02X", user.authKey[i]);
    }
    Serial.println();

    // 4) Localiza offset exato do conteúdo do OCTET STRING que contém msgAuthenticationParameters
    int auth_params_offset = findAuthParamsOffsetNearEngineID(packet, packet_len,
        params.msgAuthoritativeEngineID, params.msgAuthoritativeEngineIDLength,
        params.msgAuthenticationParameters, params.msgAuthenticationParametersLength);

    if (auth_params_offset < 0) {
        Serial.println("Authentication failed: Could not locate auth signature within the packet buffer (robust search).");
        return false;
    }

    Serial.printf("auth_params_offset: %d (packet_len=%d)\n", auth_params_offset, packet_len);
    int aroundStart = max(0, auth_params_offset - 16);
    int aroundEnd   = min((int)packet_len, auth_params_offset + 16 + params.msgAuthenticationParametersLength);
    Serial.print("Packet bytes around auth field: ");
    for (int i = aroundStart; i < aroundEnd; ++i) Serial.printf("%02X", packet[i]);
    Serial.println();

    Serial.print("auth field (before zero): ");
    for (int i = 0; i < params.msgAuthenticationParametersLength; ++i) Serial.printf("%02X", packet[auth_params_offset + i]);
    Serial.println();

    // 5) prepara cópia do pacote e zera o campo de autenticação EXATAMENTE no offset
    byte temp_packet[MAX_SNMP_PACKET_LENGTH];
    if (packet_len > MAX_SNMP_PACKET_LENGTH) {
        Serial.println("Authentication failed: packet_len > MAX_SNMP_PACKET_LENGTH");
        return false;
    }
    memcpy(temp_packet, packet, packet_len);

    // RFC3414 usa HMAC-96 (12 bytes). Vamos zerar o tamanho recebido, mas avisar se for != 12.
    int zero_len = params.msgAuthenticationParametersLength;
    if (zero_len != 12) {
        Serial.printf("WARN: msgAuthenticationParametersLength != 12 (%d). Using given length for zeroing.\n", zero_len);
    }
    // safety: clamp zero_len
    if (zero_len < 0) zero_len = 12;
    if (zero_len > 32) zero_len = 32;
    memset(temp_packet + auth_params_offset, 0, zero_len);

    // 6) calcula HMAC completo sobre temp_packet
    byte full_hmac[MBEDTLS_MD_MAX_SIZE];
    memset(full_hmac, 0, sizeof(full_hmac));
    mbedtls_md_hmac(md_info, user.authKey, digest_len, temp_packet, packet_len, full_hmac);

    // prints de debugging do HMAC
    Serial.print("Full HMAC calc: ");
    for (int i = 0; i < digest_len; ++i) Serial.printf("%02X", full_hmac[i]);
    Serial.println();

    Serial.print("HMAC-96 (used): ");
    for (int i = 0; i < 12; ++i) Serial.printf("%02X", full_hmac[i]);
    Serial.println();

    Serial.print("Received auth field: ");
    for (int i = 0; i < params.msgAuthenticationParametersLength; ++i) Serial.printf("%02X", params.msgAuthenticationParameters[i]);
    Serial.println();

    // 7) compara apenas os 12 primeiros bytes (HMAC-96)
    if (memcmp(full_hmac, params.msgAuthenticationParameters, 12) == 0) {
        Serial.println("Authentication successful.");
        return true;
    } else {
        Serial.println("Authentication failed: Wrong Digest (HMAC).");
        Serial.print("HMAC Recebido:  ");
        for (int i = 0; i < 12; ++i) Serial.printf("%02X", params.msgAuthenticationParameters[i]);
        Serial.println();
        Serial.print("HMAC Calculado: ");
        for (int i = 0; i < 12; ++i) Serial.printf("%02X", full_hmac[i]);
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