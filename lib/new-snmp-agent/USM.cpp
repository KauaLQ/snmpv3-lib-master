// USM.cpp (versão final, com localizePrivKeyForEngine e decryptPDU corrigido)
// --------------------------------------------------------------------------------
#include "USM.h"
#include "SNMPPacket.h" // Para acessar SNMPV3SecurityParameters
#include <WiFi.h> // Para obter o endereço MAC
#include <Preferences.h>
#include <cstring>
#include <algorithm>
#include <cstdint>

// mbedTLS
#include "mbedtls/md.h"
#include "mbedtls/des.h"
#include "mbedtls/aes.h"

// Construtor
USM::USM() : _engineIDLength(0), _engineBoots(1), _startTime(0), _privSaltCounter(0) {
    memset(_engineID, 0, sizeof(_engineID));
}

// Inicializa o módulo
void USM::begin() {
    Preferences preferences;
    preferences.begin("snmp-agent", false);
    _engineBoots = preferences.getUInt("engineBoots", 0);
    _engineBoots++;
    preferences.putUInt("engineBoots", _engineBoots);
    preferences.end();

    Serial.printf("SNMP EngineBoots: %d\n", _engineBoots);

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

// ----------------- PASSWORD-TO-KEY (RFC3414 A.2) - com truncamento correto a 1MB -----------------
bool USM::passwordToKey(SNMPV3User& user) {
    const mbedtls_md_info_t* md_info;
    
    if (user.authProtocol == AUTH_PROTOCOL_SHA) {
        md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    } else {
        md_info = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    }
    if (!md_info) return false;

    const char* password = user.authPassword;
    size_t pass_len = strlen(password);
    int digest_len = mbedtls_md_get_size(md_info);
    byte digest[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md_info, 0) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }

    // Stretch password para exatamente 1.048.576 bytes (truncando a última repetição se necessário)
    const uint32_t TARGET = 1048576;
    if (pass_len == 0) {
        mbedtls_md_free(&ctx);
        return false;
    }
    mbedtls_md_starts(&ctx);
    uint32_t filled = 0;
    while (filled < TARGET) {
        size_t need = TARGET - filled;
        size_t to_copy = (pass_len <= need) ? pass_len : need;
        mbedtls_md_update(&ctx, (const unsigned char*)password, to_copy);
        filled += to_copy;
        if (to_copy < pass_len) break;
    }
    mbedtls_md_finish(&ctx, digest);

    // Localize authKey com THIS engineID (para o próprio agente)
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, digest, digest_len);
    mbedtls_md_update(&ctx, this->_engineID, this->_engineIDLength);
    mbedtls_md_update(&ctx, digest, digest_len);
    mbedtls_md_finish(&ctx, user.authKey);
    Serial.println("Generated localized Auth Key.");

    // Se precisa gerar chave de privacidade local:
    if (user.securityLevel == AUTH_PRIV) {
        password = user.privPassword;
        pass_len = strlen(password);
        if (pass_len == 0) {
            mbedtls_md_free(&ctx);
            return false;
        }
        // Stretch para 1MB (priv password)
        mbedtls_md_starts(&ctx);
        filled = 0;
        while (filled < TARGET) {
            size_t need = TARGET - filled;
            size_t to_copy = (pass_len <= need) ? pass_len : need;
            mbedtls_md_update(&ctx, (const unsigned char*)password, to_copy);
            filled += to_copy;
            if (to_copy < pass_len) break;
        }
        mbedtls_md_finish(&ctx, digest);

        // Localize priv key with THIS engineID
        mbedtls_md_starts(&ctx);
        mbedtls_md_update(&ctx, digest, digest_len);
        mbedtls_md_update(&ctx, this->_engineID, this->_engineIDLength);
        mbedtls_md_update(&ctx, digest, digest_len);
        byte temp_priv_key[MBEDTLS_MD_MAX_SIZE];
        mbedtls_md_finish(&ctx, temp_priv_key);
        // RFC: privKey is 128 bits for AES - use first 16 bytes of localized result
        memcpy(user.privKey, temp_priv_key, 16);
        Serial.println("Generated localized Priv Key.");
    }

    mbedtls_md_free(&ctx);
    return true;
}

// ----------------- HELPERS -----------------
static int findSubsequence(const byte* haystack, int haystack_len, const byte* needle, int needle_len) {
    if (!haystack || !needle || needle_len <= 0 || haystack_len < needle_len) return -1;
    for (int i = 0; i <= haystack_len - needle_len; ++i) {
        if (memcmp(haystack + i, needle, needle_len) == 0) return i;
    }
    return -1;
}

static int findAuthParamsOffsetNearEngineID(const byte* packet, int packet_len,
                                            const byte* engineID, int engineIDLen,
                                            const byte* authParams, int authParamsLen) {
    if (!packet || packet_len <= 0) return -1;

    int startSearch = 0;
    if (engineID && engineIDLen > 0) {
        int foundEngineOffset = findSubsequence(packet, packet_len, engineID, engineIDLen);
        if (foundEngineOffset >= 0) startSearch = foundEngineOffset;
    }

    for (int pos = startSearch; pos + 2 < packet_len; ++pos) {
        if (packet[pos] != 0x04) continue; // OCTET STRING tag
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
        if (lenVal == authParamsLen) {
            if (memcmp(packet + valueOffset, authParams, authParamsLen) == 0) {
                return valueOffset;
            }
        }
    }

    return findSubsequence(packet, packet_len, authParams, authParamsLen);
}

// Localiza auth key (Kul) para um engineID específico (para verificação/recepção)
static bool localizeAuthKeyForEngine(const SNMPV3User& user,
                                    const byte* engineID, int engineIDLen,
                                    byte* outKey, int& outKeyLen) {
    if (!user.authPassword || !outKey) return false;

    const mbedtls_md_info_t* md_info = (user.authProtocol == AUTH_PROTOCOL_SHA)
        ? mbedtls_md_info_from_type(MBEDTLS_MD_SHA1)
        : mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    if (!md_info) return false;

    int digest_len = mbedtls_md_get_size(md_info);
    byte digest[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md_info, 0) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }

    // Stretch para 1MB (correto, truncando a última repetição)
    const uint32_t TARGET = 1048576;
    const char* password = user.authPassword;
    size_t pass_len = strlen(password);
    if (pass_len == 0) { mbedtls_md_free(&ctx); return false; }

    mbedtls_md_starts(&ctx);
    uint32_t filled = 0;
    while (filled < TARGET) {
        size_t need = TARGET - filled;
        size_t to_copy = (pass_len <= need) ? pass_len : need;
        mbedtls_md_update(&ctx, (const unsigned char*)password, to_copy);
        filled += to_copy;
        if (to_copy < pass_len) break;
    }
    mbedtls_md_finish(&ctx, digest);

    // Localize: Kul = Hash(Ku || engineID || Ku)
    byte localized[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, digest, digest_len);
    if (engineID && engineIDLen > 0) mbedtls_md_update(&ctx, engineID, engineIDLen);
    mbedtls_md_update(&ctx, digest, digest_len);
    mbedtls_md_finish(&ctx, localized);

    memcpy(outKey, localized, digest_len);
    outKeyLen = digest_len;
    mbedtls_md_free(&ctx);
    return true;
}

// Localiza priv key (Kul for priv) para um engineID específico (para decryption)
static bool localizePrivKeyForEngine(const SNMPV3User& user,
                                    const byte* engineID, int engineIDLen,
                                    byte* outKey, int& outKeyLen) {
    if (!user.privPassword || !outKey) return false;

    const mbedtls_md_info_t* md_info = (user.authProtocol == AUTH_PROTOCOL_SHA)
        ? mbedtls_md_info_from_type(MBEDTLS_MD_SHA1)
        : mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    if (!md_info) return false;

    int digest_len = mbedtls_md_get_size(md_info);
    byte digest[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md_info, 0) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }

    // Stretch priv password para 1MB
    const uint32_t TARGET = 1048576;
    const char* password = user.privPassword;
    size_t pass_len = strlen(password);
    if (pass_len == 0) { mbedtls_md_free(&ctx); return false; }

    mbedtls_md_starts(&ctx);
    uint32_t filled = 0;
    while (filled < TARGET) {
        size_t need = TARGET - filled;
        size_t to_copy = (pass_len <= need) ? pass_len : need;
        mbedtls_md_update(&ctx, (const unsigned char*)password, to_copy);
        filled += to_copy;
        if (to_copy < pass_len) break;
    }
    mbedtls_md_finish(&ctx, digest);

    // Localize with provided engineID
    byte localized[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, digest, digest_len);
    if (engineID && engineIDLen > 0) mbedtls_md_update(&ctx, engineID, engineIDLen);
    mbedtls_md_update(&ctx, digest, digest_len);
    mbedtls_md_finish(&ctx, localized);

    memcpy(outKey, localized, digest_len);
    outKeyLen = digest_len;
    mbedtls_md_free(&ctx);
    return true;
}

// ----------------- Autentica uma mensagem que será ENVIADA -----------------
bool USM::authenticateOutgoingMsg(const SNMPV3User& user, const byte* packet, uint16_t packet_len, byte* hmac_output) {
    if (user.securityLevel == NO_AUTH_NO_PRIV) return true;
    const mbedtls_md_info_t* md_info = (user.authProtocol == AUTH_PROTOCOL_SHA) ? mbedtls_md_info_from_type(MBEDTLS_MD_SHA1) : mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    int digest_len = mbedtls_md_get_size(md_info);
    byte full_hmac[MBEDTLS_MD_MAX_SIZE];

    // Calcula o HMAC completo
    mbedtls_md_hmac(md_info, user.authKey, digest_len, packet, packet_len, full_hmac);

    // Copia apenas os 12 primeiros bytes (HMAC-96)
    memcpy(hmac_output, full_hmac, 12);
    return true;
}

// ----------------- Autentica uma mensagem RECEBIDA -----------------
bool USM::authenticateIncomingMsg(const SNMPV3User& user, const SNMPV3SecurityParameters& params, const byte* packet, uint16_t packet_len) {
    if (user.securityLevel == NO_AUTH_NO_PRIV) return true;
    if (!packet || packet_len == 0) { Serial.println("Authentication failed: empty packet."); return false; }

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

    const mbedtls_md_info_t* md_info = (user.authProtocol == AUTH_PROTOCOL_SHA)
        ? mbedtls_md_info_from_type(MBEDTLS_MD_SHA1)
        : mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    if (!md_info) { Serial.println("Authentication failed: md_info NULL."); return false; }
    int digest_len = mbedtls_md_get_size(md_info);

    Serial.printf("Auth protocol: %s, digest_len: %d, authParamLen (pkt): %d\n",
        (user.authProtocol==AUTH_PROTOCOL_SHA) ? "SHA1":"MD5",
        digest_len,
        params.msgAuthenticationParametersLength);

    Serial.print("Derived authKey (local): ");
    for (int i = 0; i < digest_len; ++i) Serial.printf("%02X", user.authKey[i]);
    Serial.println();

    int auth_params_offset = findAuthParamsOffsetNearEngineID(packet, packet_len,
        params.msgAuthoritativeEngineID, params.msgAuthoritativeEngineIDLength,
        params.msgAuthenticationParameters, params.msgAuthenticationParametersLength);

    if (auth_params_offset < 0) {
        Serial.println("Authentication failed: Could not locate auth signature within the packet buffer (robust search).");
        return false;
    }

    Serial.printf("auth_params_offset: %d (packet_len=%d)\n", auth_params_offset, packet_len);
    int aroundStart = std::max(0, auth_params_offset - 16);
    int aroundEnd   = std::min((int)packet_len, auth_params_offset + 16 + params.msgAuthenticationParametersLength);
    Serial.print("Packet bytes around auth field: ");
    for (int i = aroundStart; i < aroundEnd; ++i) Serial.printf("%02X", packet[i]);
    Serial.println();

    Serial.print("auth field (before zero): ");
    for (int i = 0; i < params.msgAuthenticationParametersLength; ++i) Serial.printf("%02X", packet[auth_params_offset + i]);
    Serial.println();

    byte temp_packet[MAX_SNMP_PACKET_LENGTH];
    if (packet_len > MAX_SNMP_PACKET_LENGTH) { Serial.println("Authentication failed: packet_len > MAX_SNMP_PACKET_LENGTH"); return false; }
    memcpy(temp_packet, packet, packet_len);

    int zero_len = params.msgAuthenticationParametersLength;
    if (zero_len != 12) Serial.printf("WARN: msgAuthenticationParametersLength != 12 (%d). Using given length for zeroing.\n", zero_len);
    if (zero_len < 0) zero_len = 12;
    if (zero_len > 32) zero_len = 32;
    memset(temp_packet + auth_params_offset, 0, zero_len);

    // Localize authKey for incoming authoritative engine
    byte localized_key[MBEDTLS_MD_MAX_SIZE];
    int localized_key_len = 0;
    bool ok_loc = localizeAuthKeyForEngine(user,
                                params.msgAuthoritativeEngineID,
                                params.msgAuthoritativeEngineIDLength,
                                localized_key, localized_key_len);
    if (!ok_loc) {
        Serial.println("Authentication failed: could not localize auth key for incoming engineID.");
        return false;
    }

    Serial.print("Incoming authoritativeEngineID: ");
    for (int i=0;i<params.msgAuthoritativeEngineIDLength;i++) Serial.printf("%02X", params.msgAuthoritativeEngineID[i]);
    Serial.println();

    Serial.print("Localized authKey (for incoming engine): ");
    for (int i=0;i<localized_key_len;i++) Serial.printf("%02X", localized_key[i]);
    Serial.println();

    byte full_hmac[MBEDTLS_MD_MAX_SIZE];
    memset(full_hmac, 0, sizeof(full_hmac));
    mbedtls_md_hmac(md_info, localized_key, localized_key_len, temp_packet, packet_len, full_hmac);

    Serial.print("Full HMAC calc: ");
    for (int i = 0; i < digest_len; ++i) Serial.printf("%02X", full_hmac[i]);
    Serial.println();

    Serial.print("HMAC-96 (used): ");
    for (int i = 0; i < 12; ++i) Serial.printf("%02X", full_hmac[i]);
    Serial.println();

    Serial.print("Received auth field: ");
    for (int i = 0; i < params.msgAuthenticationParametersLength; ++i) Serial.printf("%02X", params.msgAuthenticationParameters[i]);
    Serial.println();

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

// ----------------- Criptografia (encryptPDU) - AES-CFB-128 -----------------
int USM::encryptPDU(const SNMPV3User& user, const byte* pdu, uint16_t pdu_len, byte* encrypted_pdu, byte* out_privacy_params) {
    if (user.securityLevel != AUTH_PRIV) return 0;

    if (user.privProtocol == PRIV_PROTOCOL_AES) {
        uint64_t salt = ++_privSaltCounter;
        for (int i = 0; i < 8; i++) out_privacy_params[7 - i] = (salt >> (i * 8)) & 0xFF;

        uint8_t iv[16];
        uint32_t boots_n = htonl(this->_engineBoots);
        uint32_t time_n = htonl(this->getEngineTime());
        memcpy(iv, &boots_n, 4);
        memcpy(iv + 4, &time_n, 4);
        memcpy(iv + 8, out_privacy_params, 8);

        // --- Debug logs for encryption (salt, IV, privKey peek) ---
        SNMP_LOGD("encryptPDU: salt (u64) = %llu, privSaltCounter = %llu\n", (unsigned long long)salt, (unsigned long long)_privSaltCounter);
        SNMP_LOGD("encryptPDU: privacyParameters (8 bytes):");
        for (int i = 0; i < 8; ++i) SNMP_LOGD("%02X", out_privacy_params[i]);
        SNMP_LOGD("\n");
        SNMP_LOGD("encryptPDU: IV (16 bytes):");
        for (int i = 0; i < 16; ++i) SNMP_LOGD("%02X", iv[i]);
        SNMP_LOGD("\n");

        // --- LOCALIZE privKey FOR THE ENGINE ID used in this message ---
        byte localized_priv_key[MBEDTLS_MD_MAX_SIZE];
        int localized_priv_key_len = 0;
        bool ok_loc = localizePrivKeyForEngine(user, this->_engineID, this->_engineIDLength, localized_priv_key, localized_priv_key_len);
        if (!ok_loc) {
            SNMP_LOGD("encryptPDU: ERROR localizing priv key for engineID\n");
            return 0;
        }

        SNMP_LOGD("encryptPDU: localized_priv_key (first 16 bytes):");
        for (int i=0;i<16;i++) SNMP_LOGD("%02X", localized_priv_key[i]);
        SNMP_LOGD("\n");

        // print stored user.privKey for comparison
        SNMP_LOGD("encryptPDU: user.privKey (first 16 bytes):");
        for (int i=0;i<16;i++) SNMP_LOGD("%02X", user.privKey[i]);
        SNMP_LOGD("\n");

        // Use the localized key (first 16 bytes) as AES key
        mbedtls_aes_context aes_ctx;
        mbedtls_aes_init(&aes_ctx);
        mbedtls_aes_setkey_enc(&aes_ctx, localized_priv_key, 128);

        size_t iv_off = 0;
        mbedtls_aes_crypt_cfb128(&aes_ctx, MBEDTLS_AES_ENCRYPT, pdu_len, &iv_off, iv, pdu, encrypted_pdu);

        mbedtls_aes_free(&aes_ctx);
        return pdu_len;
    }
    return 0;
}

// ----------------- Descriptografia (decryptPDU) - AES-CFB-128 (corrigido) -----------------
int USM::decryptPDU(const SNMPV3User& user, const byte* encrypted_pdu, uint16_t encrypted_len, byte* decrypted_pdu, const SNMPV3SecurityParameters& params) {
    if (user.securityLevel != AUTH_PRIV) return 0;
    if (user.privProtocol == PRIV_PROTOCOL_AES) {
        // Monta IV copiando os bytes exatamente como vieram no pacote
        uint8_t iv[16];
        memcpy(iv, &params.msgAuthoritativeEngineBoots, 4);   // assume struct guarda wire bytes
        memcpy(iv + 4, &params.msgAuthoritativeEngineTime, 4);
        memcpy(iv + 8, params.msgPrivacyParameters, 8);

        // Localiza a privKey para o engine autoritativo da mensagem
        byte localized_priv_key[MBEDTLS_MD_MAX_SIZE];
        int localized_priv_key_len = 0;
        bool ok_priv = localizePrivKeyForEngine(user,
                                  params.msgAuthoritativeEngineID,
                                  params.msgAuthoritativeEngineIDLength,
                                  localized_priv_key, localized_priv_key_len);
        if (!ok_priv) {
            Serial.println("Decrypt failed: could not localize priv key for incoming engineID.");
            return 0;
        }

        SNMP_LOGD("decryptPDU: IV for decryption: ");
        for (int i=0;i<16;i++) SNMP_LOGD("%02X", iv[i]);
        SNMP_LOGD("\n");

        SNMP_LOGD("decryptPDU: localized_priv_key (first 16 bytes): ");
        for (int i=0;i<16;i++) SNMP_LOGD("%02X", localized_priv_key[i]);
        SNMP_LOGD("\n");

        // AES key is first 16 bytes of localized result (RFC)
        mbedtls_aes_context aes_ctx;
        mbedtls_aes_init(&aes_ctx);
        mbedtls_aes_setkey_enc(&aes_ctx, localized_priv_key, 128);

        size_t iv_off = 0;
        mbedtls_aes_crypt_cfb128(&aes_ctx, MBEDTLS_AES_DECRYPT, encrypted_len, &iv_off, iv, encrypted_pdu, decrypted_pdu);
        mbedtls_aes_free(&aes_ctx);

        // print head for debug
        Serial.print("Decrypted ScopedPDU head: ");
        for (int i=0;i<16 && i<encrypted_len;i++) Serial.printf("%02X", decrypted_pdu[i]);
        Serial.println();

        return encrypted_len;
    }
    return 0;
}