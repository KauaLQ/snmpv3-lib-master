#ifndef USM_H
#define USM_H

#include <Arduino.h>

class SNMPV3SecurityParameters;  // 👈 só avisa que a struct existe

// É uma boa prática mover estas definições para um arquivo de definições global (ex: defs.h)
// mas por enquanto, deixamos aqui para que o módulo USM seja autossuficiente.
enum SNMPV3SecurityLevel {
    NO_AUTH_NO_PRIV = 0, // noAuthNoPriv
    AUTH_NO_PRIV = 1,    // authNoPriv
    AUTH_PRIV = 3        // authPriv
};

enum SNMPV3AuthProtocol {
    AUTH_PROTOCOL_MD5,
    AUTH_PROTOCOL_SHA
};

enum SNMPV3PrivProtocol {
    PRIV_PROTOCOL_DES,
    PRIV_PROTOCOL_AES
};

struct SNMPV3User {
    char userName[33]; // +1 para terminador nulo
    SNMPV3SecurityLevel securityLevel;
    SNMPV3AuthProtocol authProtocol;
    char authPassword[64]; // Senha em texto plano
    SNMPV3PrivProtocol privProtocol;
    char privPassword[64]; // Senha em texto plano

    // Chaves localizadas (geradas a partir das senhas)
    byte authKey[20]; // SHA-1 usa 20 bytes, MD5 usa 16. 20 é seguro.
    byte privKey[16]; // AES-128 usa 16 bytes.
};

class USM {
public:
    USM();
    void begin(); // Inicializa o EngineID e contadores

    // Funções de gerenciamento do Engine
    const byte* getEngineID() const { return _engineID; }
    uint8_t getEngineIDLength() const { return _engineIDLength; }
    uint32_t getEngineBoots() const { return _engineBoots; }
    uint32_t getEngineTime() const; // Retorna o tempo desde a inicialização

    // Função principal de geração de chaves (Password to Key)
    bool passwordToKey(SNMPV3User& user);

    // Funções de autenticação
    // Assinatura antiga: bool authenticateOutgoingMsg(..., byte* auth_params_ptr);
    // Assinatura NOVA:
    bool authenticateOutgoingMsg(const SNMPV3User& user, const byte* packet, uint16_t packet_len, byte* hmac_output);

    // Assinatura antiga: (..., const byte* packet, ..., const byte* received_auth_params)
    // Assinatura NOVA:
    bool authenticateIncomingMsg(const SNMPV3User& user, const SNMPV3SecurityParameters& params, const byte* packet, uint16_t packet_len);

    // Funções de privacidade (Criptografia)
    // Retorna o novo tamanho dos dados criptografados
    // Assinatura antiga: (..., const byte* privacy_params)
    // Assinatura NOVA:
    int encryptPDU(const SNMPV3User& user, const byte* pdu, uint16_t pdu_len, byte* encrypted_pdu, byte* out_privacy_params);
    // Retorna o novo tamanho dos dados descriptografados
    // Assinatura antiga: (..., const byte* privacy_params)
    // Assinatura NOVA:
    int decryptPDU(const SNMPV3User& user, const byte* encrypted_pdu, uint16_t encrypted_len, byte* decrypted_pdu, const SNMPV3SecurityParameters& params);


private:
    byte _engineID[12];
    uint8_t _engineIDLength;
    uint32_t _engineBoots;
    uint32_t _startTime; // Tempo de boot em segundos

    // Função auxiliar para o algoritmo passwordToKey
    // void _expandPassword(const char* password, byte* buf);
    uint64_t _privSaltCounter = 0; // <<< ADICIONE ESTA LINHA
};

#endif // USM_H