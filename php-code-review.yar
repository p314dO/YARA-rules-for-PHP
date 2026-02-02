/*
YARA Rule: Hardcoded Credentials and Secrets Detection in PHP
    
    Description:
        Detecta credenciales y secretos hardcodeados en código fuente PHP.
        Los secretos deberían almacenarse en variables de entorno o archivos
        de configuración seguros, nunca en el código fuente.
    
    Author: Security Analysis
    Date: 2026-02-01
    Severity: HIGH
    
    References:
        - OWASP Top 10 2021: A07:2021 – Identification and Authentication Failures
        - CWE-798: Use of Hard-coded Credentials
        - CWE-259: Use of Hard-coded Password
*/

// include "p314d0-yara-rules/harcoded-credentials-and-secrets-detection/hardcoded-credentials.yar"
// include "p314d0-yara-rules/harcoded-credentials-and-secrets-detection/harcoded-db-credentials-specific.yar"
// include "p314d0-yara-rules/harcoded-credentials-and-secrets-detection/harcoded-crypto-secrets.yar"

/*
    YARA Rule: Information Disclosure Detection in PHP Applications
    
    Description:
        Detecta archivos y patrones que pueden llevar a fugas de información
        cuando están accesibles públicamente en la raíz web de una aplicación.
        
        Esto incluye:
        - Archivos SQL con credenciales o datos sensibles
        - Mensajes de error detallados expuestos al usuario
        - Comentarios con información sensible
        - Archivos de configuración accesibles
        - Información de debugging expuesta
    
    Author: Security Analysis
    Date: 2026-02-01
    Severity: MEDIUM to HIGH
    
    References:
        - OWASP Top 10 2021: A01:2021 – Broken Access Control
        - CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
        - CWE-209: Generation of Error Message Containing Sensitive Information
        - CWE-538: Insertion of Sensitive Information into Externally-Accessible File
*/

// include "p314d0-yara-rules/information-disclosure/commented-code-with-vulnerabilities.yar"
// include "p314d0-yara-rules/information-disclosure/configuration-file-disclosure.yar"
// include "p314d0-yara-rules/information-disclosure/debug-information-disclosure.yar"
// include "p314d0-yara-rules/information-disclosure/error-message-disclosure.yar"
// include "p314d0-yara-rules/information-disclosure/sensitive-comments-disclosure.yar"
// include "p314d0-yara-rules/information-disclosure/sql-files-with-credentials.yar"

/*
    YARA Rule: Missing Security Flags on Cookies
    
    Description:
        Detecta el uso de setcookie() sin los flags de seguridad necesarios:
        - HttpOnly: Previene acceso desde JavaScript (protección XSS)
        - Secure: Solo transmite cookie por HTTPS
        - SameSite: Protección contra CSRF
        
        Las cookies de autenticación deben SIEMPRE usar estos flags.
    
    Author: Security Analysis
    Date: 2026-02-02
    Severity: MEDIUM to HIGH
    
    References:
        - OWASP Top 10 2021: A05:2021 – Security Misconfiguration
        - CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
        - CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
*/

// include "p314d0-yara-rules/cookie-security-flags/authentication-cookie-insecure.yar"
// include "p314d0-yara-rules/cookie-security-flags/cookie-without-security-flags.yar"
// include "p314d0-yara-rules/cookie-security-flags/cookie-secure-false.yar"
// include "p314d0-yara-rules/cookie-security-flags/cookie-no-samesite.yar"
// include "p314d0-yara-rules/cookie-security-flags/session-cookie-insecure-config.yar"
// include "p314d0-yara-rules/cookie-security-flags/cookie-httponly-false.yar"

/*
    YARA Rule: Weak Password Hashing Mechanism Detection
    
    Description:
        Detecta el uso de algoritmos débiles o inseguros para hashear passwords.
        Los passwords NUNCA deben hashearse con MD5, SHA1, o funciones criptográficas
        rápidas sin salt. Deben usarse funciones específicas para passwords como:
        - password_hash() (bcrypt, argon2)
        - PBKDF2
        - scrypt
        
        Esta regla detecta:
        - Uso de MD5 para passwords
        - Uso de SHA1/SHA256 sin salt
        - Hashing en base de datos (SQL con md5/sha1)
        - Falta de salt en hashing
    
    Author: Security Analysis
    Date: 2026-02-02
    Severity: CRITICAL
    
    References:
        - OWASP Top 10 2021: A02:2021 – Cryptographic Failures
        - CWE-327: Use of a Broken or Risky Cryptographic Algorithm
        - CWE-759: Use of a One-Way Hash without a Salt
        - CWE-916: Use of Password Hash With Insufficient Computational Effort
*/

include "p314d0-yara-rules/weak-password-hashing-mechanism-detection/custom-weak-hash-implementation.yar"
include "p314d0-yara-rules/weak-password-hashing-mechanism-detection/database-side-password-hashing.yar"
include "p314d0-yara-rules/weak-password-hashing-mechanism-detection/deprecated-hash-functions.yar"
include "p314d0-yara-rules/weak-password-hashing-mechanism-detection/md5-password-hashing.yar"
include "p314d0-yara-rules/weak-password-hashing-mechanism-detection/missing-password-hash-function.yar"
include "p314d0-yara-rules/weak-password-hashing-mechanism-detection/plaintext-password-in-sql.yar"
include "p314d0-yara-rules/weak-password-hashing-mechanism-detection/sha1-password-hashing.yar"
include "p314d0-yara-rules/weak-password-hashing-mechanism-detection/weak-hash-without-salt.yar"

