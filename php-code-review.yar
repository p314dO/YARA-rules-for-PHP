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

include "p314d0-yara-rules/harcoded-credentials-and-secrets-detection/hardcoded-credentials.yar"
include "p314d0-yara-rules/harcoded-credentials-and-secrets-detection/harcoded-db-credentials-specific.yar"
include "p314d0-yara-rules/harcoded-credentials-and-secrets-detection/harcoded-crypto-secrets.yar"

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

include "p314d0-yara-rules/information-disclosure/commented-code-with-vulnerabilities.yar"
include "p314d0-yara-rules/information-disclosure/configuration-file-disclosure.yar"
include "p314d0-yara-rules/information-disclosure/debug-information-disclosure.yar"
include "p314d0-yara-rules/information-disclosure/error-message-disclosure.yar"
include "p314d0-yara-rules/information-disclosure/sensitive-comments-disclosure.yar"
include "p314d0-yara-rules/information-disclosure/sql-files-with-credentials.yar"


