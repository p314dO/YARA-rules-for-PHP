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

