rule PHP_Hardcoded_Credentials
{
    meta:
        description = "Detecta credenciales hardcodeadas en código PHP"
        author = "Security Analysis"
        date = "2026-02-01"
        severity = "high"
        category = "credentials"
        cwe = "CWE-798"
        owasp = "A07:2021"
        
    strings:
        // Conexiones a bases de datos con credenciales hardcodeadas
        // mysql_connect/mysqli_connect con strings literales
        $mysql_connect1 = /mysql_connect\s*\(\s*["'][^"']+["']\s*,\s*["'][^"']+["']\s*,\s*["'][^"']+["']\s*\)/ nocase
        $mysqli_connect1 = /mysqli_connect\s*\(\s*["'][^"']+["']\s*,\s*["'][^"']+["']\s*,\s*["'][^"']+["']\s*,\s*["'][^"']+["']\s*\)/ nocase
        $pdo_connect1 = /new\s+PDO\s*\(\s*["'][^"']*[:;][^"']*["']\s*,\s*["'][^"']+["']\s*,\s*["'][^"']+["']\s*\)/ nocase
        
        // Patrones específicos de credenciales en conexiones
        $db_hardcoded = /\$\w+\s*=\s*mysql[i]?_connect\s*\([^)]*["'](root|admin|pentesterlab|user|password|test)[^)]*["'][^)]*\)/ nocase
        
        // Secretos criptográficos hardcodeados
        $crypto_secret1 = /hash\s*\(\s*["'](md5|sha1|sha256|sha512)["']\s*,\s*["'][^"']{8,}["']\s*\.\s*\$/ nocase
        $crypto_secret2 = /hash_hmac\s*\(\s*["'][^"']+["']\s*,\s*[^,]+,\s*["'][^"']{8,}["']\s*\)/ nocase
        $jwt_secret = /["']secret["']\s*[=:]\s*["'][^"']{6,}["']/ nocase
        
        // API Keys y tokens hardcodeados
        $api_key1 = /["']api[_-]?key["']\s*[=:]\s*["'][a-zA-Z0-9_\-]{16,}["']/ nocase
        $api_key2 = /["']token["']\s*[=:]\s*["'][a-zA-Z0-9_\-]{16,}["']/ nocase
        $api_key3 = /define\s*\(\s*["']API[_-]?KEY["']\s*,\s*["'][^"']{16,}["']\s*\)/ nocase
        
        // Passwords hardcodeados
        $password1 = /\$password\s*=\s*["'][^"']{4,}["']\s*;/ nocase
        $password2 = /["']password["']\s*[=:]\s*["'][^"']{4,}["']/ nocase
        $password3 = /define\s*\(\s*["']PASSWORD["']\s*,\s*["'][^"']{4,}["']\s*\)/ nocase
        
        // Patrones de configuración con secretos
        $config_secret = /\$config\s*\[\s*["'](password|secret|key|token)["']\s*\]\s*=\s*["'][^"']{4,}["']/ nocase
        
        // Salt hardcodeado
        $salt_hardcoded = /\$salt\s*=\s*["'][^"']{8,}["']/ nocase
        
    condition:
        // Debe ser un archivo PHP
        (uint16(0) == 0x3f3c or // "<?php" o "<?xml" o "<?"
         uint32(0) == 0x68703f3c) and // "<?ph"
        
        // Detectar al menos uno de los patrones
        any of ($mysql_connect*, $mysqli_connect*, $pdo_connect*, $db_hardcoded,
                $crypto_secret*, $jwt_secret,
                $api_key*, $password*, $config_secret, $salt_hardcoded)
}




