rule Cookie_Without_Security_Flags
{
    meta:
        description = "Detecta setcookie() sin flags HttpOnly y Secure"
        author = "Security Analysis"
        date = "2026-02-02"
        severity = "high"
        category = "security_misconfiguration"
        cwe = "CWE-614, CWE-1004"
        owasp = "A05:2021"
        
    strings:
        // setcookie con solo 2 parámetros (nombre, valor) - SIN flags
        $setcookie_2params = /setcookie\s*\(\s*["'][^"']+["']\s*,\s*[^)]+\s*\)/ nocase
        
        // setcookie con 3 parámetros (nombre, valor, expire) - SIN flags
        $setcookie_3params = /setcookie\s*\(\s*["'][^"']+["']\s*,\s*[^,]+,\s*[^)]+\s*\)/ nocase
        
        // setcookie con 4 parámetros (nombre, valor, expire, path) - SIN flags
        $setcookie_4params = /setcookie\s*\(\s*["'][^"']+["']\s*,\s*[^,]+,\s*[^,]+,\s*[^)]+\s*\)/ nocase
        
        // setcookie con 5 parámetros (incluye domain) pero probablemente SIN httponly/secure
        $setcookie_5params = /setcookie\s*\(\s*["'][^"']+["']\s*,\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*[^)]+\s*\)/ nocase
        
        // Detectar setcookie sin 'true' para httponly (parámetro 7)
        // setcookie con 6 parámetros pero sin httponly
        $setcookie_no_httponly = /setcookie\s*\(\s*["'][^"']+["']\s*,[^,]+,[^,]+,[^,]+,[^,]+,\s*(false|0|NULL|\"\"|'')\s*\)/ nocase
        
        // Palabras clave de autenticación en nombres de cookie
        $auth_cookie_name = /setcookie\s*\(\s*["'](auth|session|token|sid|sess|login|user)[^"']*["']/i nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        (
            // setcookie con pocos parámetros (definitivamente sin flags)
            $setcookie_2params or 
            $setcookie_3params or
            $setcookie_4params or
            $setcookie_5params or
            // setcookie sin HttpOnly
            $setcookie_no_httponly or
            // O setcookie de autenticación (más crítico)
            $auth_cookie_name
        )
}