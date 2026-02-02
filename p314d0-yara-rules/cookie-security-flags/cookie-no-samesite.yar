rule PHP_Cookie_No_SameSite
{
    meta:
        description = "Detecta cookies sin el atributo SameSite (protección CSRF)"
        author = "Security Analysis"
        date = "2026-02-02"
        severity = "medium"
        category = "security_misconfiguration"
        cwe = "CWE-352"
        
    strings:
        // setcookie sin mencionar samesite en ningún lado
        // Esto es difícil de detectar con certeza, así que buscamos setcookie sin el array de opciones
        $setcookie_old_style = /setcookie\s*\(\s*["'][^"']+["']\s*,\s*[^,)]+\s*,\s*[^,)]+\s*,\s*[^,)]+\s*,\s*[^,)]+\s*,\s*[^,)]+\s*,\s*[^,)]+\s*\)/ nocase
        
        // Cookies de autenticación sin options array (PHP < 7.3 o sin SameSite)
        $auth_no_options_array = /setcookie\s*\(\s*["'](auth|session|token)["']\s*,[^[{)]+\)/ nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}