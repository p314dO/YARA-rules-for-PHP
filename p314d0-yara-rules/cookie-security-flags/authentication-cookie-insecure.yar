rule Authentication_Cookie_Insecure
{
    meta:
        description = "Detecta cookies de autenticación específicamente sin flags de seguridad"
        author = "Security Analysis"
        date = "2026-02-02"
        severity = "critical"
        category = "authentication"
        cwe = "CWE-614, CWE-1004"
        
    strings:
        // Cookies de autenticación comunes sin opciones de seguridad
        $auth_cookie_simple = /setcookie\s*\(\s*["'](auth|session|token|login)["']\s*,\s*[^,)]+\s*\)/ nocase
        
        // setcookie("auth", ...) con solo 3 parámetros o menos
        $auth_no_flags = /setcookie\s*\(\s*["']auth["']\s*,\s*[^,)]+\s*,?\s*[^,)]*\s*\)/ nocase
        
        // Session cookies sin httponly
        $session_no_httponly = /setcookie\s*\(\s*["']sess(ion)?[^"']*["']\s*,[^)]{1,200}\)/ nocase
        
        // Token cookies inseguros
        $token_insecure = /setcookie\s*\(\s*["']token["']\s*,\s*[^,)]+\s*\)/ nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}