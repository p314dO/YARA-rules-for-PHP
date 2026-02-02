rule Cookie_HttpOnly_False
{
    meta:
        description = "Detecta cookies con HttpOnly explícitamente configurado como false"
        author = "Security Analysis"
        date = "2026-02-02"
        severity = "high"
        category = "security_misconfiguration"
        cwe = "CWE-1004"
        
    strings:
        // HttpOnly explícitamente en false
        $httponly_false1 = /setcookie\s*\([^)]{1,300},\s*false\s*\)/ nocase
        $httponly_false2 = /setcookie\s*\([^)]{1,300},\s*0\s*\)/ nocase
        
        // Array de opciones con httponly => false (PHP 7.3+)
        $options_httponly_false = /setcookie\s*\([^,]+,\s*[^,]+,\s*\[[^]]{1,300}['"]httponly['"]\s*=>\s*(false|0)[^]]{1,100}\]/ nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}