rule PHP_Cookie_Secure_False
{
    meta:
        description = "Detecta cookies con Secure flag explícitamente configurado como false"
        author = "Security Analysis"
        date = "2026-02-02"
        severity = "high"
        category = "security_misconfiguration"
        cwe = "CWE-614"
        
    strings:
        // Secure flag en false (parámetro 6)
        $secure_false = /setcookie\s*\([^,]+,[^,]+,[^,]+,[^,]+,\s*(false|0)\s*[,)]/ nocase
        
        // Array de opciones con secure => false
        $options_secure_false = /setcookie\s*\([^,]+,\s*[^,]+,\s*\[[^]]{1,300}['"]secure['"]\s*=>\s*(false|0)[^]]{1,100}\]/ nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}
