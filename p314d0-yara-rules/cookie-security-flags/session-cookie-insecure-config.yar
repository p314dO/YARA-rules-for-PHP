rule PHP_Session_Cookie_Insecure_Config
{
    meta:
        description = "Detecta configuración insegura de session cookies via ini_set"
        author = "Security Analysis"
        date = "2026-02-02"
        severity = "medium"
        category = "security_misconfiguration"
        
    strings:
        // session.cookie_httponly en false/0
        $session_httponly_false = /ini_set\s*\(\s*['"]session\.cookie_httponly['"]\s*,\s*['"]?(false|0|off)['"]?\s*\)/ nocase
        
        // session.cookie_secure en false/0
        $session_secure_false = /ini_set\s*\(\s*['"]session\.cookie_secure['"]\s*,\s*['"]?(false|0|off)['"]?\s*\)/ nocase
        
        // session.cookie_samesite no configurado o en None
        $session_samesite_none = /ini_set\s*\(\s*['"]session\.cookie_samesite['"]\s*,\s*['"]None['"]\s*\)/ nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}