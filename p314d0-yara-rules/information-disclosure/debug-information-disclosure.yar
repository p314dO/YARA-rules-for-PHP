rule Debug_Information_Disclosure
{
    meta:
        description = "Detecta código que expone información de debugging"
        author = "Security Analysis"
        date = "2026-02-01"
        severity = "medium"
        category = "information_disclosure"
        cwe = "CWE-215"
        
    strings:
        // Información del servidor expuesta
        $server_info = /echo\s+\$_SERVER/i nocase
        $phpversion = /phpversion\s*\(\s*\)/i nocase
        
        // Debug mode activado
        $debug_true = /['"]debug['"]\s*[=:]\s*(true|1|['"]on['"])/i nocase
        $define_debug = /define\s*\(\s*['"]DEBUG['"]\s*,\s*(true|1)\s*\)/i nocase
        
        // Whoami y otros comandos de sistema
        $whoami = /exec\s*\(\s*['"]whoami['"]\s*\)/i nocase
        $uname = /exec\s*\(\s*['"]uname/i nocase
        
        // Stack traces completos
        $debug_backtrace = /debug_backtrace\s*\(\s*\)/i nocase
        $print_backtrace = /debug_print_backtrace\s*\(\s*\)/i nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}