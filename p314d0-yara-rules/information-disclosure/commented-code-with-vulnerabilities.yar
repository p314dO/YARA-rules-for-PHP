rule Commented_Code_With_Vulnerabilities
{
    meta:
        description = "Detecta código comentado que contiene vulnerabilidades o información sensible"
        author = "Security Analysis"
        date = "2026-02-01"
        severity = "low"
        category = "information_disclosure"
        cwe = "CWE-615"
        
    strings:
        // Código SQL comentado con errores
        $commented_sql_error = /\/\/\s*else\s*\n\s*\/\/\s*echo\s+mysql_error/i nocase
        
        // Debug comentado pero presente
        $commented_debug1 = /\/\/\s*var_dump/i nocase
        $commented_debug2 = /\/\/\s*print_r/i nocase
        
        // Die statements comentados
        $commented_die = /\/\/\s*die\s*\(/i nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}