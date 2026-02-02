rule Hardcoded_DB_Credentials_Specific
{
    meta:
        description = "Detecta patrones específicos de credenciales de base de datos hardcodeadas"
        author = "Security Analysis"
        date = "2026-02-01"
        severity = "critical"
        category = "credentials"
        cwe = "CWE-798"
        
    strings:
        // Patrones específicos comunes de credenciales débiles
        $weak_cred1 = /mysql_connect\s*\([^)]*["'](pentesterlab|root|admin|test)["'][^)]*["'](pentesterlab|root|admin|test|password|123456)["'][^)]*\)/ nocase
        $weak_cred2 = /mysqli_connect\s*\([^)]*["'](pentesterlab|root|admin|test)["'][^)]*["'](pentesterlab|root|admin|test|password|123456)["'][^)]*\)/ nocase
        
        // Variables con credenciales asignadas directamente
        $user_hardcoded = /\$(db_?user|database_?user|username)\s*=\s*["'](root|admin|pentesterlab|user)["']\s*;/ nocase
        $pass_hardcoded = /\$(db_?pass|database_?password|password)\s*=\s*["'][^"']+["']\s*;/ nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}