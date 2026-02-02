rule SHA1_Password_Hashing
{
    meta:
        description = "Detecta uso de SHA1 para hashear passwords sin salt"
        author = "Security Analysis"
        date = "2026-02-02"
        severity = "high"
        category = "cryptography"
        cwe = "CWE-327, CWE-759"
        
    strings:
        // SHA1 directo sobre password
        $sha1_password1 = /sha1\s*\(\s*\$\s*(password|pass|pwd)/i nocase
        $sha1_password2 = /sha1\s*\(\s*\$_POST\s*\[\s*['"](password|pass|pwd)['"]\s*\]/i nocase
        
        // SHA1 en SQL
        $sql_sha1 = /(INSERT|UPDATE)\s+.{1,200}\s+password\s*.{1,100}sha1\s*\(/i nocase
        
        // Asignación de SHA1
        $assign_sha1 = /\$\s*(password|pass|pwd|hash)\s*=\s*sha1\s*\(/i nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}

