rule Plaintext_Password_In_SQL
{
    meta:
        description = "Detecta passwords en texto plano en queries SQL (sin hash)"
        author = "Security Analysis"
        date = "2026-02-02"
        severity = "critical"
        category = "cryptography"
        
    strings:
        // WHERE password = sin hash
        $plaintext_where = /WHERE\s+.{1,100}password\s*=\s*["']\s*\$/i nocase
        
        // INSERT con password sin hash evidente
        $plaintext_insert = /INSERT\s+INTO\s+.{1,100}\s+password\s*.{1,100}VALUES\s*\([^)]{1,200}\$_POST\s*\[\s*['"](password|pass)['"]\s*\]/i nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}