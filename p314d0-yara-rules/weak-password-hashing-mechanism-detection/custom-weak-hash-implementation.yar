rule Custom_Weak_Hash_Implementation
{
    meta:
        description = "Detecta implementaciones custom débiles de hashing"
        author = "Security Analysis"
        date = "2026-02-02"
        severity = "high"
        category = "cryptography"
        
    strings:
        // Funciones custom de hash que usan MD5/SHA1
        $custom_hash1 = /function\s+\w*hash.{1,20}password\w*\s*\([^)]{1,100}\)\s*\{[^}]{1,300}md5\s*\(/i nocase
        $custom_hash2 = /function\s+\w*hash.{1,20}password\w*\s*\([^)]{1,100}\)\s*\{[^}]{1,300}sha1\s*\(/i nocase
        
        // Double hashing (md5(md5($pass))) - aún débil
        $double_md5 = /md5\s*\(\s*md5\s*\(\s*\$/i nocase
        $double_sha1 = /sha1\s*\(\s*sha1\s*\(\s*\$/i nocase
        
        // Base64 usado como "hash" (no es hash)
        $base64_password = /base64_encode\s*\(\s*\$\s*(password|pass|pwd)/i nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}