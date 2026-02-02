rule Weak_Hash_Without_Salt
{
    meta:
        description = "Detecta hashing de passwords sin salt (vulnerable a rainbow tables)"
        author = "Security Analysis"
        date = "2026-02-02"
        severity = "high"
        category = "cryptography"
        cwe = "CWE-759"
        
    strings:
        // hash() sin salt evidente
        $hash_no_salt1 = /hash\s*\(\s*['"](md5|sha1|sha256)["']\s*,\s*\$\s*(password|pass|pwd)\s*\)/i nocase
        $hash_no_salt2 = /hash\s*\(\s*['"](md5|sha1|sha256)["']\s*,\s*\$_POST\s*\[\s*['"](password|pass)['"]\s*\]\s*\)/i nocase
        
        // crypt() sin salt (muy débil)
        $crypt_no_salt = /crypt\s*\(\s*\$\s*(password|pass|pwd)\s*\)/i nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}