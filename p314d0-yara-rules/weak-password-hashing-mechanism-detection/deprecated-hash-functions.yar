rule Deprecated_Hash_Functions
{
    meta:
        description = "Detecta funciones de hash deprecadas o inseguras"
        author = "Security Analysis"
        date = "2026-02-02"
        severity = "medium"
        category = "cryptography"
        
    strings:
        // crypt() con DES (muy débil)
        $crypt_des = /crypt\s*\(\s*[^,]+,\s*\$\w+\s*\)/i nocase
        
        // Algoritmos específicos débiles en hash()
        $hash_md4 = /hash\s*\(\s*['"]md4['"]/i nocase
        $hash_md2 = /hash\s*\(\s*['"]md2['"]/i nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}