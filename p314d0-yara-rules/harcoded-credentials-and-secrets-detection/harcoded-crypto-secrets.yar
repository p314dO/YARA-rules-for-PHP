rule PHP_Hardcoded_Crypto_Secrets
{
    meta:
        description = "Detecta secretos criptográficos hardcodeados en implementaciones"
        author = "Security Analysis"
        date = "2026-02-01"
        severity = "high"
        category = "cryptography"
        cwe = "CWE-798"
        
    strings:
        // Secretos en funciones hash (como en jwt.php)
        $hash_secret1 = /hash\s*\(\s*["']\w+["']\s*,\s*["'][^"']{5,}["']\s*\.\s*\$\w+\s*\)/ nocase
        $hash_secret2 = /hash\s*\(\s*["']\w+["']\s*,\s*\$\w+\s*\.\s*["'][^"']{5,}["']\s*\)/ nocase
        
        // JWT secrets hardcodeados
        $jwt_hs256 = /["']alg["']\s*:\s*["']HS256["']/ nocase
        $jwt_sign = /JWT\s*::\s*sign/ nocase
        
        // OpenSSL con keys hardcodeadas
        $openssl_key = /openssl_\w+\s*\([^)]*["'][^"']{16,}["'][^)]*\)/ nocase
        
        // Encryption keys
        $encrypt_key = /\$(encryption_?key|secret_?key|cipher_?key)\s*=\s*["'][^"']{8,}["']/ nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them and
        // Si detectamos JWT, revisar si hay hash con secret concatenado
        (($jwt_hs256 and $jwt_sign and $hash_secret1) or 
         $hash_secret2 or $openssl_key or $encrypt_key)
}