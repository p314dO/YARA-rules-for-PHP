rule Database_Side_Password_Hashing
{
    meta:
        description = "Detecta hashing de passwords en el lado de la base de datos (inseguro)"
        author = "Security Analysis"
        date = "2026-02-02"
        severity = "high"
        category = "cryptography"
        cwe = "CWE-916"
        
    strings:
        // SQL con funciones hash aplicadas a passwords - OPTIMIZADO
        $sql_md5_func = /=\s*md5\s*\(\s*["']\s*\$.{1,100}password/i nocase
        $sql_sha_func = /=\s*sha[12]\s*\(\s*["']\s*\$.{1,100}password/i nocase
        
        // INSERT/UPDATE con MD5/SHA en columna password
        $insert_md5 = /INSERT\s+INTO\s+.{1,100}\s+\(\s*[^)]{1,100}password[^)]{1,100}\)\s+VALUES\s*\([^)]{1,200}md5\s*\(/i nocase
        $update_md5 = /UPDATE\s+.{1,100}\s+SET\s+.{1,100}password\s*=\s*md5\s*\(/i nocase
        
        // Concatenación de string + password en SQL con hash
        $sql_concat_md5 = /\$sql\s*.{1,50}md5\s*\(\s*["'].{1,50}["']\s*\.\s*mysql_real_escape_string/i nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}