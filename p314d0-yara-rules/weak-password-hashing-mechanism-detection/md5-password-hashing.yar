rule MD5_Password_Hashing
{
    meta:
        description = "Detecta uso de MD5 para hashear passwords"
        author = "Security Analysis"
        date = "2026-02-02"
        severity = "critical"
        category = "cryptography"
        cwe = "CWE-327, CWE-916"
        owasp = "A02:2021"
        
    strings:
        // MD5 directo sobre password
        $md5_password1 = /md5\s*\(\s*\$\s*(password|pass|pwd)/i nocase
        $md5_password2 = /md5\s*\(\s*\$_POST\s*\[\s*['"](password|pass|pwd)['"]\s*\]/i nocase
        $md5_password3 = /md5\s*\(\s*\$_GET\s*\[\s*['"](password|pass|pwd)['"]\s*\]/i nocase
        
        // MD5 en consultas SQL (hashing en base de datos) - MEJORADO
        $sql_md5_password = /md5\s*\(\s*["\'][^"']{1,100}["']\s*\.\s*\$\s*(password|pass|pwd)/i nocase
        $sql_md5_inline = /(INSERT|UPDATE|SELECT)\s+.{1,200}\s+password\s*.{1,100}md5\s*\(/i nocase
        $sql_md5_concat = /md5\s*\(\s*\\?["'].{1,50}\\?["']\s*\.\s*mysql_real_escape_string\s*\(\s*\$\s*(password|pass)/i nocase
        
        // MD5 en string SQL concatenado
        $sql_string_md5 = /\$sql\s*.{1,100}['"]\s*,\s*md5\s*\(\s*\\?["']/i nocase
        $sql_concat_md5 = /\.=\s*['"]\s*,\s*md5\s*\(\s*\\?["']/i nocase
        $sql_password_md5 = /password\s*=\s*md5\s*\(\s*\\?["']/i nocase
        
        // Asignación de MD5 a variable de password
        $assign_md5_password = /\$\s*(password|pass|pwd|hash)\s*=\s*md5\s*\(/i nocase
        
        // Comparación de password con MD5
        $compare_md5 = /(password|pass|pwd)\s*[!=]=\s*md5\s*\(/i nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}
