rule File_With_Credentials
{
    meta:
        description = "Detecta archivos SQL que contienen credenciales o datos sensibles"
        author = "Security Analysis"
        date = "2026-02-01"
        severity = "high"
        category = "information_disclosure"
        cwe = "CWE-538"
        owasp = "A01:2021"
        
    strings:
        // Comandos SQL de creación de usuarios con passwords
        $create_user1 = /CREATE\s+USER\s+['"]?\w+['"]?\s*@\s*['"]?[^'"]{1,100}['"]?\s+IDENTIFIED\s+BY\s+['"]/i nocase
        $grant_identified = /GRANT\s+.{1,200}\s+IDENTIFIED\s+BY\s+['"]/i nocase
        
        // Passwords en INSERT statements con hash - OPTIMIZADO (contexto específico)
        $insert_password_md5 = /INSERT\s+INTO\s+.{1,100}\s+password\s*.{1,50}['"][a-f0-9]{32}['"]/i nocase
        $insert_password_sha1 = /INSERT\s+INTO\s+.{1,100}\s+password\s*.{1,50}['"][a-f0-9]{40}['"]/i nocase
        $insert_password_sha256 = /INSERT\s+INTO\s+.{1,100}\s+password\s*.{1,50}['"][a-f0-9]{64}['"]/i nocase
        
        // Hash en VALUES clause - OPTIMIZADO
        $values_md5 = /VALUES\s*\([^)]{1,200}['"][a-f0-9]{32}['"]/i nocase
        $values_sha1 = /VALUES\s*\([^)]{1,200}['"][a-f0-9]{40}['"]/i nocase
        
        // Credenciales comunes en SQL
        $sql_creds = /IDENTIFIED\s+BY\s+['"][^'"]{4,100}['"]/i nocase
        
        // Nombres de usuarios sensibles
        $admin_user = /(admin|root|pentesterlab|administrator|sa)\s*[,)'"@]/i nocase
        
        // Palabras clave de archivos SQL
        $sql_keywords = /CREATE\s+(DATABASE|TABLE|USER)/i nocase
        $insert_keyword = /INSERT\s+INTO/i nocase
        $grant_keyword = /GRANT\s+/i nocase
        
    condition:
        // Detectar si es un archivo SQL por contenido o magic bytes
        ($sql_keywords or $insert_keyword or $grant_keyword or
         uint32(0) == 0x41455243 or  // "CREA" de CREATE
         uint32(0) == 0x45534E49 or  // "INSE" de INSERT
         uint32(0) == 0x504F5244 or  // "DROP"
         uint32(0) == 0x52414C41) and // "ALAR" de ALTER
        
        // Al menos uno de los patrones sensibles
        ($create_user1 or $grant_identified or 
         $insert_password_md5 or $insert_password_sha1 or $insert_password_sha256 or
         $values_md5 or $values_sha1 or
         $sql_creds or
         ($admin_user and ($values_md5 or $values_sha1)))
}