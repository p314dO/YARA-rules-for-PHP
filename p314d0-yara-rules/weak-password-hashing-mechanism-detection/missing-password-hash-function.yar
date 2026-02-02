rule Missing_Password_Hash_Function
{
    meta:
        description = "Detecta falta de uso de password_hash() en código que maneja passwords"
        author = "Security Analysis"
        date = "2026-02-02"
        severity = "medium"
        category = "cryptography"
        cwe = "CWE-916"
        
    strings:
        // Código que maneja passwords pero NO usa password_hash
        $password_handling = /function\s+\w*register\w*\s*\([^)]{1,100}password[^)]{1,100}\)/i nocase
        $login_function = /function\s+\w*login\w*\s*\([^)]{1,100}password[^)]{1,100}\)/i nocase
        $change_password = /function\s+\w*change.{1,20}password\w*\s*\(/i nocase
        
        // NO debe contener password_hash (verificación negativa se hace manualmente)
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of ($password_handling, $login_function, $change_password) and
        not filesize > 100KB  // Evitar archivos muy grandes que pueden tener password_hash en otra parte
}