rule Sensitive_Comments_Disclosure
{
    meta:
        description = "Detecta comentarios que revelan información sensible"
        author = "Security Analysis"
        date = "2026-02-01"
        severity = "low"
        category = "information_disclosure"
        cwe = "CWE-200"
        
    strings:
        // Comentarios con passwords
        $comment_pass1 = /\/\/\s*password\s*[:=]\s*\w+/i nocase
        $comment_pass2 = /\/\*.{1,200}password\s*[:=]\s*\w+.{1,200}\*\//i nocase
        $comment_pass3 = /#\s*password\s*[:=]\s*\w+/i nocase
        
        // TODO con información sensible - limitados a 200 chars
        $todo_password = /\/\/\s*TODO.{1,200}password/i nocase
        $todo_fix = /\/\/\s*TODO.{1,200}fix.{1,50}security/i nocase
        $todo_vuln = /\/\/\s*TODO.{1,200}(vulnerability|exploit|hack)/i nocase
        
        // Comentarios con credenciales
        $comment_creds = /\/\/\s*(username|user|login)\s*[:=]\s*\w+/i nocase
        
        // Comentarios revelando estructura interna
        $comment_db = /\/\/\s*database\s*[:=]/i nocase
        $comment_api = /\/\/\s*api[_\s]key\s*[:=]/i nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}