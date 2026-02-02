rule Configuration_File_Disclosure
{
    meta:
        description = "Detecta archivos de configuración que no deberían ser públicos"
        author = "Security Analysis"
        date = "2026-02-01"
        severity = "high"
        category = "information_disclosure"
        cwe = "CWE-538"
        
    strings:
        // Archivos de configuración típicos
        $config_pattern1 = /define\s*\(\s*['"]DB_(HOST|USER|PASSWORD|NAME)['"]/i nocase
        $config_pattern2 = /\$config\s*\[\s*['"]database['"]\s*\]/i nocase
        
        // Archivos .env en código
        $dotenv_load = /Dotenv\\Dotenv::create/i nocase
        $dotenv_var = /\$_ENV\s*\[\s*['"]\w+['"]\s*\]/i
        
        // phpinfo() expuesto
        $phpinfo = /phpinfo\s*\(\s*\)/i nocase
        
        // Indicadores de archivos de configuración en el contenido
        $config_file_indicator1 = /\/\*\s*config(uration)?\s*(file|settings)/i nocase
        $config_file_indicator2 = /<\?php\s*\/\/\s*config/i nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}
