rule Error_Message_Disclosure
{
    meta:
        description = "Detecta código PHP que expone mensajes de error detallados al usuario"
        author = "Security Analysis"
        date = "2026-02-01"
        severity = "medium"
        category = "information_disclosure"
        cwe = "CWE-209"
        
    strings:
        // Echo/print de errores de MySQL
        $mysql_error1 = /echo\s+mysql_error\s*\(\s*\)/i nocase
        $mysql_error2 = /print\s+mysql_error\s*\(\s*\)/i nocase
        $mysqli_error1 = /echo\s+mysqli_error\s*\(/i nocase
        $mysqli_error2 = /print\s+mysqli_error\s*\(/i nocase
        
        // Echo/print de errores de PDO
        $pdo_error = /echo\s+\$\w+->errorInfo\s*\(\s*\)/i nocase
        
        // Var_dump/print_r en producción
        $var_dump = /var_dump\s*\(/i nocase
        $print_r_echo = /(echo|print)\s+print_r\s*\(/i nocase
        
        // Display errors habilitado
        $display_errors = /ini_set\s*\(\s*['"]display_errors['"]\s*,\s*['"]?(1|on|true)['"']?\s*\)/i nocase
        $error_reporting_all = /error_reporting\s*\(\s*E_ALL\s*\)/i nocase
        
        // Stack traces expuestos
        $exception_getMessage = /echo\s+\$\w+->getMessage\s*\(\s*\)/i nocase
        $exception_trace = /echo\s+\$\w+->getTraceAsString\s*\(\s*\)/i nocase
        
        // Debugging activo
        $xdebug = /xdebug_/i nocase
        
    condition:
        (uint16(0) == 0x3f3c or uint32(0) == 0x68703f3c) and
        any of them
}
