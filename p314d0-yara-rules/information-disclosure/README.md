# YARA Rule: Information Disclosure Detection

## Descripción
Esta regla detecta vulnerabilidades de fuga de información en aplicaciones PHP, incluyendo archivos sensibles expuestos públicamente y código que revela información que no debería ser accesible.

## Archivo
`information_disclosure.yar`

## Reglas incluidas

### 1. `SQL_File_With_Credentials`
**Severidad:** HIGH  
**CWE:** CWE-538 (Insertion of Sensitive Information into Externally-Accessible File)

Detecta archivos SQL que contienen:
- Comandos `CREATE USER` con passwords
- Statements `GRANT ... IDENTIFIED BY`
- Hashes de passwords (MD5, SHA1, SHA256)
- Usuarios sensibles (admin, root, pentesterlab)
- Credenciales en INSERT statements

### 2. `PHP_Error_Message_Disclosure`
**Severidad:** MEDIUM  
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)

Detecta exposición de mensajes de error:
- `echo mysql_error()` / `mysqli_error()`
- Errores de PDO expuestos
- `var_dump()` / `print_r()` en código productivo
- `display_errors` habilitado
- Stack traces y exception messages expuestos

### 3. `PHP_Sensitive_Comments_Disclosure`
**Severidad:** LOW  
**CWE:** CWE-200 (Exposure of Sensitive Information)

Detecta comentarios con información sensible:
- Passwords o credenciales en comentarios
- TODOs con información de seguridad
- Comentarios revelando estructura interna

### 4. `PHP_Configuration_File_Disclosure`
**Severidad:** HIGH  
**CWE:** CWE-538

Detecta archivos de configuración expuestos:
- Archivos config.php, settings.php
- Definiciones de credenciales de base de datos
- `phpinfo()` expuesto

### 5. `Sensitive_File_In_Webroot`
**Severidad:** HIGH  
**CWE:** CWE-538

Detecta archivos que no deberían estar en webroot:
- Archivos .sql
- Backups (.bak, .backup, .old)
- Archivos .env
- composer.json, package.json

### 6. `PHP_Debug_Information_Disclosure`
**Severidad:** MEDIUM  
**CWE:** CWE-215 (Information Exposure Through Debug Information)

Detecta información de debugging expuesta:
- Variables `$_SERVER` expuestas
- Debug mode activado
- Stack traces completos

### 7. `PHP_Commented_Code_With_Vulnerabilities`
**Severidad:** LOW  
**CWE:** CWE-615 (Inclusion of Sensitive Information in Source Code Comments)

Detecta código comentado problemático:
- `echo mysql_error()` comentado
- Debug statements comentados pero presentes en código

## Ejemplos detectados

### deploy.sql (Archivo SQL con credenciales)
```sql
-- ✗ VULNERABLE
GRANT ALL PRIVILEGES ON cr.* TO pentesterlab@'localhost' IDENTIFIED BY 'pentesterlab';

INSERT INTO `users` (login,password) VALUES ('admin','bcd86545c5903856961fa21b914c5fe4');
```

**Problemas detectados:**
1. ✗ Archivo SQL accesible en webroot
2. ✗ Credenciales de base de datos en texto plano
3. ✗ Hash MD5 de password del admin expuesto
4. ✗ Usuario 'admin' identificable

**Impacto:**
- Exposición de credenciales de base de datos
- Password hash del admin puede ser crackeado (MD5 es débil)
- Información sobre estructura de la base de datos

**Solución:**
```bash
# 1. Mover archivos SQL fuera del webroot
mv deploy.sql /var/www/database/scripts/

# 2. Restringir acceso con .htaccess
<Files "*.sql">
    Require all denied
</Files>

# 3. Usar variables de entorno para credenciales
# No incluir passwords en archivos de deployment
```

### user.php (Error messages expuestos)
```php
// ✗ VULNERABLE - Línea 77
else 
    echo mysql_error();
```

**Problema:** Expone detalles internos de errores SQL al usuario.

**Riesgo:**
- Revela estructura de base de datos
- Facilita ataques SQL injection
- Información sobre configuración interna

**Solución:**
```php
// ✓ CORRECTO
else {
    error_log("Database error: " . mysql_error()); // Log interno
    echo "An error occurred. Please try again.";   // Mensaje genérico al usuario
}
```

### user.php (Código comentado vulnerable)
```php
// ✗ VULNERABLE - Líneas 61-62
//else 
  //echo mysql_error();
```

**Problema:** Aunque está comentado, el código permanece en producción.

**Riesgo:**
- Puede ser descomentado accidentalmente
- Revela intención original del desarrollador
- Indica que el error no se está manejando apropiadamente

**Solución:**
```php
// ✓ CORRECTO - Eliminar código comentado
// Usar control de versiones (git) para historial
```

## Uso

### Escanear archivos individuales
```bash
yara information_disclosure.yar deploy.sql
yara information_disclosure.yar user.php
```

### Escanear directorio completo
```bash
yara -r information_disclosure.yar /var/www/html/
```

### Ver matches específicos
```bash
yara -s information_disclosure.yar /var/www/html/deploy.sql
```

## Remediación

### Para archivos SQL

**Problema:** Archivos SQL en webroot
```bash
# ✗ Estructura vulnerable
/var/www/html/
├── index.php
├── deploy.sql          # ¡ACCESIBLE PÚBLICAMENTE!
└── config.php
```

**Solución:**
```bash
# ✓ Estructura segura
/var/www/
├── html/               # Webroot
│   ├── index.php
│   └── config.php
└── database/           # FUERA del webroot
    └── deploy.sql
```

### Para mensajes de error

**Desarrollo:**
```php
// config.dev.php
ini_set('display_errors', 1);
error_reporting(E_ALL);
```

**Producción:**
```php
// config.prod.php
ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_ALL);
ini_set('error_log', '/var/log/php/error.log');

// Manejar errores apropiadamente
try {
    $result = mysql_query($sql);
    if (!$result) {
        error_log("DB Error: " . mysql_error());
        throw new Exception("Database operation failed");
    }
} catch (Exception $e) {
    error_log($e->getMessage());
    echo "An error occurred. Please contact support.";
}
```

### Proteger archivos sensibles con .htaccess

```apache
# .htaccess en webroot
<FilesMatch "\.(sql|bak|backup|old|env|log|ini)$">
    Require all denied
</FilesMatch>

<FilesMatch "^(composer|package)\.json$">
    Require all denied
</FilesMatch>
```

### Checklist de seguridad

- [ ] Archivos SQL fuera del webroot
- [ ] Display errors deshabilitado en producción
- [ ] Logs de error en ubicación segura
- [ ] Sin `var_dump()` o `print_r()` en producción
- [ ] Mensajes de error genéricos al usuario
- [ ] .htaccess configurado para denegar archivos sensibles
- [ ] Sin código comentado en producción
- [ ] Sin passwords o credenciales en comentarios
- [ ] phpinfo() eliminado o protegido
- [ ] Archivos .env, composer.json fuera de webroot

## Resultados de validación

```
deploy.sql: ✓ DETECTADO
  [SQL_File_With_Credentials]
    • GRANT con IDENTIFIED BY (credenciales)
    • Hash MD5 de password
    • Usuario pentesterlab/admin
  [Sensitive_File_In_Webroot]
    • Archivo .sql en webroot

user.php: ✓ DETECTADO
  [PHP_Error_Message_Disclosure]
    • echo mysql_error() expuesto (2 ocurrencias)
  [PHP_Commented_Code_With_Vulnerabilities]
    • SQL error comentado
    • die() comentado
```

## Referencias
- [OWASP Top 10 2021: A01 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-209: Error Message Information Leak](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-538: File and Directory Information Exposure](https://cwe.mitre.org/data/definitions/538.html)