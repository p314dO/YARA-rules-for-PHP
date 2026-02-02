# YARA Rule: Hardcoded Credentials Detection

## Descripción
Esta regla detecta credenciales y secretos hardcodeados en código fuente PHP, que es una vulnerabilidad crítica de seguridad.

## Archivo
`hardcoded_credentials.yar`

## Reglas incluidas

### 1. `PHP_Hardcoded_Credentials`
**Severidad:** HIGH  
**CWE:** CWE-798 (Use of Hard-coded Credentials)

Detecta patrones generales de credenciales hardcodeadas:
- Conexiones a bases de datos con credenciales en strings literales
- Secretos criptográficos hardcodeados
- API keys y tokens hardcodeados
- Passwords en variables
- Salts hardcodeados

### 2. `PHP_Hardcoded_DB_Credentials_Specific`
**Severidad:** CRITICAL  
**CWE:** CWE-798

Detecta patrones específicos de credenciales débiles de base de datos:
- Usuarios comunes: `root`, `admin`, `pentesterlab`, `test`
- Passwords comunes: `password`, `123456`, valores duplicados
- Variables de configuración con credenciales asignadas directamente

### 3. `PHP_Hardcoded_Crypto_Secrets`
**Severidad:** HIGH  
**CWE:** CWE-798

Detecta secretos en implementaciones criptográficas:
- Secretos en funciones `hash()` concatenados con datos
- JWT secrets hardcodeados
- OpenSSL keys hardcodeadas
- Encryption keys en variables

## Ejemplos detectados

### db.php
```php
// ✗ VULNERABLE
$lnk = mysql_connect("127.0.0.1", "pentesterlab", "pentesterlab");
```

**Problema:** Credenciales de base de datos hardcodeadas directamente en el código.

**Solución:**
```php
// ✓ CORRECTO
$lnk = mysql_connect(
    getenv('DB_HOST'),
    getenv('DB_USER'),
    getenv('DB_PASS')
);
```

### jwt.php
```php
// ✗ VULNERABLE
return hash("sha256","donth4ckmebr0".$data);
```

**Problema:** Secret criptográfico hardcodeado en el código fuente.

**Solución:**
```php
// ✓ CORRECTO
return hash_hmac("sha256", $data, getenv('JWT_SECRET'));
```

## Uso

### Ejecutar la regla
```bash
yara hardcoded_credentials.yar /path/to/php/files/
```

### Escanear directorio recursivamente
```bash
yara -r hardcoded_credentials.yar /path/to/project/
```

### Obtener detalles de matches
```bash
yara -s hardcoded_credentials.yar target_file.php
```

## Remediación

### Mejores prácticas

1. **Variables de entorno**
   ```php
   $db_host = getenv('DB_HOST');
   $db_user = getenv('DB_USER');
   $db_pass = getenv('DB_PASSWORD');
   ```

2. **Archivo de configuración externo** (fuera del código fuente)
   ```php
   $config = parse_ini_file('/etc/app/config.ini');
   $db_pass = $config['db_password'];
   ```

3. **Gestores de secretos**
   - AWS Secrets Manager
   - HashiCorp Vault
   - Azure Key Vault
   - Google Secret Manager

4. **Para desarrollo local**
   ```php
   // Usar .env con librerías como vlucas/phpdotenv
   require 'vendor/autoload.php';
   $dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
   $dotenv->load();
   
   $secret = $_ENV['JWT_SECRET'];
   ```

### Checklist de seguridad
- [ ] Ningún secreto en el código fuente
- [ ] Variables de entorno configuradas en producción
- [ ] `.env` en `.gitignore`
- [ ] Secretos diferentes entre desarrollo/staging/producción
- [ ] Rotación periódica de secretos
- [ ] Acceso limitado a secretos de producción

## Referencias
- [OWASP Top 10 2021: A07 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

## Resultados de validación

```
db.php: ✓ DETECTADO
  - mysql_connect con credenciales hardcodeadas
  - Credenciales débiles (pentesterlab/pentesterlab)

jwt.php: ✓ DETECTADO
  - Secret criptográfico hardcodeado ("donth4ckmebr0")
  - Implementación JWT con HS256

user.php: ✓ DETECTADO
  - Uso de JWT::sign (relacionado con secret hardcodeado)
```