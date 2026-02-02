# YARA Rule: Weak Password Hashing Mechanism Detection

## Descripción
Esta regla detecta el uso de algoritmos débiles o inseguros para hashear passwords. Los passwords NUNCA deben hashearse con MD5, SHA1, o funciones criptográficas rápidas. Deben usarse funciones específicas diseñadas para passwords como bcrypt, argon2, o PBKDF2.

## Archivo
`weak_password_hashing.yar`

## Reglas incluidas

### 1. `PHP_MD5_Password_Hashing`
**Severidad:** CRITICAL  
**CWE:** CWE-327 (Broken Cryptographic Algorithm), CWE-916 (Insufficient Computational Effort)

Detecta uso de MD5 para hashear passwords:
- MD5 directo sobre variables de password
- MD5 en consultas SQL (hashing en base de datos)
- MD5 con `mysql_real_escape_string`
- Asignación o comparación con MD5

### 2. `PHP_SHA1_Password_Hashing`
**Severidad:** HIGH  
**CWE:** CWE-327, CWE-759 (One-Way Hash Without Salt)

Detecta uso de SHA1 para passwords sin salt:
- SHA1 directo sobre passwords
- SHA1 en queries SQL
- Asignaciones con SHA1

### 3. `PHP_Weak_Hash_Without_Salt`
**Severidad:** HIGH  
**CWE:** CWE-759

Detecta hashing sin salt (vulnerable a rainbow tables):
- `hash('md5', $password)` sin salt
- `hash('sha1', $password)` sin salt
- `crypt($password)` sin salt

### 4. `PHP_Database_Side_Password_Hashing`
**Severidad:** HIGH  
**CWE:** CWE-916

Detecta hashing en el lado de la base de datos:
- INSERT/UPDATE con funciones hash SQL
- Concatenación de SQL con md5/sha1
- Password en texto plano hacia la base de datos

### 5. `PHP_Missing_Password_Hash_Function`
**Severidad:** MEDIUM  
**CWE:** CWE-916

Detecta funciones que manejan passwords pero no usan `password_hash()`:
- Funciones register/login/change_password sin password_hash

### 6. `PHP_Plaintext_Password_In_SQL`
**Severidad:** CRITICAL

Detecta passwords en texto plano en SQL:
- WHERE password = sin hash
- INSERT con password sin procesar

### 7. `PHP_Custom_Weak_Hash_Implementation`
**Severidad:** HIGH

Detecta implementaciones custom débiles:
- Funciones custom que usan MD5/SHA1
- Double hashing (md5(md5($pass))) - aún débil
- base64_encode como "hash"

### 8. `PHP_Deprecated_Hash_Functions`
**Severidad:** MEDIUM

Detecta funciones deprecadas:
- crypt() con DES
- hash() con MD2/MD4

## Ejemplos detectados

### user.php - Función register() (VULNERABLE)

```php
// ✗ VULNERABLE - Líneas 66-71
public static function register($user, $password) {
    $sql = "INSERT INTO users (login,password) values (\"";
    $sql.= mysql_real_escape_string($user);
    $sql.= "\", md5(\"";
    $sql.= mysql_real_escape_string($password);
    $sql.= "\"))";
    $result = mysql_query($sql);
    // ...
}
```

**Problemas detectados:**
1. ✗ **MD5 es un algoritmo débil** - Diseñado para velocidad, no seguridad
2. ✗ **Sin salt** - Vulnerable a rainbow tables
3. ✗ **Hashing en base de datos** - Password en texto plano entre app y DB
4. ✗ **Password en logs de DB** - Probablemente registrado en texto plano

### user.php - Función login() (VULNERABLE)

```php
// ✗ VULNERABLE - Líneas 48-53
public static function login($user, $password) {
    $sql = "SELECT * FROM users where login=\"";
    $sql.= mysql_real_escape_string($user);
    $sql.= "\" and password=md5(\"";
    $sql.= mysql_real_escape_string($password);
    $sql.= "\")";
    $result = mysql_query($sql);
    // ...
}
```

**Problemas:**
- ✗ Mismo problema: MD5 sin salt
- ✗ Password enviado en texto plano a la base de datos
- ✗ Vulnerable a ataques de diccionario y rainbow tables

## ¿Por qué MD5 es inseguro para passwords?

### 1. **Demasiado rápido**
MD5 fue diseñado para ser RÁPIDO, lo cual es malo para passwords:
- Un atacante puede probar **billones** de passwords por segundo
- GPUs modernas: ~200 **billones** de hashes MD5/segundo
- Hace ataques de fuerza bruta muy eficientes

### 2. **Sin salt = Rainbow Tables**
Sin salt, todos los usuarios con password "123456" tendrán el mismo hash:
```
password: 123456
MD5:      e10adc3949ba59abbe56e057f20f883e
```
Un atacante puede usar **rainbow tables** pre-computadas con millones de hashes.

### 3. **Passwords en texto plano hacia la DB**
```php
// ✗ El password viaja en TEXTO PLANO por la red interna
$sql = "INSERT ... md5(\"mypassword123\")";
```
Esto significa:
- ✗ Password visible en logs de base de datos
- ✗ Password interceptable en red interna
- ✗ Password visible en query logs

### 4. **Colisiones conocidas**
MD5 tiene colisiones conocidas (diferentes inputs dan el mismo hash).

## Solución Correcta

### ✅ Usar `password_hash()` (PHP 5.5+)

#### Para REGISTRAR usuarios:
```php
// ✓ CORRECTO
public static function register($user, $password) {
    // password_hash genera automáticamente un salt único
    $hash = password_hash($password, PASSWORD_ARGON2ID);
    // o PASSWORD_BCRYPT para compatibilidad
    
    $sql = "INSERT INTO users (login, password) VALUES (?, ?)";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$user, $hash]);
    
    return true;
}
```

**Ventajas:**
- ✅ Salt único automático para cada usuario
- ✅ Algoritmo seguro (Argon2id o bcrypt)
- ✅ Password hasheado en la aplicación, NO en DB
- ✅ Costoso computacionalmente (dificulta ataques)

#### Para VERIFICAR login:
```php
// ✓ CORRECTO
public static function login($user, $password) {
    $sql = "SELECT password FROM users WHERE login = ?";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$user]);
    $row = $stmt->fetch();
    
    if ($row && password_verify($password, $row['password'])) {
        return true;
    }
    return false;
}
```

**Ventajas:**
- ✅ `password_verify()` es resistente a timing attacks
- ✅ Maneja automáticamente el salt del hash
- ✅ Compatible con diferentes algoritmos

## Algoritmos Recomendados (2026)

| Algoritmo | Uso | Configuración PHP |
|-----------|-----|-------------------|
| **Argon2id** | ✅ Mejor opción | `PASSWORD_ARGON2ID` |
| **Argon2i** | ✅ Alternativa | `PASSWORD_ARGON2I` |
| **bcrypt** | ✅ Compatible | `PASSWORD_BCRYPT` |
| **PBKDF2** | ⚠️ Aceptable | Requiere implementación manual |
| **scrypt** | ⚠️ Aceptable | Requiere extensión |
| SHA-256/512 | ❌ **NO usar** | Demasiado rápido sin PBKDF2 |
| SHA-1 | ❌ **NO usar** | Inseguro |
| MD5 | ❌ **NO usar** | Completamente roto |

## Configuración recomendada

### Para máxima seguridad (Argon2id):
```php
$options = [
    'memory_cost' => 65536,  // 64 MB
    'time_cost' => 4,        // 4 iterations
    'threads' => 3           // 3 parallel threads
];

$hash = password_hash($password, PASSWORD_ARGON2ID, $options);
```

### Para compatibilidad (bcrypt):
```php
$options = [
    'cost' => 12  // Factor de trabajo (10-14 recomendado)
];

$hash = password_hash($password, PASSWORD_BCRYPT, $options);
```

## Migración desde MD5

### Paso 1: Añadir nueva columna
```sql
ALTER TABLE users ADD COLUMN password_new VARCHAR(255);
```

### Paso 2: Migrar gradualmente
```php
// En login
public static function login($user, $password) {
    $sql = "SELECT password, password_new FROM users WHERE login = ?";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$user]);
    $row = $stmt->fetch();
    
    if (!$row) return false;
    
    // Si tiene hash nuevo, usarlo
    if (!empty($row['password_new'])) {
        return password_verify($password, $row['password_new']);
    }
    
    // Si no, verificar con MD5 viejo y actualizar
    if (md5($password) === $row['password']) {
        // ¡Aprovechar el login para migrar!
        $newHash = password_hash($password, PASSWORD_ARGON2ID);
        $update = "UPDATE users SET password_new = ? WHERE login = ?";
        $stmt = $pdo->prepare($update);
        $stmt->execute([$newHash, $user]);
        return true;
    }
    
    return false;
}
```

### Paso 3: Después de migración completa
```sql
-- Renombrar columna nueva
ALTER TABLE users DROP COLUMN password;
ALTER TABLE users CHANGE password_new password VARCHAR(255);
```

## Uso de las reglas

### Escanear archivos PHP
```bash
yara weak_password_hashing.yar user.php
yara weak_password_hashing.yar login.php
```

### Escanear proyecto completo
```bash
yara -r weak_password_hashing.yar /var/www/html/
```

### Ver matches detallados
```bash
yara -s weak_password_hashing.yar /var/www/html/*.php
```

## Resultados de validación

```
user.php: ✓ DETECTADO
  [PHP_MD5_Password_Hashing]
    • INSERT/UPDATE/SELECT password = md5()
    • $sql con md5
    • password=md5()
  [PHP_Database_Side_Password_Hashing]
    • SQL concat con md5

Total: 3 vulnerabilidades detectadas
```

## Impacto de la vulnerabilidad

### Ataque con Rainbow Tables
```bash
# Hash MD5 encontrado en DB
hash: e10adc3949ba59abbe56e057f20f883e

# Búsqueda en rainbow table
$ echo "e10adc3949ba59abbe56e057f20f883e" | rainbow-crack
Password found: 123456

# Tiempo: < 1 segundo
```

### Ataque de Fuerza Bruta
```python
# GPU moderna puede probar 200 mil millones de hashes MD5/segundo
# Password de 8 caracteres alfanuméricos:
# 62^8 = 218 billones de combinaciones
# Tiempo con MD5: ~18 minutos
# Tiempo con bcrypt (cost=12): ~150 AÑOS
```

## Checklist de Seguridad

### Hashing de Passwords:
- [ ] Usar `password_hash()` con Argon2id o bcrypt
- [ ] NO usar MD5, SHA1, SHA256 directos
- [ ] NO hashear en la base de datos
- [ ] Salt único automático (via password_hash)
- [ ] Usar `password_verify()` para verificar
- [ ] Cost factor apropiado (bcrypt: 12+, Argon2: 64MB+)

### Base de Datos:
- [ ] Columna password: VARCHAR(255) o mayor
- [ ] Password hasheado en aplicación, no en SQL
- [ ] Usar prepared statements
- [ ] No loggear passwords (ni en texto plano ni hash)

### Código:
- [ ] Migrar de MD5/SHA1 a password_hash()
- [ ] Rehashear passwords en login (si detectas hash viejo)
- [ ] No enviar password por GET
- [ ] Usar HTTPS siempre

## Referencias
- [OWASP Top 10 2021: A02 - Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-759: Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)
- [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [PHP password_hash() Documentation](https://www.php.net/manual/en/function.password-hash.php)
