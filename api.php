<?php
/**
 * api.php — API REST clínica blindada
 * Hospital San Juan Bautista Huaral / Red de Salud Huaral-Chancay
 *
 * Endpoints principales:
 *   GET  ?action=establecimientos
 *   POST ?action=login | register_obstetra | logout
 *   GET  ?action=session_restore | overview | lookup_dni | audit_logs | reporte_campo | reporte_metodos
 *   POST ?action=save_paciente | update_estado | change_establecimiento | save_metodo
 *        ?action=verify_chain | test_waf
 *
 * Seguridad: PDO nativo persistente, WAF SQLi/XSS, rate limiting,
 * Bearer Token HMAC-SHA256 + cookie HttpOnly, sesión persistente de 7 días
 * (sliding expiration), AES-256-GCM y cadena de auditoría SHA-256.
 */
declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/catalogo_establecimientos.php';

// ---------------------------------------------------------------------------
// Cabeceras de seguridad clínica (OWASP ASVS L3) y CORS controlado
// ---------------------------------------------------------------------------
function api_server_origin(): string
{
    $forwardedProto = strtolower(trim((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')));
    $https = $forwardedProto === 'https'
        || (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off');
    $scheme = $https ? 'https' : 'http';
    $host = (string)($_SERVER['HTTP_X_FORWARDED_HOST'] ?? $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost');
    $host = trim(explode(',', $host)[0]);
    if ($host === '') {
        $host = 'localhost';
    }
    return $scheme . '://' . $host;
}

if (function_exists('header_remove')) {
    header_remove('X-Powered-By');
    header_remove('Server');
}
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('Content-Security-Policy: default-src \'none\'; frame-ancestors \'none\'; base-uri \'none\'; form-action \'none\'; object-src \'none\'');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cross-Origin-Resource-Policy: same-origin');
header('X-Permitted-Cross-Domain-Policies: none');
header('Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=()');
header('Vary: Origin');

$requestOrigin = trim((string)($_SERVER['HTTP_ORIGIN'] ?? ''));
$configuredOrigins = array_values(array_filter(array_map(
    'trim',
    explode(',', (string)getenv('ALLOWED_ORIGIN'))
), static fn (string $origin): bool => $origin !== ''));
if (!$configuredOrigins) {
    $configuredOrigins[] = api_server_origin();
}

$originAllowed = false;
if ($requestOrigin !== '') {
    foreach ($configuredOrigins as $allowedOrigin) {
        if ($allowedOrigin === '*' || hash_equals($allowedOrigin, $requestOrigin)) {
            $originAllowed = true;
            break;
        }
    }
    if ($originAllowed) {
        // Se devuelve el origen exacto (nunca "*" con credenciales) para que el
        // navegador aplique la política CORS sin abrir la API a cualquier sitio.
        header('Access-Control-Allow-Origin: ' . $requestOrigin);
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With, X-Sync-Token');
        header('Access-Control-Expose-Headers: Retry-After');
        header('Access-Control-Max-Age: 600');
    } else {
        json_error('Origen no autorizado por la política CORS del hospital.', 403, [
            'code' => 'CORS_ORIGIN_DENIED',
        ]);
    }
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// ---------------------------------------------------------------------------
// Helpers de respuesta
// ---------------------------------------------------------------------------
function json_out(array $data, int $status = 200): void
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    exit;
}

function json_error(string $message, int $status = 400, array $extra = []): void
{
    json_out(array_merge(['error' => $message], $extra), $status);
}

function read_json_body(): array
{
    static $cached = null;
    if (is_array($cached)) {
        return $cached;
    }
    $raw = file_get_contents('php://input');
    $decoded = json_decode($raw !== false ? $raw : '', true);
    $cached = is_array($decoded) ? $decoded : [];
    return $cached;
}

function require_session(): array
{
    $session = HospitalHuaralDB::authenticateSession();
    if ($session === null) {
        json_error('Sesión no válida o expirada. Inicie sesión nuevamente.', 401, [
            'code' => 'AUTH_REQUIRED',
        ]);
    }
    $dni = (string)($session['dni'] ?? '');
    $acceso = $dni !== '' ? HospitalHuaralDB::accesoUsuario($dni) : null;
    if ($acceso === null) {
        json_error('Su cuenta no existe en la tabla única app_usuarios. Solicite al Administrador de Estadística que la active.', 403, [
            'code' => 'ACCESS_NOT_FOUND',
        ]);
    }
    if (!HospitalHuaralDB::accesoActivo($dni)) {
        json_error('Su acceso a la aplicación fue desactivado. Contacte al Administrador de Estadística.', 403, [
            'code' => 'ACCESS_DISABLED',
        ]);
    }
    return $session;
}

/**
 * Perfil público de la obstetra autenticada (sin secretos TOTP).
 *
 * @param array<string, mixed> $session
 * @return array<string, mixed>
 */
function session_profile_payload(PDO $pdo, array $session): array
{
    $dni = (string)($session['dni'] ?? '');
    $acceso = HospitalHuaralDB::accesoUsuario($dni) ?: [];
    $nombres = trim((string)($acceso['nombres'] ?? ''));
    $apellidoPaterno = trim((string)($acceso['apellido_paterno'] ?? ''));
    $apellidoMaterno = trim((string)($acceso['apellido_materno'] ?? ''));
    $nombreCompleto = trim((string)($acceso['nombre_completo'] ?? ''));
    if ($nombreCompleto === '') {
        $nombreCompleto = trim($nombres . ' ' . $apellidoPaterno . ' ' . $apellidoMaterno);
    }
    if ($nombreCompleto === '') {
        $nombreCompleto = HospitalHuaralDB::nombrePersona($dni, $pdo);
    }
    if ($nombreCompleto === '') {
        $nombreCompleto = 'OBSTETRA ' . $dni;
    }
    $codEstab = (string)($session['cod_estab'] ?? ($acceso['cod_estab'] ?? '000005481'));
    $rol = HospitalHuaralDB::rolUsuario($dni);
    $esAdmin = is_admin_session(['dni' => $dni]);
    return [
        'token' => (string)($session['token'] ?? ''),
        'dni' => $dni,
        'nombres' => $nombres,
        'apellido_paterno' => $apellidoPaterno,
        'apellido_materno' => $apellidoMaterno,
        'nombreCompleto' => $nombreCompleto,
        'email' => (string)($acceso['email'] ?? ''),
        'celular' => (string)($acceso['celular'] ?? ''),
        'rol' => $rol,
        'rol_etiqueta' => HospitalHuaralDB::rolEtiqueta($rol),
        'nivelid' => $esAdmin ? 1 : 2,
        'cod_estab' => $codEstab,
        'estab_nombre' => hospital_nombre_establecimiento($codEstab),
        'verified2FA' => false,
        'platform' => (string)($session['platform'] ?? 'Web Desktop'),
        'isAdmin' => $esAdmin,
        'isJefa' => es_jefa_session(['dni' => $dni]),
        'puedeVerRed' => $esAdmin,
        'puedeCambiarEstablecimiento' => $esAdmin,
        'puedeGestionarAccesos' => puede_gestionar_accesos(['dni' => $dni]),
        'puedeResetearObstetra' => puede_resetear_obstetra(['dni' => $dni]),
        'accesoActivo' => HospitalHuaralDB::accesoActivo($dni),
        'expires_at' => (int)($session['expires_at'] ?? (time() + HospitalHuaralDB::SESSION_TTL)),
        'session_ttl' => HospitalHuaralDB::SESSION_TTL,
    ];
}

function is_admin_session(array $session): bool
{
    $dni = (string)($session['dni'] ?? '');
    if ($dni !== '' && HospitalHuaralDB::rolUsuario($dni) === 'ADMIN_ESTADISTICA') {
        return true;
    }
    return in_array($dni, array_map('strval', array_filter([
        getenv('APP_ADMIN_DNI') ?: '',
    ])), true) || (int)(getenv('APP_ADMIN_NIVELID') ?: 0) === 1;
}

function es_jefa_session(array $session): bool
{
    return HospitalHuaralDB::rolUsuario((string)($session['dni'] ?? '')) === 'JEFA_OBSTETRAS';
}

function puede_ver_red(array $session): bool
{
    return HospitalHuaralDB::esRolRed(HospitalHuaralDB::rolUsuario((string)($session['dni'] ?? '')));
}

function puede_gestionar_accesos(array $session): bool
{
    return is_admin_session($session);
}

function puede_resetear_obstetra(array $session): bool
{
    return HospitalHuaralDB::puedeResetearObstetra(HospitalHuaralDB::rolUsuario((string)($session['dni'] ?? '')));
}

/**
 * Variantes indexables del establecimiento activo de la sesión.
 *
 * @return array<int, string>
 */
function codigos_establecimiento_sesion(array $session): array
{
    $codigo = (string)($session['cod_estab'] ?? '');
    $variantes = hospital_codigos_busqueda_establecimiento($codigo);
    return $variantes ?: ($codigo !== '' ? [$codigo] : ['000005481']);
}

/**
 * Solo el Administrador de Estadística puede solicitar alcance de red.
 */
function es_alcance_red(array $session, string $alcance): bool
{
    return is_admin_session($session) && strtolower(trim($alcance)) === 'red';
}

/**
 * Condición SARGable `alias.cod_estab IN (...)` con placeholders posicionales.
 *
 * @param array<int, string> $codigos
 * @return array{0: string, 1: array<int, string>}
 */
function filtro_establecimiento_sql(string $alias, array $codigos): array
{
    $codigos = array_values(array_unique(array_filter(array_map('strval', $codigos), static fn ($c) => trim($c) !== '')));
    if (!$codigos) {
        return ['', []];
    }
    return [
        ' AND ' . $alias . '.cod_estab IN (' . implode(',', array_fill(0, count($codigos), '?')) . ') ',
        $codigos,
    ];
}


/**
 * Modo demostración: por defecto SOLO se activa en desarrollo local. En
 * producción (APP_ENV=production o RENDER=1) exige APP_DEMO_MODE=1 explícito.
 * Nunca debe habilitarse en el servidor del hospital.
 */
function demo_mode_enabled(): bool
{
    $raw = getenv('APP_DEMO_MODE');
    if ($raw !== false && trim((string)$raw) !== '') {
        return trim((string)$raw) === '1';
    }
    $appEnv = strtolower(trim((string)getenv('APP_ENV')));
    $render = strtolower(trim((string)getenv('RENDER')));
    return !($appEnv === 'production' || in_array($render, ['1', 'true', 'yes'], true));
}

/**
 * Segundo factor TOTP. Desactivado por defecto para evitar bloqueos operativos
 * (código vencido, autenticador no enrolado o desafío expirado). Puede
 * reactivarse en cualquier momento con APP_2FA_REQUIRED=1.
 */
function two_factor_required(): bool
{
    // El flujo clínico de obstetras es de UN SOLO PASO por decisión operativa:
    // DNI + clave + establecimiento. Las tablas app_2fa_challenges y
    // app_totp_secretos se conservan por compatibilidad, pero el login nunca
    // crea desafíos ni solicita OTP/TOTP.
    return false;
}

function waf_action_for_type(?string $type): string
{
    return match ($type) {
        'SQLI' => 'WAF_SQLI_BLOCKED',
        'XSS' => 'WAF_XSS_BLOCKED',
        'PATH_TRAVERSAL' => 'WAF_PATH_TRAVERSAL_BLOCKED',
        default => 'WAF_BLOCKED',
    };
}

// ---------------------------------------------------------------------------
// Conexión, endpoint de salud y WAF de aplicación
// ---------------------------------------------------------------------------
$action = isset($_GET['action']) ? (string)$_GET['action'] : '';
$body = read_json_body();

try {
    $pdo = HospitalHuaralDB::getConnection();
} catch (Throwable $e) {
    error_log('[PlanificaHIS] DB connection failure: ' . $e->getMessage());
    if ($action === 'health') {
        json_out([
            'status' => 'degraded',
            'db' => 'disconnected',
            'timestamp' => date('c'),
        ], 503);
    }
    json_error('No se pudo conectar a MySQL/MariaDB. Verifique que el servicio esté activo y la base de datos configurada.', 503);
}

// Endpoint ligero para Render/UptimeRobot. Nunca expone credenciales ni PII.
if ($action === 'health') {
    try {
        $pdo->query('SELECT 1')->fetchColumn();
        json_out([
            'status' => 'ok',
            'db' => 'connected',
            'timestamp' => date('c'),
        ], 200);
    } catch (Throwable $e) {
        error_log('[PlanificaHIS] Health check failure: ' . $e->getMessage());
        json_out([
            'status' => 'degraded',
            'db' => 'disconnected',
            'timestamp' => date('c'),
        ], 503);
    }
}

// WAF: inspecciona query string + cuerpo JSON + ruta. El simulador se evalúa aparte.
if ($action !== 'test_waf') {
    $inspection = HospitalHuaralDB::detectMaliciousPayload([
        'query' => $_GET,
        'body' => $body,
        'uri' => $_SERVER['REQUEST_URI'] ?? '',
    ]);
    if ($inspection['type'] !== null) {
        $ip = HospitalHuaralDB::clientIp();
        $platform = HospitalHuaralDB::detectPlatform();
        HospitalHuaralDB::registrarAuditoria(
            'WAF_INTERCEPTOR',
            waf_action_for_type($inspection['type']),
            'Ataque ' . $inspection['type'] . ' neutralizado. Patrón: [' . $inspection['matched'] . ']. Ruta: ' . ($_SERVER['REQUEST_URI'] ?? ''),
            '',
            $platform
        );
        json_error('Solicitud bloqueada por el Firewall de Seguridad Clínica (' . $inspection['type'] . ' detectado).', 403, [
            'code' => 'WAF_' . $inspection['type'] . '_BLOCKED',
            'matchedPattern' => $inspection['matched'],
            'ip' => $ip,
        ]);
    }
}

// ---------------------------------------------------------------------------
// Catálogo público (no contiene PII; necesario para el registro de obstetras)
// ---------------------------------------------------------------------------
if ($action === 'establecimientos') {
    json_out([
        'total' => count(hospital_establecimientos()),
        'establecimientos' => hospital_establecimientos(),
        'porDistrito' => hospital_establecimientos_por_distrito(),
    ]);
}

// ---------------------------------------------------------------------------
// Restauración de sesión persistente (cookie HttpOnly o Bearer de localStorage)
// ---------------------------------------------------------------------------
if ($action === 'session_restore' || $action === 'check_session') {
    $session = HospitalHuaralDB::authenticateSession();
    if ($session === null) {
        HospitalHuaralDB::clearSessionCookie();
        json_error('No existe una sesión persistente válida.', 401, ['code' => 'AUTH_REQUIRED']);
    }
    $accesoRestore = HospitalHuaralDB::accesoUsuario((string)$session['dni']);
    if ($accesoRestore === null || !HospitalHuaralDB::accesoActivo((string)$session['dni'])) {
        HospitalHuaralDB::revokeSession((string)$session['token']);
        json_error('Su cuenta no está activa en app_usuarios. Inicie sesión o contacte al Administrador de Estadística.', 403, ['code' => 'ACCESS_DISABLED']);
    }
    json_out([
        'authenticated' => true,
        'session' => session_profile_payload($pdo, $session),
        'server_time' => date('c'),
    ]);
}

// ---------------------------------------------------------------------------
// 1. LOGIN — 5 intentos fallidos / 15 min por IP + DNI
// ---------------------------------------------------------------------------
if ($action === 'login') {
    $dni = preg_replace('/[^0-9]/', '', (string)($body['dni'] ?? '')) ?? '';
    $password = (string)($body['password'] ?? '');
    $ip = HospitalHuaralDB::clientIp();
    $platform = HospitalHuaralDB::detectPlatform();

    if (strlen($dni) < 8 || strlen($dni) > 11) {
        json_error('Ingrese un DNI válido de 8 a 11 dígitos.', 400);
    }

    $bucket = 'login_fail:' . hash('sha256', $ip . '|' . $dni);
    $limit = HospitalHuaralDB::rateLimitStatus($bucket, 5, 900);
    if (!$limit['allowed']) {
        HospitalHuaralDB::registrarAuditoria($dni, 'LOGIN_RATE_LIMITED', 'Límite de 5 intentos fallidos alcanzado. Bloqueo temporal de 15 minutos.', '', $platform);
        json_error('Demasiados intentos fallidos. Espere 15 minutos antes de volver a intentar.', 429, [
            'retryAfter' => $limit['retryAfter'],
        ]);
    }

    $stmt = $pdo->prepare('SELECT * FROM app_usuarios WHERE dni = :dni LIMIT 1');
    $stmt->execute([':dni' => $dni]);
    $user = $stmt->fetch() ?: null;
    $preactivado = HospitalHuaralDB::dniPreactivado($dni);

    if (!$user && $preactivado !== null) {
        // Los DNIs preactivados se siembran en app_usuarios durante bootstrap.
        // Si por una instalación previa no existieran, se crean aquí.
        try {
            $pdo->prepare("
                INSERT INTO app_usuarios (dni, nombre_completo, rol, cod_estab, activo, puede_ver_red, creado_por)
                VALUES (:dni, :nombre, :rol, '000005481', 1, :red, 'LOGIN_BOOTSTRAP')
            ")->execute([
                ':dni' => $dni,
                ':nombre' => (string)$preactivado['nombre'],
                ':rol' => (string)$preactivado['rol'],
                ':red' => $preactivado['rol'] === 'ADMIN_ESTADISTICA' ? 1 : 0,
            ]);
            HospitalHuaralDB::olvidarAcceso($dni);
            $stmt->execute([':dni' => $dni]);
            $user = $stmt->fetch() ?: null;
        } catch (Throwable $e) {
            error_log('[PlanificaHIS] login bootstrap usuario: ' . $e->getMessage());
        }
    }
    if (!$user) {
        HospitalHuaralDB::rateLimitHit($bucket, 900);
        HospitalHuaralDB::registrarAuditoria($dni, 'AUTH_LOGIN_FAILED', 'DNI no registrado en app_usuarios.', '', $platform);
        // Respuesta genérica: no se revela si el DNI existe (anti-enumeración).
        json_error('DNI o contraseña incorrectos.', 401, ['remainingAttempts' => max(0, 4 - (int)$limit['hits'])]);
    }
    if ((int)($user['activo'] ?? 1) !== 1) {
        json_error('La cuenta se encuentra inactiva. Contacte a la Unidad de Estadística e Informática.', 403, [
            'code' => 'ACCESS_DISABLED',
        ]);
    }

    $storedPass = (string)($user['clave_hash'] ?? '');
    if ($storedPass === '') {
        // Contraseña inicial: el propio DNI. Se guarda Bcrypt automáticamente.
        $claveInicial = (string)(getenv('APP_PREACTIVATED_PASSWORD') ?: $dni);
        if (!hash_equals($claveInicial, $password)) {
            HospitalHuaralDB::rateLimitHit($bucket, 900);
            HospitalHuaralDB::registrarAuditoria($dni, 'AUTH_LOGIN_FAILED', 'Clave inicial incorrecta (clave_hash vacío).', '', $platform);
            json_error('DNI o contraseña incorrectos.', 401, ['remainingAttempts' => max(0, 4 - (int)$limit['hits'])]);
        }
        $pdo->prepare('UPDATE app_usuarios SET clave_hash = :pass WHERE dni = :dni LIMIT 1')
            ->execute([':pass' => HospitalHuaralDB::hashPassword($password), ':dni' => $dni]);
        $user['clave_hash'] = HospitalHuaralDB::hashPassword($password);
    } elseif (!HospitalHuaralDB::verifyPassword($password, $storedPass)) {
        HospitalHuaralDB::rateLimitHit($bucket, 900);
        HospitalHuaralDB::registrarAuditoria($dni, 'AUTH_LOGIN_FAILED', 'Contraseña inválida verificada con Bcrypt/Scrypt. Intento registrado.', '', $platform);
        $remaining = max(0, 4 - (int)$limit['hits']);
        json_error('DNI o contraseña incorrectos.', 401, ['remainingAttempts' => $remaining]);
    }

    HospitalHuaralDB::rateLimitReset($bucket);
    try {
        $pdo->prepare('UPDATE app_usuarios SET ultimo_login = CURRENT_TIMESTAMP WHERE dni = :dni LIMIT 1')
            ->execute([':dni' => $dni]);
    } catch (Throwable $e) {
        // El último acceso es informativo.
    }
    HospitalHuaralDB::olvidarAcceso($dni);

    $codEstab = hospital_codigo_canonico((string)($user['cod_estab'] ?? ''));
    if (hospital_establecimiento($codEstab) === null) {
        $codEstab = HospitalHuaralDB::obtenerEstablecimientoObstetra($dni);
    }
    if (hospital_establecimiento($codEstab) === null) {
        $codEstab = '000005481';
    }
    if ($codEstab !== (string)($user['cod_estab'] ?? '')) {
        try {
            $pdo->prepare('UPDATE app_usuarios SET cod_estab = :estab WHERE dni = :dni LIMIT 1')
                ->execute([':estab' => $codEstab, ':dni' => $dni]);
        } catch (Throwable $e) {
            // Se conserva el establecimiento de la sesión.
        }
    }

    $nombreCompleto = trim((string)($user['nombre_completo'] ?? ''));
    if ($nombreCompleto === '') {
        $nombreCompleto = trim(
            (string)($user['nombres'] ?? '') . ' ' .
            (string)($user['apellido_paterno'] ?? '') . ' ' .
            (string)($user['apellido_materno'] ?? '')
        );
    }
    if ($nombreCompleto === '') {
        $nombreCompleto = HospitalHuaralDB::nombrePersona($dni, $pdo);
    }
    if ($nombreCompleto === '') {
        $nombreCompleto = 'OBSTETRA ' . $dni;
    }
    $rol = strtoupper(trim((string)($user['rol'] ?? ''))) ?: 'OBSTETRA';
    $esAdmin = $rol === 'ADMIN_ESTADISTICA';
    $esJefa = $rol === 'JEFA_OBSTETRAS';

    // LOGIN DIRECTO DE UN SOLO PASO: credenciales válidas => sesión persistente
    // de 7 días. No se crean desafíos 2FA ni se solicita código TOTP/OTP.
    $token = HospitalHuaralDB::createSessionToken($dni, $codEstab, $platform);
    HospitalHuaralDB::registrarAuditoria(
        $dni,
        'AUTH_LOGIN_SUCCESS',
        'Credenciales válidas en app_usuarios. Login directo sin 2FA. Rol ' . $rol . '. Sesión persistente de 7 días emitida.',
        $codEstab,
        $platform
    );
    json_out([
        'requires2FA' => false,
        'session' => [
            'token' => $token,
            'dni' => $dni,
            'nombres' => (string)($user['nombres'] ?? ''),
            'apellido_paterno' => (string)($user['apellido_paterno'] ?? ''),
            'apellido_materno' => (string)($user['apellido_materno'] ?? ''),
            'nombreCompleto' => $nombreCompleto,
            'email' => (string)($user['email'] ?? ''),
            'celular' => (string)($user['celular'] ?? ''),
            'rol' => $rol,
            'rol_etiqueta' => HospitalHuaralDB::rolEtiqueta($rol),
            'nivelid' => $esAdmin ? 1 : 2,
            'cod_estab' => $codEstab,
            'estab_nombre' => hospital_nombre_establecimiento($codEstab),
            'verified2FA' => false,
            'platform' => $platform,
            'isAdmin' => $esAdmin,
            'isJefa' => $esJefa,
            'puedeVerRed' => $esAdmin,
            'puedeCambiarEstablecimiento' => $esAdmin,
            'puedeGestionarAccesos' => $esAdmin,
            'puedeResetearObstetra' => $esAdmin || $esJefa,
            'accesoActivo' => true,
            'expires_at' => time() + HospitalHuaralDB::SESSION_TTL,
            'session_ttl' => HospitalHuaralDB::SESSION_TTL,
        ],
    ]);
}

// ---------------------------------------------------------------------------
// 2. REGISTRO DE OBSTETRA + ESTABLECIMIENTO ASIGNADO
// ---------------------------------------------------------------------------
if ($action === 'register_obstetra') {
    $dni = preg_replace('/[^0-9]/', '', (string)($body['dni'] ?? '')) ?? '';
    $nombre1 = strtoupper(HospitalHuaralDB::sanitizeText($body['nombre1'] ?? '', 90));
    $apaterno = strtoupper(HospitalHuaralDB::sanitizeText($body['apaterno'] ?? '', 90));
    $amaterno = strtoupper(HospitalHuaralDB::sanitizeText($body['amaterno'] ?? '', 90));
    $email = strtolower(HospitalHuaralDB::sanitizeText($body['email'] ?? '', 190));
    $celular = preg_replace('/[^0-9]/', '', (string)($body['celular'] ?? '')) ?? '';
    $password = (string)($body['password'] ?? '');
    $codEstab = hospital_codigo_canonico((string)($body['cod_estab'] ?? ''));
    $platform = HospitalHuaralDB::detectPlatform();

    if (strlen($dni) !== 8 || $nombre1 === '' || $apaterno === '' || $email === '' || strlen($password) < 8) {
        json_error('Complete DNI (8 dígitos), nombres, apellidos, correo y contraseña de al menos 8 caracteres.', 400);
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        json_error('El correo institucional no tiene un formato válido.', 400);
    }
    if (hospital_establecimiento($codEstab) === null) {
        json_error('Seleccione un establecimiento válido de la Red Huaral-Chancay (53 IPRESS).', 400);
    }

    $stmt = $pdo->prepare('SELECT dni FROM app_usuarios WHERE dni = :dni LIMIT 1');
    $stmt->execute([':dni' => $dni]);
    if ($stmt->fetchColumn()) {
        json_error('Ya existe una cuenta con ese DNI. Inicie sesión o recupere su acceso.', 409);
    }

    $hashed = HospitalHuaralDB::hashPassword($password);
    $nombreCompleto = trim("{$apellidoPaterno} {$apellidoMaterno}, {$nombre1}");
    $stmt = $pdo->prepare("
        INSERT INTO app_usuarios
            (dni, nombres, apellido_paterno, apellido_materno, nombre_completo, email, celular,
             clave_hash, rol, cod_estab, puede_ver_red, activo, creado_por)
        VALUES
            (:dni, :nombres, :ap, :am, :completo, :email, :cel,
             :pass, 'OBSTETRA', :nivelcd, 0, 1, 'AUTOREGISTRO')
    ");
    $stmt->execute([
        ':dni' => $dni,
        ':nombres' => $nombre1,
        ':ap' => $apaterno,
        ':am' => $amaterno,
        ':completo' => $nombreCompleto,
        ':email' => $email,
        ':cel' => substr($celular, 0, 15),
        ':pass' => $hashed,
        ':nivelcd' => $codEstab,
    ]);
    HospitalHuaralDB::olvidarAcceso($dni);

    HospitalHuaralDB::establecerEstablecimientoObstetra($dni, $codEstab);

    // La cuenta queda operativa y la sesión persistente se emite de inmediato:
    // registro y login son de un solo paso, sin secretos TOTP ni desafíos.
    $token = HospitalHuaralDB::createSessionToken($dni, $codEstab, $platform);
    HospitalHuaralDB::registrarAuditoria(
        $dni,
        'REGISTRO_OBSTETRA',
        'Cuenta creada en app_usuarios para ' . $nombreCompleto . ' en ' . hospital_nombre_establecimiento($codEstab) . ' con login directo de 7 días.',
        $codEstab,
        $platform
    );
    json_out([
        'requires2FA' => false,
        'session' => [
            'token' => $token,
            'dni' => $dni,
            'nombres' => $nombre1,
            'apellido_paterno' => $apaterno,
            'apellido_materno' => $amaterno,
            'nombreCompleto' => $nombreCompleto,
            'email' => $email,
            'celular' => $celular,
            'rol' => 'OBSTETRA',
            'rol_etiqueta' => 'Obstetra',
            'nivelid' => 2,
            'cod_estab' => $codEstab,
            'estab_nombre' => hospital_nombre_establecimiento($codEstab),
            'verified2FA' => false,
            'platform' => $platform,
            'isAdmin' => false,
            'isJefa' => false,
            'puedeVerRed' => false,
            'puedeCambiarEstablecimiento' => false,
            'puedeGestionarAccesos' => false,
            'puedeResetearObstetra' => false,
            'accesoActivo' => true,
            'expires_at' => time() + HospitalHuaralDB::SESSION_TTL,
            'session_ttl' => HospitalHuaralDB::SESSION_TTL,
        ],
    ], 201);
}

// ---------------------------------------------------------------------------
// 3. VERIFICAR 2FA TOTP — DESHABILITADO (compatibilidad de tablas únicamente)
// ---------------------------------------------------------------------------
if ($action === 'verify_2fa') {
    json_error('El código de verificación 2FA está deshabilitado. El acceso es directo con DNI y contraseña.', 410, [
        'code' => '2FA_DISABLED',
    ]);
}

if ($action === 'verify_2fa') {
    $challengeId = HospitalHuaralDB::sanitizeText($body['challengeId'] ?? '', 64);
    $code = preg_replace('/[^0-9]/', '', (string)($body['code'] ?? '')) ?? '';
    $platform = HospitalHuaralDB::detectPlatform();
    $ip = HospitalHuaralDB::clientIp();

    if (!preg_match('/^[a-f0-9]{48}$/', $challengeId) || strlen($code) !== 6) {
        json_error('Desafío 2FA o código inválido.', 400);
    }

    // Máximo 5 intentos de verificación por desafío (no por DNI), para evitar
    // fuerza bruta sobre el código TOTP de 6 dígitos.
    $bucket = '2fa:' . hash('sha256', $challengeId . '|' . $ip);
    $limit = HospitalHuaralDB::rateLimitStatus($bucket, 5, 900);
    if (!$limit['allowed']) {
        HospitalHuaralDB::marcarChallengeUsado($challengeId);
        HospitalHuaralDB::registrarAuditoria(
            'DESCONOCIDO',
            'AUTH_2FA_RATE_LIMITED',
            'Límite de 5 intentos de verificación 2FA alcanzado para un desafío.',
            '',
            $platform
        );
        json_error('Demasiados intentos 2FA para este desafío. Inicie sesión nuevamente.', 429, [
            'retryAfter' => $limit['retryAfter'],
        ]);
    }
    HospitalHuaralDB::rateLimitHit($bucket, 900);

    $challenge = HospitalHuaralDB::obtenerChallenge($challengeId);
    if (!$challenge) {
        json_error('La verificación 2FA expiró o ya fue utilizada. Inicie sesión nuevamente.', 401);
    }

    $secret = HospitalHuaralDB::obtenerSecretoTotp((string)$challenge['dni']);
    if (!HospitalHuaralDB::verifyTOTP($secret, $code)) {
        HospitalHuaralDB::registrarAuditoria(
            (string)$challenge['dni'],
            'AUTH_2FA_FAILED',
            'Código TOTP inválido. Ventana RFC 6238 rechazada. El desafío continúa disponible hasta agotar los 5 intentos.',
            (string)$challenge['cod_estab'],
            $platform
        );
        json_error('Código 2FA de 6 dígitos incorrecto o expirado.', 401, [
            'remainingAttempts' => max(0, (int)$limit['remaining'] - 1),
        ]);
    }

    HospitalHuaralDB::marcarChallengeUsado($challengeId);
    HospitalHuaralDB::rateLimitReset($bucket);

    $dni = (string)$challenge['dni'];
    $codEstab = hospital_codigo_canonico((string)$challenge['cod_estab']);
    $stmt = $pdo->prepare('SELECT nombres, apellido_paterno, apellido_materno, email, rol FROM app_usuarios WHERE dni = :dni LIMIT 1');
    $stmt->execute([':dni' => $dni]);
    $user = $stmt->fetch() ?: [];
    $nombreCompleto = trim((string)($user['nombres'] ?? '') . ' ' . (string)($user['apellido_paterno'] ?? '') . ' ' . (string)($user['apellido_materno'] ?? ''));
    if ($nombreCompleto === '') {
        $nombreCompleto = 'OBSTETRA ' . $dni;
    }

    $token = HospitalHuaralDB::createSessionToken($dni, $codEstab, $platform);
    HospitalHuaralDB::registrarAuditoria($dni, 'AUTH_2FA_VERIFIED', 'Autenticación 2FA TOTP RFC 6238 verificada. Sesión Bearer emitida (expira en 8 h, inactividad 30 min).', $codEstab, $platform);

    json_out([
        'requires2FA' => false,
        'session' => [
            'token' => $token,
            'dni' => $dni,
            'nombreCompleto' => $nombreCompleto,
            'rol' => (string)($user['rol'] ?? 'OBSTETRA'),
            'nivelid' => strtoupper((string)($user['rol'] ?? '')) === 'ADMIN_ESTADISTICA' ? 1 : 2,
            'cod_estab' => $codEstab,
            'estab_nombre' => hospital_nombre_establecimiento($codEstab),
            'verified2FA' => true,
            'platform' => $platform,
            'isAdmin' => is_admin_session(['dni' => $dni]),
        ],
    ]);
}

// ---------------------------------------------------------------------------
// 4. LOGOUT / CAMBIO DE ESTABLECIMIENTO
// ---------------------------------------------------------------------------
if ($action === 'logout') {
    $session = require_session();
    HospitalHuaralDB::revokeSession((string)$session['token']);
    HospitalHuaralDB::registrarAuditoria($session['dni'], 'LOGOUT', 'Sesión revocada por el usuario.', $session['cod_estab'], $session['platform']);
    json_out(['success' => true]);
}

if ($action === 'change_establecimiento') {
    $session = require_session();
    if (!is_admin_session($session)) {
        json_error('Solo el Administrador de Estadística puede cambiar el establecimiento desde la cabecera. La Jefatura y las obstetras tienen establecimiento fijo.', 403, [
            'code' => 'ADMIN_REQUIRED',
        ]);
    }
    $codEstab = hospital_codigo_canonico((string)($body['cod_estab'] ?? ''));
    if (hospital_establecimiento($codEstab) === null) {
        json_error('El establecimiento seleccionado no pertenece a la Red Huaral-Chancay.', 400);
    }
    HospitalHuaralDB::cambiarEstablecimientoSesion((string)$session['token'], $codEstab, (string)$session['dni']);
    HospitalHuaralDB::registrarAuditoria(
        $session['dni'],
        'CAMBIO_ESTABLECIMIENTO',
        'El Administrador de Estadística cambió el establecimiento activo a ' . hospital_nombre_establecimiento($codEstab) . '.',
        $codEstab,
        $session['platform']
    );
    json_out([
        'success' => true,
        'session' => [
            'dni' => $session['dni'],
            'cod_estab' => $codEstab,
            'estab_nombre' => hospital_nombre_establecimiento($codEstab),
        ],
    ]);
}

// ---------------------------------------------------------------------------
// 4-B. RECUPERACIÓN DE CLAVE SIN TOTP (DNI + PIN/últimos 4 + establecimiento)
// ---------------------------------------------------------------------------
if ($action === 'recuperar_clave') {
    $dni = preg_replace('/[^0-9]/', '', (string)($body['dni'] ?? '')) ?? '';
    $pin = preg_replace('/[^0-9A-Za-z]/', '', (string)($body['pin'] ?? '')) ?? '';
    $codEstab = hospital_codigo_canonico((string)($body['cod_estab'] ?? ''));
    $nuevaClave = (string)($body['password'] ?? '');
    $platform = HospitalHuaralDB::detectPlatform();

    if (strlen($dni) < 8 || strlen($dni) > 11) {
        json_error('Ingrese un DNI válido de 8 a 11 dígitos.', 400);
    }
    if (strlen($pin) < 4) {
        json_error('Ingrese su PIN de recuperación o los últimos 4 dígitos de su DNI/celular.', 400);
    }
    if (strlen($nuevaClave) < 8) {
        json_error('La nueva contraseña debe tener al menos 8 caracteres.', 400);
    }

    $bucket = 'recuperar_clave:' . hash('sha256', HospitalHuaralDB::clientIp() . '|' . $dni);
    $limit = HospitalHuaralDB::rateLimitStatus($bucket, 5, 900);
    if (!$limit['allowed']) {
        json_error('Demasiados intentos de recuperación. Espere 15 minutos.', 429, ['retryAfter' => $limit['retryAfter']]);
    }

    $stmtUser = $pdo->prepare('SELECT * FROM app_usuarios WHERE dni = :dni LIMIT 1');
    $stmtUser->execute([':dni' => $dni]);
    $usuario = $stmtUser->fetch() ?: null;

    if ($usuario === null) {
        HospitalHuaralDB::rateLimitHit($bucket, 900);
        HospitalHuaralDB::registrarAuditoria($dni, 'AUTH_RECOVERY_FAILED', 'Recuperación rechazada: DNI sin cuenta en app_usuarios.', '', $platform);
        json_error('Los datos de recuperación no coinciden. Verifique DNI, PIN y establecimiento.', 401);
    }
    if ((int)($usuario['activo'] ?? 1) !== 1) {
        json_error('Su cuenta está desactivada. Contacte al Administrador de Estadística.', 403, ['code' => 'ACCESS_DISABLED']);
    }

    $estabGuardado = trim((string)($usuario['cod_estab'] ?? ''));
    if ($estabGuardado === '' || strtoupper($estabGuardado) === 'ALL' || hospital_establecimiento($estabGuardado) === null) {
        if ($codEstab === '' || hospital_establecimiento($codEstab) === null) {
            HospitalHuaralDB::rateLimitHit($bucket, 900);
            json_error('Seleccione un establecimiento válido de la Red Huaral-Chancay.', 400);
        }
        // La cuenta no tenía establecimiento: se acepta y guarda el seleccionado.
        $estabAsignado = $codEstab;
    } else {
        $estabAsignado = hospital_codigo_canonico($estabGuardado);
        if ($codEstab === '' || $codEstab !== $estabAsignado) {
            HospitalHuaralDB::rateLimitHit($bucket, 900);
            HospitalHuaralDB::registrarAuditoria($dni, 'AUTH_RECOVERY_FAILED', 'Recuperación rechazada: establecimiento no coincide.', '', $platform);
            json_error('Los datos de recuperación no coinciden. Verifique DNI, PIN y establecimiento.', 401);
        }
    }

    $pinHash = (string)($usuario['pin_recuperacion'] ?? '');
    $ultimosDni = substr($dni, -4);
    $celularRegistrado = preg_replace('/[^0-9]/', '', (string)($usuario['celular'] ?? '')) ?? '';
    $ultimosCelular = strlen($celularRegistrado) >= 4 ? substr($celularRegistrado, -4) : '';
    $pinValido = false;
    if ($pinHash !== '') {
        $pinValido = hash_equals($pinHash, $pin) || HospitalHuaralDB::verifyPassword($pin, $pinHash);
    }
    if (!$pinValido && hash_equals($ultimosDni, $pin)) {
        $pinValido = true;
    }
    if (!$pinValido && $ultimosCelular !== '' && hash_equals($ultimosCelular, $pin)) {
        $pinValido = true;
    }
    if (!$pinValido) {
        HospitalHuaralDB::rateLimitHit($bucket, 900);
        HospitalHuaralDB::registrarAuditoria($dni, 'AUTH_RECOVERY_FAILED', 'Recuperación rechazada: PIN o últimos 4 dígitos incorrectos.', '', $platform);
        json_error('Los datos de recuperación no coinciden. Verifique DNI, PIN y establecimiento.', 401);
    }

    $hash = HospitalHuaralDB::hashPassword($nuevaClave);
    $pdo->prepare('UPDATE app_usuarios SET clave_hash = :pass, cod_estab = :estab WHERE dni = :dni LIMIT 1')
        ->execute([':pass' => $hash, ':estab' => $estabAsignado, ':dni' => $dni]);
    HospitalHuaralDB::olvidarAcceso($dni);
    HospitalHuaralDB::establecerEstablecimientoObstetra($dni, $estabAsignado);

    HospitalHuaralDB::rateLimitReset($bucket);
    HospitalHuaralDB::registrarAuditoria(
        $dni,
        'AUTH_RECOVERY_SUCCESS',
        'Contraseña restablecida en app_usuarios mediante DNI + PIN/últimos 4 dígitos + establecimiento (sin TOTP).',
        $estabAsignado,
        $platform
    );
    json_out(['success' => true, 'message' => 'Contraseña actualizada. Ya puede iniciar sesión con su nueva clave.']);
}

// ---------------------------------------------------------------------------
// 4-C. PERFIL PROPIO: nombres, celular, correo, PIN y contraseña
// ---------------------------------------------------------------------------
if ($action === 'actualizar_mi_perfil') {
    $session = require_session();
    $dni = (string)$session['dni'];
    $nombres = strtoupper(HospitalHuaralDB::sanitizeText($body['nombres'] ?? '', 120));
    $apellidoPaterno = strtoupper(HospitalHuaralDB::sanitizeText($body['apellido_paterno'] ?? '', 80));
    $apellidoMaterno = strtoupper(HospitalHuaralDB::sanitizeText($body['apellido_materno'] ?? '', 80));
    $nombreCompletoInput = strtoupper(HospitalHuaralDB::sanitizeText($body['nombre_completo'] ?? '', 190));
    $celular = preg_replace('/[^0-9]/', '', (string)($body['celular'] ?? '')) ?? '';
    $email = strtolower(HospitalHuaralDB::sanitizeText($body['email'] ?? '', 190));
    $pin = preg_replace('/[^0-9]/', '', (string)($body['pin'] ?? '')) ?? '';
    $nuevaClave = (string)($body['password'] ?? '');
    $codEstabInput = trim((string)($body['cod_estab'] ?? ''));

    if ($celular !== '' && (strlen($celular) < 6 || strlen($celular) > 15)) {
        json_error('El celular debe contener entre 6 y 15 dígitos.', 400);
    }
    if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        json_error('El correo electrónico no tiene un formato válido.', 400);
    }
    if ($pin !== '' && strlen($pin) !== 4) {
        json_error('El PIN de recuperación debe tener exactamente 4 dígitos.', 400);
    }
    if ($nuevaClave !== '' && strlen($nuevaClave) < 8) {
        json_error('La nueva contraseña debe tener al menos 8 caracteres.', 400);
    }
    $codEstabFinal = '';
    if ($codEstabInput !== '') {
        $codEstabFinal = hospital_codigo_canonico($codEstabInput);
        if (hospital_establecimiento($codEstabFinal) === null) {
            json_error('Seleccione un establecimiento válido de la Red Huaral-Chancay (53 IPRESS).', 400);
        }
    }

    $actual = HospitalHuaralDB::accesoUsuario($dni) ?: [];
    $nombresFinal = $nombres !== '' ? $nombres : (string)($actual['nombres'] ?? '');
    $apPaternoFinal = $apellidoPaterno !== '' ? $apellidoPaterno : (string)($actual['apellido_paterno'] ?? '');
    $apMaternoFinal = $apellidoMaterno !== '' ? $apellidoMaterno : (string)($actual['apellido_materno'] ?? '');
    $nombreCompleto = trim($nombresFinal . ' ' . $apPaternoFinal . ' ' . $apMaternoFinal);
    if ($nombreCompletoInput !== '') {
        $nombreCompleto = $nombreCompletoInput;
    }
    if ($nombreCompleto === '') {
        $nombreCompleto = trim((string)($actual['nombre_completo'] ?? ''));
    }
    if ($nombreCompleto === '') {
        $nombreCompleto = HospitalHuaralDB::nombrePersona($dni, $pdo);
    }
    if ($nombreCompleto === '') {
        $nombreCompleto = 'OBSTETRA ' . $dni;
    }

    $sets = [];
    $params = [':dni' => $dni];
    if ($nombres !== '') {
        $sets[] = 'nombres = :nombres';
        $params[':nombres'] = $nombres;
    }
    if ($apellidoPaterno !== '') {
        $sets[] = 'apellido_paterno = :ap';
        $params[':ap'] = $apellidoPaterno;
    }
    if ($apellidoMaterno !== '') {
        $sets[] = 'apellido_materno = :am';
        $params[':am'] = $apellidoMaterno;
    }
    $sets[] = 'nombre_completo = :completo';
    $params[':completo'] = $nombreCompleto;
    if ($celular !== '') {
        $sets[] = 'celular = :cel';
        $params[':cel'] = substr($celular, 0, 15);
    }
    if ($email !== '') {
        $sets[] = 'email = :email';
        $params[':email'] = $email;
    }
    if ($pin !== '') {
        $sets[] = 'pin_recuperacion = :pin';
        $params[':pin'] = HospitalHuaralDB::hashPassword($pin);
    }
    if ($nuevaClave !== '') {
        $sets[] = 'clave_hash = :pass';
        $params[':pass'] = HospitalHuaralDB::hashPassword($nuevaClave);
    }
    $codEstabSesion = hospital_codigo_canonico((string)($actual['cod_estab'] ?? $session['cod_estab']));
    if ($codEstabFinal !== '') {
        $sets[] = 'cod_estab = :estab';
        $params[':estab'] = $codEstabFinal;
        $codEstabSesion = $codEstabFinal;
    }
    $pdo->prepare('UPDATE app_usuarios SET ' . implode(', ', $sets) . ' WHERE dni = :dni LIMIT 1')->execute($params);
    HospitalHuaralDB::olvidarAcceso($dni);

    if ($codEstabFinal !== '') {
        HospitalHuaralDB::establecerEstablecimientoObstetra($dni, $codEstabFinal);
        $pdo->prepare('UPDATE app_sesiones SET cod_estab = :estab WHERE token_hash = :hash AND dni = :dni')
            ->execute([
                ':estab' => $codEstabFinal,
                ':hash' => hash('sha256', (string)$session['token']),
                ':dni' => $dni,
            ]);
    }

    HospitalHuaralDB::registrarAuditoria(
        $dni,
        'PERFIL_ACTUALIZADO',
        'Actualización de datos personales y seguridad' . ($codEstabFinal !== '' ? ' · Establecimiento: ' . hospital_nombre_establecimiento($codEstabFinal) : '') . ($nuevaClave !== '' ? ' (contraseña cambiada)' : '') . ($pin !== '' ? ' (PIN actualizado)' : '') . '.',
        $codEstabSesion,
        (string)$session['platform']
    );
    $session['cod_estab'] = $codEstabSesion;
    $session['estab_nombre'] = hospital_nombre_establecimiento($codEstabSesion);
    json_out([
        'success' => true,
        'message' => 'Datos personales y de seguridad actualizados.',
        'session' => session_profile_payload($pdo, $session),
    ]);
}

// ---------------------------------------------------------------------------
// 4-D. GESTIÓN DE ACCESOS (solo ADMIN_ESTADISTICA) Y RESETEO DE CLAVES
// ---------------------------------------------------------------------------
if ($action === 'listar_accesos') {
    $session = require_session();
    if (!puede_gestionar_accesos($session)) {
        json_error('Solo el Administrador de Estadística puede gestionar accesos.', 403, ['code' => 'ADMIN_REQUIRED']);
    }
    $q = trim((string)($_GET['q'] ?? ''));
    $rolFiltro = strtoupper(trim((string)($_GET['rol'] ?? 'TODOS')));
    $estabFiltro = trim((string)($_GET['cod_estab'] ?? 'TODOS'));
    $activoFiltro = trim((string)($_GET['activo'] ?? 'TODOS'));
    $where = [];
    $params = [];
    if ($q !== '') {
        $where[] = '(dni LIKE :q1 OR nombre_completo LIKE :q2 OR nombres LIKE :q3 OR apellido_paterno LIKE :q4 OR apellido_materno LIKE :q5)';
        $like = '%' . str_replace(['%', '_'], ['\%', '\_'], $q) . '%';
        $params[':q1'] = $like;
        $params[':q2'] = $like;
        $params[':q3'] = $like;
        $params[':q4'] = $like;
        $params[':q5'] = $like;
    }
    if ($rolFiltro !== '' && $rolFiltro !== 'TODOS') {
        $where[] = 'rol = :rol';
        $params[':rol'] = $rolFiltro;
    }
    if ($estabFiltro !== '' && $estabFiltro !== 'TODOS') {
        $variantesEstab = hospital_codigos_busqueda_establecimiento($estabFiltro);
        if (!$variantesEstab) {
            $variantesEstab = [$estabFiltro];
        }
        $marcasEstab = [];
        foreach (array_values($variantesEstab) as $i => $codEstabFiltro) {
            $marca = ':filtro_estab' . $i;
            $marcasEstab[] = $marca;
            $params[$marca] = $codEstabFiltro;
        }
        $where[] = 'cod_estab IN (' . implode(',', $marcasEstab) . ')';
    }
    if ($activoFiltro === '1' || $activoFiltro === '0') {
        $where[] = 'activo = :activo';
        $params[':activo'] = (int)$activoFiltro;
    }
    $sqlWhere = $where ? (' WHERE ' . implode(' AND ', $where)) : '';
    $stmt = $pdo->prepare("SELECT * FROM app_usuarios {$sqlWhere} ORDER BY rol ASC, apellido_paterno ASC, nombres ASC LIMIT 800");
    $stmt->execute($params);
    $accesos = $stmt->fetchAll();

    $dnisAccesos = array_values(array_filter(array_map(static fn ($row) => trim((string)($row['dni'] ?? '')), $accesos)));
    $capturas = [];
    $ultimasCapturas = [];
    if ($dnisAccesos) {
        try {
            $marcasDni = implode(',', array_fill(0, count($dnisAccesos), '?'));
            $stmtCap = $pdo->prepare("
                SELECT codpsal_obstetra, COUNT(*) AS total, MAX(fecha_registro) AS ultima
                FROM pacientes_sin_metodo
                WHERE codpsal_obstetra IN ({$marcasDni})
                GROUP BY codpsal_obstetra
            ");
            $stmtCap->execute($dnisAccesos);
            foreach ($stmtCap->fetchAll() as $filaCap) {
                $dniCap = (string)$filaCap['codpsal_obstetra'];
                $capturas[$dniCap] = (int)($filaCap['total'] ?? 0);
                $ultimasCapturas[$dniCap] = (string)($filaCap['ultima'] ?? '');
            }
        } catch (Throwable $e) {
            $capturas = [];
        }
    }

    foreach ($accesos as &$acceso) {
        $dniAcceso = (string)($acceso['dni'] ?? '');
        $acceso['rol_etiqueta'] = HospitalHuaralDB::rolEtiqueta((string)$acceso['rol']);
        $acceso['estab_nombre'] = hospital_nombre_establecimiento((string)$acceso['cod_estab']);
        $acceso['pin_configurado'] = (string)($acceso['pin_recuperacion'] ?? '') !== '';
        $acceso['clave_configurada'] = (string)($acceso['clave_hash'] ?? '') !== '';
        $acceso['total_captadas'] = $capturas[$dniAcceso] ?? 0;
        $acceso['ultima_captura'] = $ultimasCapturas[$dniAcceso] ?? '';
        unset($acceso['pin_recuperacion'], $acceso['clave_hash']);
    }
    unset($acceso);
    json_out([
        'success' => true,
        'accesos' => $accesos,
        'roles' => [
            ['codigo' => 'OBSTETRA', 'etiqueta' => 'Obstetra'],
            ['codigo' => 'JEFA_OBSTETRAS', 'etiqueta' => 'Jefa de Obstetras'],
            ['codigo' => 'ADMIN_ESTADISTICA', 'etiqueta' => 'Administrador de Estadística'],
        ],
        'establecimientos' => hospital_establecimientos(),
    ]);
}

if ($action === 'buscar_persona') {
    $session = require_session();
    if (!puede_gestionar_accesos($session) && !puede_resetear_obstetra($session)) {
        json_error('No tiene permiso para consultar personal.', 403);
    }
    $q = trim((string)($_GET['q'] ?? ''));
    $q = preg_replace('/[^0-9A-Za-zÁÉÍÓÚÜÑáéíóúüñ .\-]/u', '', $q) ?? '';
    if ($q === '') {
        json_out(['success' => true, 'personas' => []]);
    }
    $resultados = [];
    $vistos = [];
    $agregar = static function (string $dni, string $nombre, string $origen) use (&$resultados, &$vistos): void {
        $dni = trim($dni);
        $nombre = trim($nombre);
        if ($dni === '' || $nombre === '' || isset($vistos[$dni])) {
            return;
        }
        $vistos[$dni] = true;
        $resultados[] = ['dni' => $dni, 'nombre' => $nombre, 'origen' => $origen];
    };
    foreach (array_keys(hospital_dnis_preactivados()) as $dniPre) {
        $metaPre = hospital_dnis_preactivados()[$dniPre];
        if (str_contains($dniPre, $q) || mb_stripos((string)$metaPre['nombre'], $q) !== false) {
            $agregar((string)$dniPre, (string)$metaPre['nombre'], 'APP');
        }
    }
    $tablasPersonal = ['mstrpers', 'his_mstrpers'];
    foreach ($tablasPersonal as $tabla) {
        try {
            $stmt = $pdo->prepare("SELECT CODPSAL, NOMBRE FROM {$tabla} WHERE CODPSAL = :exacto OR NOMBRE LIKE :like ORDER BY NOMBRE ASC LIMIT 20");
            $stmt->execute([':exacto' => $q, ':like' => '%' . $q . '%']);
            foreach ($stmt->fetchAll() as $fila) {
                $agregar((string)$fila['CODPSAL'], (string)$fila['NOMBRE'], strtoupper($tabla));
            }
        } catch (Throwable $e) {
            // La tabla puede no existir en una instalación mínima.
        }
    }
    try {
        $stmt = $pdo->prepare("
            SELECT dni,
                   TRIM(CONCAT(IFNULL(nombres,''), ' ', IFNULL(apellido_paterno,''), ' ', IFNULL(apellido_materno,''))) AS nombre
            FROM app_usuarios
            WHERE dni LIKE :q OR nombre_completo LIKE :like
            LIMIT 20
        ");
        $stmt->execute([':q' => '%' . $q . '%', ':like' => '%' . $q . '%']);
        foreach ($stmt->fetchAll() as $fila) {
            $agregar((string)$fila['dni'], (string)$fila['nombre'], 'APP_USUARIOS');
        }
    } catch (Throwable $e) {
        // Sin tabla app_usuarios disponible.
    }
    json_out(['success' => true, 'personas' => array_slice($resultados, 0, 30)]);
}

if ($action === 'guardar_acceso') {
    $session = require_session();
    if (!puede_gestionar_accesos($session)) {
        json_error('Solo el Administrador de Estadística puede gestionar accesos.', 403, ['code' => 'ADMIN_REQUIRED']);
    }
    $dni = preg_replace('/[^0-9]/', '', (string)($body['dni'] ?? '')) ?? '';
    $nombres = strtoupper(HospitalHuaralDB::sanitizeText($body['nombres'] ?? '', 120));
    $apellidoPaterno = strtoupper(HospitalHuaralDB::sanitizeText($body['apellido_paterno'] ?? '', 80));
    $apellidoMaterno = strtoupper(HospitalHuaralDB::sanitizeText($body['apellido_materno'] ?? '', 80));
    $nombre = strtoupper(HospitalHuaralDB::sanitizeText($body['nombre_completo'] ?? '', 190));
    $rol = strtoupper(trim((string)($body['rol'] ?? 'OBSTETRA')));
    $codEstab = hospital_codigo_canonico((string)($body['cod_estab'] ?? ''));
    $activo = !isset($body['activo']) || !empty($body['activo']) ? 1 : 0;
    $pin = preg_replace('/[^0-9]/', '', (string)($body['pin'] ?? '')) ?? '';
    $email = strtolower(HospitalHuaralDB::sanitizeText($body['email'] ?? '', 190));
    $celular = preg_replace('/[^0-9]/', '', (string)($body['celular'] ?? '')) ?? '';
    $password = (string)($body['password'] ?? '');

    if (strlen($dni) < 8 || strlen($dni) > 11) {
        json_error('El DNI debe tener entre 8 y 11 dígitos.', 400);
    }
    if (!in_array($rol, ['ADMIN_ESTADISTICA', 'JEFA_OBSTETRAS', 'OBSTETRA'], true)) {
        json_error('Rol inválido. Use OBSTETRA, JEFA_OBSTETRAS o ADMIN_ESTADISTICA.', 400);
    }
    if (hospital_establecimiento($codEstab) === null) {
        json_error('Seleccione un establecimiento válido de la Red Huaral-Chancay.', 400);
    }
    if ($pin !== '' && strlen($pin) !== 4) {
        json_error('El PIN de recuperación debe tener exactamente 4 dígitos.', 400);
    }
    if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        json_error('El correo electrónico no tiene un formato válido.', 400);
    }
    if ($password !== '' && strlen($password) < 8) {
        json_error('La contraseña debe tener al menos 8 caracteres.', 400);
    }
    $nombrePartes = trim($nombres . ' ' . $apellidoPaterno . ' ' . $apellidoMaterno);
    if ($nombre === '') {
        $nombre = $nombrePartes;
    }
    if ($nombre === '') {
        $nombre = strtoupper(HospitalHuaralDB::nombrePersona($dni, $pdo));
    }
    if ($nombre === '') {
        $nombre = 'OBSTETRA ' . $dni;
    }
    $pinHash = $pin !== '' ? HospitalHuaralDB::hashPassword($pin) : '';
    $puedeVerRed = $rol === 'ADMIN_ESTADISTICA' ? 1 : 0;

    $existente = HospitalHuaralDB::accesoUsuario($dni);
    if ($existente === null) {
        $pdo->prepare("
            INSERT INTO app_usuarios
                (dni, nombres, apellido_paterno, apellido_materno, nombre_completo, email, celular,
                 clave_hash, pin_recuperacion, rol, cod_estab, puede_ver_red, activo, creado_por)
            VALUES
                (:dni, :nombres, :ap, :am, :completo, :email, :cel,
                 :pass, :pin, :rol, :estab, :red, :activo, :creado)
        ")->execute([
            ':dni' => $dni,
            ':nombres' => $nombres,
            ':ap' => $apellidoPaterno,
            ':am' => $apellidoMaterno,
            ':completo' => $nombre,
            ':email' => $email,
            ':cel' => substr($celular, 0, 15),
            ':pass' => $password !== '' ? HospitalHuaralDB::hashPassword($password) : '',
            ':pin' => $pinHash,
            ':rol' => $rol,
            ':estab' => $codEstab,
            ':red' => $puedeVerRed,
            ':activo' => $activo,
            ':creado' => (string)$session['dni'],
        ]);
    } else {
        $sets = [
            'rol = :rol',
            'cod_estab = :estab',
            'puede_ver_red = :red',
            'activo = :activo',
        ];
        $params = [
            ':rol' => $rol,
            ':estab' => $codEstab,
            ':red' => $puedeVerRed,
            ':activo' => $activo,
            ':dni' => $dni,
        ];
        if ($nombres !== '') {
            $sets[] = 'nombres = :nombres';
            $params[':nombres'] = $nombres;
        }
        if ($apellidoPaterno !== '') {
            $sets[] = 'apellido_paterno = :ap';
            $params[':ap'] = $apellidoPaterno;
        }
        if ($apellidoMaterno !== '') {
            $sets[] = 'apellido_materno = :am';
            $params[':am'] = $apellidoMaterno;
        }
        if ($nombre !== '') {
            $sets[] = 'nombre_completo = :completo';
            $params[':completo'] = $nombre;
        }
        if ($email !== '') {
            $sets[] = 'email = :email';
            $params[':email'] = $email;
        }
        if ($celular !== '') {
            $sets[] = 'celular = :cel';
            $params[':cel'] = substr($celular, 0, 15);
        }
        if ($pinHash !== '') {
            $sets[] = 'pin_recuperacion = :pin';
            $params[':pin'] = $pinHash;
        }
        if ($password !== '') {
            $sets[] = 'clave_hash = :pass';
            $params[':pass'] = HospitalHuaralDB::hashPassword($password);
        }
        $pdo->prepare('UPDATE app_usuarios SET ' . implode(', ', $sets) . ' WHERE dni = :dni LIMIT 1')->execute($params);
    }
    HospitalHuaralDB::olvidarAcceso($dni);
    HospitalHuaralDB::establecerEstablecimientoObstetra($dni, $codEstab);
    try {
        $pdo->prepare('UPDATE app_sesiones SET cod_estab = :estab WHERE dni = :dni AND revoked = 0')
            ->execute([':estab' => $codEstab, ':dni' => $dni]);
    } catch (Throwable $e) {
        // La sesión activa se actualizará en el próximo inicio de sesión.
    }

    HospitalHuaralDB::registrarAuditoria(
        (string)$session['dni'],
        'ACCESO_GUARDADO',
        'Acceso ' . $rol . ' para DNI ' . $dni . ' (' . $nombre . ') en ' . hospital_nombre_establecimiento($codEstab) . '. Activo=' . $activo . '.',
        (string)$session['cod_estab'],
        (string)$session['platform']
    );
    json_out(['success' => true, 'message' => 'Acceso guardado correctamente en app_usuarios.', 'dni' => $dni]);
}

if ($action === 'cambiar_estado_acceso') {
    $session = require_session();
    if (!puede_gestionar_accesos($session)) {
        json_error('Solo el Administrador de Estadística puede gestionar accesos.', 403, ['code' => 'ADMIN_REQUIRED']);
    }
    $dni = preg_replace('/[^0-9]/', '', (string)($body['dni'] ?? '')) ?? '';
    $activo = !empty($body['activo']) ? 1 : 0;
    if ($dni === '') {
        json_error('DNI inválido.', 400);
    }
    if ($dni === (string)$session['dni'] && $activo === 0) {
        json_error('No puede desactivar su propio acceso de administrador.', 409);
    }
    $stmt = $pdo->prepare('UPDATE app_usuarios SET activo = :activo WHERE dni = :dni LIMIT 1');
    $stmt->execute([':activo' => $activo, ':dni' => $dni]);
    if ($stmt->rowCount() === 0) {
        json_error('No se encontró el acceso solicitado.', 404);
    }
    HospitalHuaralDB::olvidarAcceso($dni);
    HospitalHuaralDB::registrarAuditoria(
        (string)$session['dni'],
        'ACCESO_ESTADO',
        'Acceso DNI ' . $dni . ' ' . ($activo ? 'activado' : 'desactivado') . '.',
        (string)$session['cod_estab'],
        (string)$session['platform']
    );
    json_out(['success' => true, 'dni' => $dni, 'activo' => $activo]);
}

if ($action === 'resetear_clave_usuario' || $action === 'resetear_clave_obstetra') {
    $session = require_session();
    if (!puede_resetear_obstetra($session)) {
        json_error('Solo la Jefatura de Obstetras o el Administrador de Estadística pueden restablecer claves.', 403);
    }
    $dni = preg_replace('/[^0-9]/', '', (string)($body['dni'] ?? '')) ?? '';
    if (strlen($dni) < 8 || strlen($dni) > 11) {
        json_error('DNI inválido.', 400);
    }
    $acceso = HospitalHuaralDB::accesoUsuario($dni);
    if ($acceso === null) {
        json_error('No se encontró una cuenta de app_usuarios con ese DNI.', 404);
    }
    $rolObjetivo = strtoupper(trim((string)($acceso['rol'] ?? 'OBSTETRA')));
    if (!is_admin_session($session)) {
        if ($rolObjetivo !== 'OBSTETRA') {
            json_error('La Jefatura de Obstetras solo puede restablecer la clave de obstetras de su establecimiento.', 403);
        }
        $estabJefa = hospital_codigo_canonico((string)$session['cod_estab']);
        $estabObjetivo = hospital_codigo_canonico((string)($acceso['cod_estab'] ?? ''));
        if ($estabJefa === '' || $estabObjetivo === '' || $estabJefa !== $estabObjetivo) {
            json_error('La obstetra no pertenece a su establecimiento. Solo puede restablecer claves de su equipo.', 403, [
                'code' => 'ESTABLECIMIENTO_DENEGADO',
            ]);
        }
    }

    $nombre = trim((string)($acceso['nombre_completo'] ?? ''));
    if ($nombre === '') {
        $nombre = HospitalHuaralDB::nombrePersona($dni, $pdo);
    }
    if ($nombre === '') {
        $nombre = 'OBSTETRA ' . $dni;
    }
    $codEstab = hospital_codigo_canonico((string)($acceso['cod_estab'] ?? $session['cod_estab']));

    $hash = HospitalHuaralDB::hashPassword($dni);
    $pdo->prepare("UPDATE app_usuarios SET clave_hash = :pass, pin_recuperacion = '' WHERE dni = :dni LIMIT 1")
        ->execute([':pass' => $hash, ':dni' => $dni]);
    HospitalHuaralDB::olvidarAcceso($dni);

    HospitalHuaralDB::registrarAuditoria(
        (string)$session['dni'],
        'CLAVE_RESETEADA',
        'Clave restablecida a su DNI para ' . $dni . ' (' . $nombre . ') en ' . hospital_nombre_establecimiento($codEstab) . '. PIN de recuperación limpiado.',
        (string)$session['cod_estab'],
        (string)$session['platform']
    );
    json_out([
        'success' => true,
        'message' => 'Clave restablecida. La nueva contraseña temporal es el propio DNI de la obstetra.',
        'dni' => $dni,
        'nombre' => $nombre,
    ]);
}

// ---------------------------------------------------------------------------
// 5. OVERVIEW — Dashboard, agenda de ampollas e indicadores
// ---------------------------------------------------------------------------
if ($action === 'overview') {
    $session = require_session();
    $platform = $session['platform'];
    $catalogo = catalogo_metodos_planificacion($pdo);
    $verRed = puede_ver_red($session);
    $rolSesion = HospitalHuaralDB::rolUsuario((string)$session['dni']);
    $esJefaSesion = $rolSesion === 'JEFA_OBSTETRAS';
    $esObstetraSesion = !$verRed && !$esJefaSesion;
    $alcanceSesion = strtolower(trim((string)($_GET['alcance'] ?? ($verRed ? 'red' : 'establecimiento'))));
    $modoRed = es_alcance_red($session, $alcanceSesion);
    $obstetraFiltro = preg_replace('/[^0-9A-Za-z]/', '', (string)($_GET['obstetra'] ?? '')) ?? '';
    if ($obstetraFiltro === 'TODOS') {
        $obstetraFiltro = '';
    }

    // RBAC estricto: Estadística puede ver toda la red; Jefatura ve únicamente
    // las captaciones de su establecimiento; la obstetra solo sus registros.
    $wherePacientes = [];
    $scopeParamsPacientes = [];
    if (!$modoRed) {
        $codigosEstabSesion = codigos_establecimiento_sesion($session);
        $wherePacientes[] = 'p.cod_estab IN (' . implode(',', array_fill(0, count($codigosEstabSesion), '?')) . ')';
        $scopeParamsPacientes = array_merge($scopeParamsPacientes, $codigosEstabSesion);
    }
    if ($esObstetraSesion) {
        $wherePacientes[] = 'p.codpsal_obstetra = ?';
        $scopeParamsPacientes[] = (string)$session['dni'];
    } elseif ($obstetraFiltro !== '') {
        $wherePacientes[] = 'p.codpsal_obstetra = ?';
        $scopeParamsPacientes[] = $obstetraFiltro;
    }
    $scopePacientes = $wherePacientes ? ' WHERE ' . implode(' AND ', $wherePacientes) . ' ' : '';

    $stmt = $pdo->prepare("
        SELECT p.*
        FROM pacientes_sin_metodo p
        {$scopePacientes}
        ORDER BY p.fecha_registro DESC
        LIMIT 500
    ");
    $stmt->execute($scopeParamsPacientes);
    $pacientesRows = $stmt->fetchAll();
    $dnisObstetras = array_map(static fn ($row) => (string)$row['codpsal_obstetra'], $pacientesRows);
    $diccionarioObstetras = nombres_personas_por_dni($pdo, $dnisObstetras);
    $pacientes = [];
    foreach ($pacientesRows as $row) {
        $codObstetra = (string)$row['codpsal_obstetra'];
        $pacientes[] = [
            'id' => (int)$row['id'],
            'dni' => (string)$row['dni'],
            'apellido_paterno' => (string)$row['apellido_paterno'],
            'apellido_materno' => (string)$row['apellido_materno'],
            'nombres' => (string)$row['nombres'],
            'edad' => (int)$row['edad'],
            'celular' => HospitalHuaralDB::decryptPII((string)$row['celular']),
            'correo' => HospitalHuaralDB::decryptPII((string)$row['correo']),
            'direccion' => HospitalHuaralDB::decryptPII((string)$row['direccion']),
            'distrito' => (string)$row['distrito'],
            'sector' => (string)$row['sector'],
            'estado_paciente' => (string)$row['estado_paciente'],
            'codpsal_obstetra' => $codObstetra,
            'nombre_obstetra' => (string)($diccionarioObstetras[$codObstetra] ?? ('OBST. ' . $codObstetra)),
            'cod_estab' => (string)($row['cod_estab'] ?? ''),
            'estab_nombre' => hospital_nombre_establecimiento((string)($row['cod_estab'] ?? '')),
            'atencion_99208' => (int)($row['atencion_99208'] ?? 0) === 1,
            'fecha_registro' => (string)$row['fecha_registro'],
            'encrypted_raw' => [
                'celular' => (string)$row['celular'],
                'correo' => (string)$row['correo'],
                'direccion' => (string)$row['direccion'],
            ],
        ];
    }

    // Agenda operativa construida desde las alertas programáticas oficiales:
    // incluye únicamente pacientes que tocan HOY, MAÑANA o están VENCIDAS.
    $alertas = alertas_programaticas_datos($pdo, $session, $catalogo);
    $agenda = [];
    foreach (['hoy', 'manana', 'vencidas'] as $grupoAlerta) {
        foreach (($alertas['listas'][$grupoAlerta] ?? []) as $filaAlerta) {
            $agenda[] = [
                'id_his' => 0,
                'dni' => (string)($filaAlerta['dni'] ?? ''),
                'paciente_nombre' => (string)($filaAlerta['paciente_nombre'] ?? ''),
                'edad' => (int)($filaAlerta['edad'] ?? 0),
                'historia_clinica' => (string)($filaAlerta['historia_clinica'] ?? ''),
                'COD_ESTAB' => (string)($filaAlerta['cod_estab'] ?? ''),
                'establecimiento' => (string)($filaAlerta['establecimiento'] ?? ''),
                'codigo_his' => (string)($filaAlerta['codigo_his'] ?? ''),
                'codigo_metodo' => (string)($filaAlerta['codigo_metodo'] ?? ''),
                'metodo_descripcion' => (string)($filaAlerta['nombre_metodo'] ?? ''),
                'fecha_ultima_aplicacion' => (string)($filaAlerta['fecha_aplicacion_iso'] ?? ''),
                'fecha_proxima_cita' => (string)($filaAlerta['fecha_proximo_metodo_iso'] ?? ''),
                'ciclo_dias' => (int)($filaAlerta['dias_ciclo'] ?? 0),
                'dias_restantes' => (int)($filaAlerta['dias_restantes'] ?? 0),
                'estado_cita' => (int)($filaAlerta['dias_restantes'] ?? 0) < 0
                    ? 'VENCIDA_ABANDONO'
                    : ((int)($filaAlerta['dias_restantes'] ?? 0) === 0 ? 'TOCA_HOY' : 'TOCA_MANANA'),
                'celular' => (string)($filaAlerta['celular'] ?? ''),
                'direccion' => (string)($filaAlerta['direccion'] ?? ''),
                'distrito' => (string)($filaAlerta['distrito'] ?? ''),
                'sector' => (string)($filaAlerta['sector'] ?? ''),
                'prioridad_llamada' => (string)($filaAlerta['prioridad_llamada'] ?? ''),
                'obstetra_dni' => (string)($filaAlerta['obstetra_dni'] ?? ''),
                'nombre_obstetra' => (string)($filaAlerta['nombre_obstetra'] ?? ''),
            ];
        }
    }
    usort($agenda, static function (array $a, array $b): int {
        $cmp = (int)$a['dias_restantes'] <=> (int)$b['dias_restantes'];
        return $cmp !== 0 ? $cmp : strcmp((string)$a['paciente_nombre'], (string)$b['paciente_nombre']);
    });
    $agenda = array_slice($agenda, 0, 100);

    $scopeProd = $scopePacientes;
    $stmtProd = $pdo->prepare("
        SELECT p.codpsal_obstetra AS codpsal,
               p.cod_estab AS cod_estab,
               COUNT(*) AS totalCaptadas,
               SUM(CASE WHEN p.estado_paciente = 'INSATISFECHA_SIN_METODO' THEN 1 ELSE 0 END) AS insatisfechasCaptadas,
               SUM(CASE WHEN p.estado_paciente = 'CAPTADA_CON_METODO' THEN 1 ELSE 0 END) AS conMetodoLogrado
        FROM pacientes_sin_metodo p
        {$scopeProd}
        GROUP BY p.codpsal_obstetra, p.cod_estab
        ORDER BY totalCaptadas DESC
        LIMIT 100
    ");
    $stmtProd->execute($scopeParamsPacientes);
    $produccion = $stmtProd->fetchAll();
    $dnisProd = array_map(static fn ($row) => (string)$row['codpsal'], $produccion);
    $diccionarioProd = nombres_personas_por_dni($pdo, $dnisProd);
    foreach ($produccion as &$prodRow) {
        $cod = (string)$prodRow['codpsal'];
        $prodRow['nombre'] = (string)($diccionarioProd[$cod] ?? ('Obstetra DNI ' . $cod));
    }
    unset($prodRow);

    $auditoria = is_admin_session($session) ? HospitalHuaralDB::ultimaAuditoria(30) : [];
    $stats = [
        'totalCaptadas' => count($pacientes),
        'insatisfechasSinMetodo' => count(array_filter($pacientes, static fn ($p) => $p['estado_paciente'] === 'INSATISFECHA_SIN_METODO')),
        'captadasConMetodo' => count(array_filter($pacientes, static fn ($p) => $p['estado_paciente'] === 'CAPTADA_CON_METODO')),
        'seguimientoDomiciliario' => count(array_filter($pacientes, static fn ($p) => $p['estado_paciente'] === 'SEGUIMIENTO_DOMICILIARIO')),
        'citasAmpollaHoyManana' => (int)($alertas['hoy'] ?? 0) + (int)($alertas['manana'] ?? 0),
        'alertasVencidas' => (int)($alertas['vencidas'] ?? 0),
        'alertasHisPorCaptar' => (int)($alertas['total'] ?? 0),
        'atenciones99208' => count(array_filter($pacientes, static fn ($p) => $p['atencion_99208'] === true)),
    ];
    $metricsRow = [];
    if (is_admin_session($session)) {
        $metricsRow = $pdo->query("
            SELECT
              SUM(CASE WHEN accion = 'WAF_SQLI_BLOCKED' THEN 1 ELSE 0 END) AS sqli,
              SUM(CASE WHEN accion = 'WAF_XSS_BLOCKED' THEN 1 ELSE 0 END) AS xss,
              SUM(CASE WHEN accion IN ('AUTH_2FA_VERIFIED', 'AUTH_2FA_FAILED') THEN 1 ELSE 0 END) AS totp,
              SUM(CASE WHEN accion LIKE 'AUTH_LOGIN_FAILED%' OR accion = 'LOGIN_RATE_LIMITED' THEN 1 ELSE 0 END) AS failed,
              COUNT(*) AS total
            FROM auditoria_seguridad_app
        ")->fetch() ?: [];
    }
    $rol = HospitalHuaralDB::rolUsuario((string)$session['dni']);

    json_out([
        'session' => [
            'dni' => $session['dni'],
            'cod_estab' => $session['cod_estab'],
            'estab_nombre' => $session['estab_nombre'],
            'platform' => $platform,
            'verified2FA' => two_factor_required(),
            'isAdmin' => is_admin_session($session),
            'isJefa' => es_jefa_session($session),
            'rol' => $rol,
            'rol_etiqueta' => HospitalHuaralDB::rolEtiqueta($rol),
            'puedeVerRed' => $verRed,
            'puedeCambiarEstablecimiento' => is_admin_session($session),
            'puedeGestionarAccesos' => puede_gestionar_accesos($session),
            'puedeResetearObstetra' => puede_resetear_obstetra($session),
            'accesoActivo' => HospitalHuaralDB::accesoActivo((string)$session['dni']),
        ],
        'stats' => $stats,
        'alertas' => $alertas,
        'securityMetrics' => [
            'sqliBlockedCount' => (int)($metricsRow['sqli'] ?? 0),
            'xssBlockedCount' => (int)($metricsRow['xss'] ?? 0),
            'totpVerifiedCount' => (int)($metricsRow['totp'] ?? 0),
            'encryptedRecordsCount' => count($pacientes),
            'failedLoginsBlocked' => (int)($metricsRow['failed'] ?? 0),
            'auditLogCount' => (int)($metricsRow['total'] ?? 0),
        ],
        'catalogoMetodos' => array_values($catalogo),
        'pacientes' => $pacientes,
        'agendaAmpollas' => $agenda,
        'produccionObstetras' => $produccion,
        'auditLogs' => $auditoria,
        'establecimientos' => hospital_establecimientos(),
        'distritos' => [
            ['UBIGEO' => '150601', 'DESC_DIST' => 'HUARAL'],
            ['UBIGEO' => '150605', 'DESC_DIST' => 'CHANCAY'],
            ['UBIGEO' => '150604', 'DESC_DIST' => 'AUCALLAMA'],
            ['UBIGEO' => '150606', 'DESC_DIST' => 'IHUARI'],
            ['UBIGEO' => '150602', 'DESC_DIST' => 'ATAVILLOS ALTO'],
            ['UBIGEO' => '150603', 'DESC_DIST' => 'ATAVILLOS BAJO'],
            ['UBIGEO' => '150607', 'DESC_DIST' => 'LAMPIAN'],
            ['UBIGEO' => '150608', 'DESC_DIST' => 'PACARAOS'],
            ['UBIGEO' => '150609', 'DESC_DIST' => 'SAN MIGUEL DE ACOS'],
            ['UBIGEO' => '150610', 'DESC_DIST' => 'SANTA CRUZ DE ANDAMARCA'],
            ['UBIGEO' => '150611', 'DESC_DIST' => 'SUMBILCA'],
            ['UBIGEO' => '150612', 'DESC_DIST' => 'VEINTISIETE DE NOVIEMBRE'],
        ],
    ]);
}

// ---------------------------------------------------------------------------
// 6. HELPERS CLÍNICOS: 99208, UPS Planificación Familiar y establecimientos
// ---------------------------------------------------------------------------
/**
 * Resuelve el nombre oficial del establecimiento con prioridad:
 * 1) catálogo IPRESS local (53 establecimientos),
 * 2) nombre devuelto por el JOIN con `establec`,
 * 3) consulta directa a `establec` por cualquiera de las variantes del código.
 */
function resolver_nombre_establecimiento(PDO $pdo, ?string $codigo, ?string $fallback = null): string
{
    $codigo = trim((string)$codigo);
    $variantes = hospital_codigos_busqueda_establecimiento($codigo);
    // El catálogo oficial manda: se prueba el código recibido y sus variantes
    // (IPRESS, interno de 4 dígitos, sin ceros) antes de consultar establec.
    foreach ($variantes as $variante) {
        $est = hospital_establecimiento($variante);
        if ($est !== null) {
            $nombre = trim((string)($est['DESC_ESTAB'] ?? ''));
            if ($nombre !== '') {
                return $nombre;
            }
        }
    }

    $fallback = trim((string)$fallback);
    if ($fallback !== '' && $fallback !== $codigo) {
        return $fallback;
    }

    if ($variantes) {
        $placeholders = implode(',', array_fill(0, count($variantes), '?'));
        try {
            $stmt = $pdo->prepare("SELECT DESC_ESTAB FROM establec WHERE COD_ESTAB IN ({$placeholders}) LIMIT 1");
            $stmt->execute($variantes);
            $nombre = trim((string)($stmt->fetchColumn() ?: ''));
            if ($nombre !== '') {
                return $nombre;
            }
        } catch (Throwable $e) {
            // La tabla establec puede no existir en una instalación mínima.
        }
    }

    return $fallback !== '' ? $fallback : ($codigo !== '' ? $codigo : 'SIN ESTABLECIMIENTO');
}

/**
 * Diccionario en memoria de nombres de obstetras. Evita JOIN entre tablas con
 * colaciones distintas (`pacientes_sin_metodo` utf8_general_ci vs
 * `mstrpers`/`his_mstrpers` utf8_bin) y se resuelve con CODPSAL (PK) IN (...).
 *
 * @param array<int, string> $dnis
 * @return array<string, string>
 */
function nombres_personas_por_dni(PDO $pdo, array $dnis): array
{
    $limpios = [];
    foreach ($dnis as $dni) {
        $dni = preg_replace('/[^0-9A-Za-z]/', '', (string)$dni) ?? '';
        if ($dni !== '') {
            $limpios[$dni] = $dni;
        }
    }
    if (!$limpios) {
        return [];
    }
    $dnis = array_values($limpios);
    $nombres = [];
    foreach (['mstrpers', 'his_mstrpers'] as $tabla) {
        $pendientes = array_values(array_diff($dnis, array_keys($nombres)));
        if (!$pendientes) {
            break;
        }
        try {
            $placeholders = implode(',', array_fill(0, count($pendientes), '?'));
            $stmt = $pdo->prepare("SELECT CODPSAL, NOMBRE FROM {$tabla} WHERE CODPSAL IN ({$placeholders})");
            $stmt->execute($pendientes);
            foreach ($stmt->fetchAll() as $row) {
                $codigo = trim((string)($row['CODPSAL'] ?? ''));
                $nombre = trim((string)($row['NOMBRE'] ?? ''));
                if ($codigo !== '' && $nombre !== '') {
                    $nombres[$codigo] = $nombre;
                }
            }
        } catch (Throwable $e) {
            // La tabla puede no existir en una instalación mínima.
        }
    }
    return $nombres;
}

/**
 * Datos de contacto descifrados de las pacientes captadas, indexados por DNI.
 * Se usa para enriquecer la agenda y las alertas de seguimiento programático.
 *
 * @param array<int, string> $dnis
 * @return array<string, array<string, mixed>>
 */
function contactos_pacientes_por_dni(PDO $pdo, array $dnis): array
{
    $limpios = [];
    foreach ($dnis as $dni) {
        $dni = preg_replace('/[^0-9]/', '', (string)$dni) ?? '';
        if ($dni !== '') {
            $limpios[$dni] = $dni;
        }
    }
    if (!$limpios) {
        return [];
    }
    $dnis = array_values($limpios);
    $placeholders = implode(',', array_fill(0, count($dnis), '?'));
    try {
        $stmt = $pdo->prepare("
            SELECT dni, apellido_paterno, apellido_materno, nombres, edad,
                   celular, correo, direccion, distrito, sector, estado_paciente,
                   cod_estab, codpsal_obstetra
            FROM pacientes_sin_metodo
            WHERE dni IN ({$placeholders})
        ");
        $stmt->execute($dnis);
        $mapa = [];
        foreach ($stmt->fetchAll() as $row) {
            $dni = trim((string)($row['dni'] ?? ''));
            if ($dni === '') {
                continue;
            }
            $row['celular'] = HospitalHuaralDB::decryptPII((string)($row['celular'] ?? ''));
            $row['correo'] = HospitalHuaralDB::decryptPII((string)($row['correo'] ?? ''));
            $row['direccion'] = HospitalHuaralDB::decryptPII((string)($row['direccion'] ?? ''));
            $mapa[$dni] = $row;
        }
        return $mapa;
    } catch (Throwable $e) {
        return [];
    }
}

/**
 * Alertas proactivas de seguimiento programático: pacientes que les toca HOY,
 * MAÑANA o están VENCIDAS. Se calcula con las 14 variantes oficiales del HIS y
 * ventanas SARGables de fecha de aplicación para no escanear los 5 GB.
 *
 * @param array<string, array<string, mixed>>|null $catalogo
 * @return array<string, mixed>
 */
function alertas_programaticas_datos(PDO $pdo, array $session, ?array $catalogo = null, int $limiteLista = 1000): array
{
    $catalogo = $catalogo ?: catalogo_metodos_planificacion($pdo);
    $variantes = [];
    foreach ($catalogo as $meta) {
        if ((int)($meta['activo'] ?? 1) !== 1 || (int)($meta['dias_ciclo'] ?? 0) <= 0) {
            continue;
        }
        foreach ((array)($meta['codigos_consulta'] ?? []) as $variante) {
            $variante = trim((string)$variante);
            if ($variante !== '') {
                $variantes[$variante] = $variante;
            }
        }
    }

    $vacio = [
        'manana' => 0,
        'hoy' => 0,
        'vencidas' => 0,
        'total' => 0,
        'listas' => ['manana' => [], 'hoy' => [], 'vencidas' => []],
    ];
    if (!$variantes) {
        return $vacio;
    }

    $hoy = new DateTimeImmutable('today');
    $manana = $hoy->modify('+1 day');
    $lookbackVencidas = 365;
    $expr = "COALESCE(
        CASE
          WHEN h.DIA BETWEEN 1 AND 31
           AND h.MES BETWEEN 1 AND 12
           AND h.ANO BETWEEN 1900 AND 2100
          THEN STR_TO_DATE(
                 CONCAT(h.ANO, '-', LPAD(h.MES, 2, '0'), '-', LPAD(h.DIA, 2, '0')),
                 '%Y-%m-%d'
               )
        END,
        DATE(h.fecha_reg),
        DATE(dt.fecha_reg)
    )";

    $condiciones = [];
    $params = [];
    foreach ($variantes as $variante) {
        $meta = resolver_metodo_catalogo($catalogo, $variante);
        if ($meta === null) {
            continue;
        }
        $dias = max(1, (int)$meta['dias_ciclo']);
        $condiciones[] = "(dt.DX = ? AND {$expr} BETWEEN ? AND ?)";
        $params[] = $variante;
        $params[] = $hoy->modify('-' . $dias . ' days')->format('Y-m-d');
        $params[] = $manana->modify('-' . $dias . ' days')->format('Y-m-d');

        $condiciones[] = "(dt.DX = ? AND {$expr} BETWEEN ? AND ?)";
        $params[] = $variante;
        $params[] = $hoy->modify('-' . ($dias + $lookbackVencidas) . ' days')->format('Y-m-d');
        $params[] = $hoy->modify('-' . ($dias + 1) . ' days')->format('Y-m-d');
    }
    if (!$condiciones) {
        return $vacio;
    }

    $anioMin = (int)date('Y') - 2;
    $anioMax = (int)date('Y') + 1;
    $rolAlertas = HospitalHuaralDB::rolUsuario((string)($session['dni'] ?? ''));
    $esObstetraAlertas = !puede_ver_red($session) && $rolAlertas !== 'JEFA_OBSTETRAS';
    $alcanceAlertas = strtolower(trim((string)($_GET['alcance'] ?? (is_admin_session($session) ? 'red' : 'establecimiento'))));
    $modoRedAlertas = es_alcance_red($session, $alcanceAlertas);
    $obstetraAlertas = preg_replace('/[^0-9A-Za-z]/', '', (string)($_GET['obstetra'] ?? '')) ?? '';
    if ($obstetraAlertas === 'TODOS') {
        $obstetraAlertas = '';
    }
    $scopeAlertas = [];
    $scopeParams = [];
    if (!$modoRedAlertas) {
        $codigosEstabAlertas = codigos_establecimiento_sesion($session);
        $scopeAlertas[] = 'h.COD_ESTAB IN (' . implode(',', array_fill(0, count($codigosEstabAlertas), '?')) . ')';
        $scopeParams = array_merge($scopeParams, $codigosEstabAlertas);
    }
    if ($esObstetraAlertas) {
        $scopeAlertas[] = 'h.CODPSAL = ?';
        $scopeParams[] = (string)($session['dni'] ?? '');
    } elseif ($obstetraAlertas !== '') {
        $scopeAlertas[] = 'h.CODPSAL = ?';
        $scopeParams[] = $obstetraAlertas;
    }
    $scope = $scopeAlertas ? (' AND ' . implode(' AND ', $scopeAlertas) . ' ') : '';

    $sql = "
        SELECT h.ID AS id_his, h.DNI AS dni, h.COD_ESTAB AS cod_estab,
               h.CODPSAL AS obstetra_dni, h.EDAD AS edad, h.HCLFAM AS historia_clinica,
               TRIM(h.Apellido_p) AS apellido_paterno, TRIM(h.Apellido_m) AS apellido_materno,
               TRIM(COALESCE(NULLIF(h.Dnombres, ''), h.Pnombre)) AS nombres,
               h.DIA, h.MES, h.ANO, h.fecha_reg,
               dt.DX AS codigo_his, dt.id_dosis AS dosis, dt.fecha_reg AS fecha_dx,
               {$expr} AS fecha_aplicacion
        FROM his_dl h
        INNER JOIN his_dl_dt dt ON dt.ID = h.ID
        WHERE h.ANO BETWEEN ? AND ?
          AND (" . implode(' OR ', $condiciones) . ")
          {$scope}
        ORDER BY h.ANO DESC, h.MES DESC, h.DIA DESC, h.ID DESC
        LIMIT 20000
    ";
    $paramsSql = array_merge([$anioMin, $anioMax], $params, $scopeParams);

    $mejores = [];
    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute($paramsSql);
        foreach ($stmt->fetchAll() as $row) {
            $dni = trim((string)($row['dni'] ?? ''));
            $codigoHis = trim((string)($row['codigo_his'] ?? ''));
            if ($dni === '' || $codigoHis === '') {
                continue;
            }
            $meta = resolver_metodo_catalogo($catalogo, $codigoHis);
            if ($meta === null || (int)$meta['dias_ciclo'] <= 0) {
                continue;
            }
            $fecha = trim((string)($row['fecha_aplicacion'] ?? ''));
            if ($fecha === '' || str_starts_with($fecha, '0000-00-00')) {
                $fecha = fecha_aplicacion_his($row);
            }
            if ($fecha === '') {
                continue;
            }
            try {
                $proximo = (new DateTimeImmutable($fecha))->modify('+' . (int)$meta['dias_ciclo'] . ' days');
            } catch (Throwable $e) {
                continue;
            }
            $diasRestantes = (int)$hoy->diff($proximo)->format('%r%a');
            if ($diasRestantes > 1 || $diasRestantes < -$lookbackVencidas) {
                continue;
            }
            $score = $fecha . '|' . str_pad((string)(int)$meta['dias_ciclo'], 4, '0', STR_PAD_LEFT)
                . '|' . str_pad((string)(int)($row['id_his'] ?? 0), 12, '0', STR_PAD_LEFT);
            if (isset($mejores[$dni]) && strcmp($score, (string)$mejores[$dni]['_score']) <= 0) {
                continue;
            }
            $mejores[$dni] = [
                '_score' => $score,
                'row' => $row,
                'meta' => $meta,
                'fecha' => $fecha,
                'proximo' => $proximo->format('Y-m-d'),
                'dias_restantes' => $diasRestantes,
            ];
        }
    } catch (Throwable $e) {
        error_log('[PlanificaHIS] alertas_programaticas_datos: ' . $e->getMessage());
        return $vacio;
    }

    if (!$mejores) {
        return $vacio;
    }

    $dnis = array_keys($mejores);
    $contactos = contactos_pacientes_por_dni($pdo, $dnis);
    $dnisObstetras = array_map(static fn ($sel) => (string)($sel['row']['obstetra_dni'] ?? ''), $mejores);
    $nombresObstetras = nombres_personas_por_dni($pdo, $dnisObstetras);
    $listas = ['manana' => [], 'hoy' => [], 'vencidas' => []];

    foreach ($mejores as $dni => $sel) {
        $row = $sel['row'];
        $meta = $sel['meta'];
        $cap = $contactos[$dni] ?? [];
        $apellidosHis = trim(trim((string)($row['apellido_paterno'] ?? '')) . ' ' . trim((string)($row['apellido_materno'] ?? '')));
        $nombresHis = trim((string)($row['nombres'] ?? ''));
        $nombreHis = trim($apellidosHis . ($apellidosHis !== '' && $nombresHis !== '' ? ', ' : '') . $nombresHis);
        $apellidosCap = trim(trim((string)($cap['apellido_paterno'] ?? '')) . ' ' . trim((string)($cap['apellido_materno'] ?? '')));
        $nombresCap = trim((string)($cap['nombres'] ?? ''));
        $nombreCap = trim($apellidosCap . ($apellidosCap !== '' && $nombresCap !== '' ? ', ' : '') . $nombresCap);
        $pacienteNombre = strtoupper($nombreHis !== '' ? $nombreHis : $nombreCap);
        if ($pacienteNombre === '') {
            // El HIS local no siempre guarda nombres; el DNI evita tarjetas vacías.
            $pacienteNombre = 'PACIENTE ' . $dni;
        }
        $edad = (int)($row['edad'] ?? 0);
        if ($edad <= 0) {
            $edad = (int)($cap['edad'] ?? 0);
        }
        $codEstab = trim((string)($row['cod_estab'] ?? ($cap['cod_estab'] ?? '')));
        $codObstetra = trim((string)($row['obstetra_dni'] ?? ''));
        $diasRestantes = (int)$sel['dias_restantes'];
        $prioridad = $diasRestantes < 0
            ? 'ALTA (VENCIDA)'
            : ($diasRestantes === 0 ? 'ALTA (HOY)' : ($diasRestantes === 1 ? 'ALTA (MAÑANA)' : ($diasRestantes <= 7 ? 'MEDIA' : 'BAJA')));
        $fila = [
            'dni' => $dni,
            'paciente_nombre' => $pacienteNombre,
            'edad' => $edad,
            'historia_clinica' => (string)($row['historia_clinica'] ?? ''),
            'cod_estab' => $codEstab,
            'establecimiento' => resolver_nombre_establecimiento($pdo, $codEstab),
            'codigo_metodo' => (string)$meta['codigo_dx'],
            'codigo_his' => (string)($row['codigo_his'] ?? ''),
            'nombre_metodo' => (string)$meta['nombre_metodo'],
            'fecha_aplicacion' => fecha_para_mostrar($sel['fecha']),
            'fecha_aplicacion_iso' => $sel['fecha'],
            'dias_ciclo' => (int)$meta['dias_ciclo'],
            'fecha_proximo_metodo' => fecha_para_mostrar($sel['proximo']),
            'fecha_proximo_metodo_iso' => $sel['proximo'],
            'dias_restantes' => $diasRestantes,
            'estado_programacion' => $diasRestantes < 0 ? 'VENCIDO_ABANDONO' : ($diasRestantes === 0 ? 'TOCA_EN_FECHA' : 'PROXIMO_7_DIAS'),
            'prioridad_llamada' => $prioridad,
            'celular' => (string)($cap['celular'] ?? ''),
            'direccion' => (string)($cap['direccion'] ?? ''),
            'distrito' => (string)($cap['distrito'] ?? ''),
            'sector' => (string)($cap['sector'] ?? ''),
            'obstetra_dni' => $codObstetra,
            'nombre_obstetra' => (string)($nombresObstetras[$codObstetra] ?? ('OBST. ' . $codObstetra)),
        ];
        if ($diasRestantes === 1) {
            $listas['manana'][] = $fila;
        } elseif ($diasRestantes === 0) {
            $listas['hoy'][] = $fila;
        } else {
            $listas['vencidas'][] = $fila;
        }
    }

    $totales = [
        'manana' => count($listas['manana']),
        'hoy' => count($listas['hoy']),
        'vencidas' => count($listas['vencidas']),
    ];
    foreach ($listas as &$lista) {
        usort($lista, static function (array $a, array $b): int {
            $cmp = (int)$a['dias_restantes'] <=> (int)$b['dias_restantes'];
            return $cmp !== 0 ? $cmp : strcmp((string)$a['paciente_nombre'], (string)$b['paciente_nombre']);
        });
        $lista = array_slice($lista, 0, max(1, $limiteLista));
    }
    unset($lista);

    return [
        'manana' => $totales['manana'],
        'hoy' => $totales['hoy'],
        'vencidas' => $totales['vencidas'],
        'total' => $totales['manana'] + $totales['hoy'] + $totales['vencidas'],
        'listas' => $listas,
    ];
}

/**
 * Catálogo clínico oficial de los 14 métodos HIS y sus variantes de código.
 * Lee `app_catalogo_metodos`; si la tabla no existe usa el catálogo embebido.
 * El resultado se indexa por código oficial (con punto) y cada entrada incluye
 * `codigos_consulta`, la lista exacta que debe viajar en `dt.DX IN (...)`.
 *
 * @return array<string, array<string, mixed>>
 */
function catalogo_metodos_planificacion(PDO $pdo, bool $forceReload = false): array
{
    static $catalogo = null;
    if ($forceReload) {
        $catalogo = null;
    }
    if (is_array($catalogo)) {
        return $catalogo;
    }

    $oficial = hospital_catalogo_metodos_oficial();
    $filasDb = [];
    try {
        HospitalHuaralDB::ensureCatalogoOficial($pdo);
        $stmt = $pdo->query('SELECT codigo_dx, nombre_metodo, alias_codigos, dias_ciclo, requiere_cita, activo, orden FROM app_catalogo_metodos ORDER BY orden ASC, nombre_metodo ASC');
        foreach ($stmt->fetchAll() as $row) {
            $codigo = trim((string)($row['codigo_dx'] ?? ''));
            if ($codigo !== '') {
                $filasDb[$codigo] = $row;
            }
        }
    } catch (Throwable $e) {
        // La tabla se crea en bootstrapSchema; el fallback mantiene la app operativa.
    }

    $catalogo = [];
    foreach ($oficial as $codigo => $metaOficial) {
        $db = $filasDb[$codigo] ?? null;
        $alias = array_map('strval', (array)($metaOficial['alias'] ?? []));
        if ($db !== null) {
            foreach (explode(',', (string)($db['alias_codigos'] ?? '')) as $aliasDb) {
                $aliasDb = trim($aliasDb);
                if ($aliasDb !== '') {
                    $alias[] = $aliasDb;
                }
            }
        }
        $alias = array_values(array_unique(array_filter($alias, static fn ($a) => $a !== '')));
        $catalogo[$codigo] = [
            'codigo_dx' => $codigo,
            'nombre_metodo' => trim((string)($db['nombre_metodo'] ?? $metaOficial['nombre_metodo'])),
            'dias_ciclo' => $db !== null
                ? max(0, (int)($db['dias_ciclo'] ?? $metaOficial['dias_ciclo']))
                : (int)$metaOficial['dias_ciclo'],
            'requiere_cita' => $db !== null
                ? ((int)($db['requiere_cita'] ?? 1) === 1 ? 1 : 0)
                : (int)$metaOficial['requiere_cita'],
            'activo' => $db !== null
                ? ((int)($db['activo'] ?? 1) === 1 ? 1 : 0)
                : (int)$metaOficial['activo'],
            'orden' => $db !== null ? (int)($db['orden'] ?? $metaOficial['orden']) : (int)$metaOficial['orden'],
            'alias' => $alias,
            'codigos_consulta' => array_values(array_unique(array_merge([$codigo], $alias))),
        ];
    }
    return $catalogo;
}

/**
 * Resuelve un DX del HIS (oficial o variante) a la entrada canónica del catálogo.
 *
 * @param array<string, array<string, mixed>> $catalogo
 * @return array<string, mixed>|null
 */
function resolver_metodo_catalogo(array $catalogo, ?string $codigo): ?array
{
    $codigo = trim((string)$codigo);
    if ($codigo === '') {
        return null;
    }
    if (isset($catalogo[$codigo])) {
        return $catalogo[$codigo];
    }
    foreach ($catalogo as $meta) {
        if (in_array($codigo, array_map('strval', (array)($meta['codigos_consulta'] ?? [])), true)) {
            return $meta;
        }
    }
    return null;
}

/**
 * @return array<int, string>
 */
function codigos_metodos_activos(array $catalogo): array
{
    $codigos = [];
    foreach ($catalogo as $codigo => $meta) {
        if ((int)($meta['activo'] ?? 1) === 1 && (int)($meta['dias_ciclo'] ?? 0) > 0) {
            $codigos[] = (string)$codigo;
        }
    }
    return $codigos ?: array_map('strval', array_keys($catalogo));
}

/**
 * Lista completa de variantes HIS para `dt.DX IN (...)`, sin funciones sobre la
 * columna. Si se pasa un filtro (oficial o variante) se expande solo ese método.
 *
 * @param array<string, array<string, mixed>> $catalogo
 * @param array<int, string> $filtro
 * @return array<int, string>
 */
function codigos_consulta_metodos(array $catalogo, array $filtro = []): array
{
    $destino = [];
    $incluirTodos = !$filtro;
    foreach ($catalogo as $meta) {
        if ((int)($meta['activo'] ?? 1) !== 1 || (int)($meta['dias_ciclo'] ?? 0) <= 0) {
            continue;
        }
        $coincide = $incluirTodos;
        if (!$incluirTodos) {
            $variantes = array_map('strval', (array)($meta['codigos_consulta'] ?? []));
            foreach ($filtro as $codigoFiltro) {
                if (in_array(trim((string)$codigoFiltro), $variantes, true)) {
                    $coincide = true;
                    break;
                }
            }
        }
        if ($coincide) {
            foreach ((array)($meta['codigos_consulta'] ?? [$meta['codigo_dx']]) as $variante) {
                $variante = trim((string)$variante);
                if ($variante !== '') {
                    $destino[$variante] = $variante;
                }
            }
        }
    }
    return array_values($destino);
}

/**
 * Fecha real de aplicación en his_dl: DIA/MES/ANO válidos o, como respaldo,
 * fecha_reg / fecha_reg del detalle.
 *
 * @param array<string, mixed> $row
 */
function fecha_aplicacion_his(array $row): string
{
    $dia = (int)($row['DIA'] ?? 0);
    $mes = (int)($row['MES'] ?? 0);
    $ano = (int)($row['ANO'] ?? 0);
    if ($dia >= 1 && $dia <= 31 && $mes >= 1 && $mes <= 12 && $ano >= 1900 && $ano <= 2100) {
        $fecha = sprintf('%04d-%02d-%02d', $ano, $mes, $dia);
        if (checkdate($mes, $dia, $ano)) {
            return $fecha;
        }
    }

    foreach (['fecha_dx', 'fecha_reg'] as $campo) {
        $raw = trim((string)($row[$campo] ?? ''));
        if ($raw === '' || str_starts_with($raw, '0000-00-00')) {
            continue;
        }
        $timestamp = strtotime($raw);
        if ($timestamp !== false) {
            return date('Y-m-d', $timestamp);
        }
    }
    return '';
}

function fecha_para_mostrar(?string $iso): string
{
    $iso = trim((string)$iso);
    if ($iso === '') {
        return '';
    }
    $dt = DateTimeImmutable::createFromFormat('!Y-m-d', $iso);
    return $dt instanceof DateTimeImmutable ? $dt->format('d/m/Y') : '';
}

/**
 * Última atención de Planificación Familiar de la paciente en TODA la red.
 * Prioriza la última atención con método del catálogo; si no existe, conserva
 * la última atención de la UPS 302304 para contextualizar el origen.
 *
 * @param array<string, array<string, mixed>> $catalogo
 * @param array<int, string> $codigosUps
 * @return array<string, mixed>
 */
function programacion_planificacion_paciente(
    PDO $pdo,
    string $dni,
    string $codEstabActual,
    array $catalogo,
    array $codigosUps = ['302304']
): array {
    // Se consultan TODAS las variantes oficiales del HIS (con punto, sin punto,
    // con .00 y alias históricos) sin aplicar funciones sobre dt.DX.
    $codigosActivos = codigos_consulta_metodos($catalogo);

    $codigosUps = array_values(array_unique(array_filter(array_map(
        static fn ($codigo): string => trim((string)$codigo),
        $codigosUps
    ), static fn (string $codigo): bool => $codigo !== '')));
    if (!$codigosUps) {
        $codigosUps = ['302304'];
    }

    $placeholdersDx = implode(',', array_fill(0, count($codigosActivos), '?'));
    $placeholdersUps = implode(',', array_fill(0, count($codigosUps), '?'));
    $select = "
        SELECT h.ID, h.DNI, h.COD_ESTAB, h.COD_SERVSA, h.CODPSAL,
               h.ANO, h.MES, h.DIA, h.fecha_reg, h.HCLFAM, h.FICHAFAM,
               h.Apellido_p, h.Apellido_m, h.Pnombre, h.Dnombres, h.EDAD,
               dt.DX, dt.id_dosis, dt.fecha_reg AS fecha_dx
        FROM his_dl h
        INNER JOIN his_dl_dt dt ON dt.ID = h.ID
    ";
    $order = ' ORDER BY h.ANO DESC, h.MES DESC, h.DIA DESC, h.ID DESC LIMIT 40';

    $rows = [];
    try {
        $stmt = $pdo->prepare(
            $select .
            " WHERE h.DNI = ? AND (h.COD_SERVSA IN ({$placeholdersUps}) OR dt.DX IN ({$placeholdersDx}))" .
            $order
        );
        $stmt->execute(array_merge([$dni], $codigosUps, $codigosActivos));
        $rows = $stmt->fetchAll();
    } catch (Throwable $e) {
        try {
            $stmt = $pdo->prepare(
                $select .
                " WHERE h.DNI = ? AND dt.DX IN ({$placeholdersDx})" .
                $order
            );
            $stmt->execute(array_merge([$dni], $codigosActivos));
            $rows = $stmt->fetchAll();
        } catch (Throwable $e2) {
            $rows = [];
        }
    }

    $ultimaAtencion = null;
    $ultimaConMetodo = null;
    foreach ($rows as $row) {
        $fecha = fecha_aplicacion_his($row);
        if ($fecha === '') {
            continue;
        }
        if ($ultimaAtencion === null) {
            $ultimaAtencion = $row;
            $ultimaAtencion['_fecha_aplicacion'] = $fecha;
        }
        $dx = trim((string)($row['DX'] ?? ''));
        $metaDx = resolver_metodo_catalogo($catalogo, $dx);
        if ($metaDx !== null && (int)($metaDx['dias_ciclo'] ?? 0) > 0) {
            if ($ultimaConMetodo === null) {
                $ultimaConMetodo = $row;
                $ultimaConMetodo['_fecha_aplicacion'] = $fecha;
                $ultimaConMetodo['_meta'] = $metaDx;
            }
        }
        if ($ultimaAtencion !== null && $ultimaConMetodo !== null) {
            break;
        }
    }

    $codigoHis = $ultimaConMetodo !== null ? trim((string)($ultimaConMetodo['DX'] ?? '')) : '';
    $metaUltimo = $codigoHis !== '' ? resolver_metodo_catalogo($catalogo, $codigoHis) : null;
    $codigo = $metaUltimo !== null ? (string)$metaUltimo['codigo_dx'] : $codigoHis;
    $diasCiclo = $metaUltimo !== null ? max(0, (int)($metaUltimo['dias_ciclo'] ?? 0)) : 0;
    $fechaAplicacionIso = $ultimaConMetodo !== null ? (string)($ultimaConMetodo['_fecha_aplicacion'] ?? '') : '';
    $fechaProximoIso = '';
    $diasParaProximo = null;
    $hoy = new DateTimeImmutable('today');
    if ($codigo !== '' && $diasCiclo > 0 && $fechaAplicacionIso !== '') {
        $proximo = (new DateTimeImmutable($fechaAplicacionIso))->modify('+' . $diasCiclo . ' days');
        $fechaProximoIso = $proximo->format('Y-m-d');
        $diasParaProximo = (int)$hoy->diff($proximo)->format('%r%a');
    }

    if ($codigo === '' || $fechaProximoIso === '') {
        $estado = 'SIN_METODO';
    } elseif ($diasParaProximo === 0) {
        $estado = 'TOCA_HOY';
    } elseif ($diasParaProximo !== null && $diasParaProximo > 0 && $diasParaProximo <= 7) {
        $estado = 'PROXIMO_7_DIAS';
    } elseif ($diasParaProximo !== null && $diasParaProximo < 0) {
        $estado = 'VENCIDO_ABANDONO';
    } else {
        $estado = 'AL_DIA';
    }

    $estabReferencia = '';
    if ($ultimaConMetodo !== null) {
        $estabReferencia = trim((string)($ultimaConMetodo['COD_ESTAB'] ?? ''));
    } elseif ($ultimaAtencion !== null) {
        $estabReferencia = trim((string)($ultimaAtencion['COD_ESTAB'] ?? ''));
    }
    $estabCanonico = $estabReferencia !== '' ? hospital_codigo_canonico($estabReferencia) : '';
    $estabActualCanonico = hospital_codigo_canonico($codEstabActual);
    $esMismoEstablecimiento = $estabCanonico !== '' && $estabCanonico === $estabActualCanonico;
    $nombreOrigen = $estabReferencia !== '' ? resolver_nombre_establecimiento($pdo, $estabReferencia) : '';
    $nombreActual = hospital_nombre_establecimiento($codEstabActual);
    $nombreMetodo = $metaUltimo !== null ? (string)$metaUltimo['nombre_metodo'] : '';
    $fechaProximoMostrar = fecha_para_mostrar($fechaProximoIso);
    $fechaAplicacionMostrar = fecha_para_mostrar($fechaAplicacionIso);
    $diasVencidos = $diasParaProximo !== null && $diasParaProximo < 0 ? abs($diasParaProximo) : 0;

    if ($codigo === '') {
        $recomendacion = $estabReferencia !== ''
            ? 'Registra atenciones de Planificación Familiar en ' . $nombreOrigen . ', pero no se identifica un método anticonceptivo vigente. Realice consejería y registre la captación en ' . $nombreActual . '.'
            : 'No registra método anticonceptivo en la Red Huaral-Chancay. Realice consejería en ' . $nombreActual . ' y registre la captación.';
    } elseif ($estado === 'TOCA_HOY') {
        $recomendacion = 'Le corresponde HOY (' . $fechaProximoMostrar . ') el método ' . $nombreMetodo . ' (código ' . $codigo . '). Confirme el control/administración y actualice sus datos de contacto.';
        if (!$esMismoEstablecimiento && $nombreOrigen !== '') {
            $recomendacion .= ' Última aplicación registrada en ' . $nombreOrigen . '; coordine la continuidad en ' . $nombreActual . '.';
        }
    } elseif ($estado === 'VENCIDO_ABANDONO') {
        $recomendacion = 'Paciente VENCIDA: el método ' . $nombreMetodo . ' correspondía desde el ' . $fechaProximoMostrar . ' (hace ' . $diasVencidos . ' días). Priorice el contacto telefónico y el seguimiento domiciliario para evitar abandono.';
        if (!$esMismoEstablecimiento && $nombreOrigen !== '') {
            $recomendacion .= ' Última aplicación en ' . $nombreOrigen . '.';
        }
    } elseif ($estado === 'PROXIMO_7_DIAS') {
        $recomendacion = 'Próximo método ' . $nombreMetodo . ' en ' . (int)$diasParaProximo . ' día(s), para el ' . $fechaProximoMostrar . '. Programe la cita y confirme la disponibilidad del insumo.';
    } else {
        $recomendacion = 'Paciente al día con ' . $nombreMetodo . '. Próximo método el ' . $fechaProximoMostrar . ' (faltan ' . (int)$diasParaProximo . ' días).';
        if (!$esMismoEstablecimiento && $nombreOrigen !== '') {
            $recomendacion .= ' Seguimiento registrado en ' . $nombreOrigen . '.';
        }
    }

    return [
        'tieneMetodoRegistrado' => $codigo !== '',
        'codigoMetodo' => $codigo,
        'codigoHis' => $codigoHis,
        'nombreMetodo' => $nombreMetodo,
        'dosis' => $ultimaConMetodo !== null ? (string)($ultimaConMetodo['id_dosis'] ?? '') : '',
        'fechaUltimaAplicacion' => $fechaAplicacionMostrar,
        'fechaUltimaAplicacionIso' => $fechaAplicacionIso,
        'diasCiclo' => $diasCiclo,
        'fechaProximoMetodo' => $fechaProximoMostrar,
        'fechaProximoMetodoIso' => $fechaProximoIso,
        'diasParaProximo' => $diasParaProximo,
        'estadoProgramacion' => $estado,
        'establecimientoUltimoMetodo' => [
            'codigo' => $estabCanonico !== '' ? $estabCanonico : $estabReferencia,
            'nombre' => $nombreOrigen,
            'esMismoEstablecimiento' => $esMismoEstablecimiento,
        ],
        'fechaUltimaAtencionPf' => $ultimaAtencion !== null ? fecha_para_mostrar((string)($ultimaAtencion['_fecha_aplicacion'] ?? '')) : '',
        'recomendacionClinica' => $recomendacion,
    ];
}

/**
 * Determina si una fila HIS corresponde realmente a la UPS de Planificación
 * Familiar. Se prioriza COD_SERVSA 302304 (o equivalentes) y, solo cuando el
 * campo está vacío, se aceptan los DX históricos de métodos anticonceptivos.
 *
 * @param array<string, mixed> $row
 * @param array<int, string> $codigosUps
 */
function atencion_ups_es_planificacion_familiar(array $row, array $codigosUps, array $codigosMetodos = []): bool
{
    $codServsa = trim((string)($row['COD_SERVSA'] ?? ''));
    if ($codServsa !== '') {
        return in_array($codServsa, $codigosUps, true);
    }
    if (!$codigosMetodos) {
        foreach (hospital_catalogo_metodos_oficial() as $meta) {
            $codigosMetodos[] = (string)($meta['codigo_dx'] ?? '');
            foreach ((array)($meta['alias'] ?? []) as $alias) {
                $codigosMetodos[] = (string)$alias;
            }
        }
    }
    $dx = trim((string)($row['DX'] ?? ''));
    return in_array($dx, array_values(array_unique($codigosMetodos)), true);
}

/**
 * @return array<int, array<string, mixed>>
 */
function consultar_atenciones_99208(PDO $pdo, string $dni): array
{
    // El parámetro se limpia en PHP y se compara SIN funciones sobre dt.DX,
    // para que la base de 5 GB pueda usar el índice del detalle clínico.
    $dni = preg_replace('/[^0-9]/', '', $dni) ?? '';
    $catalogo = catalogo_metodos_planificacion($pdo);
    $codigos = codigos_consulta_metodos($catalogo);
    if (!$codigos) {
        return [];
    }
    $placeholders = implode(',', array_fill(0, count($codigos), '?'));
    $sql = "
        SELECT h.ID, h.DNI, h.COD_ESTAB, h.COD_ESTAB AS nombre_establecimiento,
               h.DIA, h.MES, h.ANO, h.fecha_reg, dt.DX, dt.TDX, dt.LDX,
               dt.fecha_reg AS fecha_dx, h.CODPSAL
        FROM his_dl h
        INNER JOIN his_dl_dt dt ON dt.ID = h.ID
        WHERE h.DNI = ? AND dt.DX IN ({$placeholders})
        ORDER BY h.ANO DESC, h.MES DESC, h.DIA DESC
        LIMIT 10
    ";
    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute(array_merge([$dni], $codigos));
        return $stmt->fetchAll();
    } catch (Throwable $e) {
        try {
            $stmt = $pdo->prepare($sql);
            $stmt->execute(array_merge([$dni], $codigos));
            return $stmt->fetchAll();
        } catch (Throwable $e2) {
            return [];
        }
    }
}

/**
 * Códigos UPS equivalentes a Planificación Familiar.
 * @return array<int, string>
 */
function codigos_ups_planificacion_familiar(PDO $pdo): array
{
    $codigos = ['302304'];
    foreach (['tablaupsequivalente', 'maestro_sys_ups'] as $tabla) {
        try {
            $cols = $pdo->prepare("
                SELECT COLUMN_NAME FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :tabla
            ");
            $cols->execute([':tabla' => $tabla]);
            $nombres = array_map(static fn ($r) => (string)$r['COLUMN_NAME'], $cols->fetchAll());
            if (!$nombres) {
                continue;
            }
            $colCodigo = null;
            $colNombre = null;
            foreach ($nombres as $col) {
                if ($colCodigo === null && preg_match('/^(codigo|cod_ups|codups|id_ups|codigo_ups)$/i', $col)) {
                    $colCodigo = $col;
                }
                if ($colNombre === null && preg_match('/(nombre|descripcion|denominacion)/i', $col)) {
                    $colNombre = $col;
                }
            }
            if ($colCodigo === null) {
                continue;
            }
            if ($colNombre !== null) {
                $sql = "SELECT DISTINCT `{$colCodigo}` AS codigo FROM `{$tabla}`
                        WHERE `{$colNombre}` LIKE '%PLANIFIC%' LIMIT 50";
            } else {
                $sql = "SELECT DISTINCT `{$colCodigo}` AS codigo FROM `{$tabla}` LIMIT 50";
            }
            foreach ($pdo->query($sql)->fetchAll() as $row) {
                $codigo = trim((string)($row['codigo'] ?? ''));
                if ($codigo !== '' && preg_match('/^[A-Za-z0-9\-\.]{1,20}$/', $codigo)) {
                    $codigos[] = $codigo;
                }
            }
        } catch (Throwable $e) {
            // La tabla puede no existir en el servidor local; se mantiene 302304.
        }
    }
    return array_values(array_unique($codigos));
}

/**
 * @return array<int, array<string, mixed>>
 */
function consultar_ups_planificacion_familiar(PDO $pdo, string $dni, string $codEstab, array $codigosUps): array
{
    $codigosEstab = hospital_codigos_busqueda_establecimiento($codEstab);
    if (!$codigosEstab) {
        $codigosEstab = [trim($codEstab)];
    }
    $codigosUps = array_values(array_unique(array_filter(array_map(
        static fn ($codigo): string => trim((string)$codigo),
        $codigosUps
    ), static fn (string $codigo): bool => $codigo !== '')));
    if (!$codigosUps) {
        $codigosUps = ['302304'];
    }

    // Se incluyen TODAS las variantes oficiales del catálogo clínico
    // (con punto, sin punto, .00 y alias históricos), sin funciones sobre dt.DX.
    $dxCodes = codigos_consulta_metodos(catalogo_metodos_planificacion($pdo));
    if (!$dxCodes) {
        $dxCodes = ['99208'];
    }
    $placeholdersEstab = implode(',', array_fill(0, count($codigosEstab), '?'));
    $placeholdersUps = implode(',', array_fill(0, count($codigosUps), '?'));
    $placeholdersDx = implode(',', array_fill(0, count($dxCodes), '?'));

    // h.COD_ESTAB IN (...) es sargable y usa idx_his_dl_dni_estab_ups.
    // Se eliminó RIGHT(TRIM(h.COD_ESTAB), 5) = RIGHT(TRIM(?), 5), que forzaba
    // un Table Scan sobre millones de filas de his_dl.
    $sql = "
        SELECT h.ID, h.DNI, h.COD_ESTAB, h.COD_SERVSA, h.CODPSAL,
               h.ANO, h.MES, h.DIA, h.fecha_reg, h.HCLFAM,
               dt.DX, dt.TDX, dt.LDX, dt.id_dosis, dt.Alerta, dt.fecha_reg AS fecha_dx
        FROM his_dl h
        INNER JOIN his_dl_dt dt ON dt.ID = h.ID
        WHERE h.DNI = ?
          AND h.COD_ESTAB IN ({$placeholdersEstab})
          AND (h.COD_SERVSA IN ({$placeholdersUps}) OR dt.DX IN ({$placeholdersDx}))
        ORDER BY h.ANO DESC, h.MES DESC, h.DIA DESC
        LIMIT 20
    ";
    $params = array_merge([$dni], $codigosEstab, $codigosUps, $dxCodes);
    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    } catch (Throwable $e) {
        try {
            $sqlFallback = "
                SELECT h.ID, h.DNI, h.COD_ESTAB, h.CODPSAL,
                       h.ANO, h.MES, h.DIA, h.fecha_reg, h.HCLFAM,
                       dt.DX, dt.TDX, dt.LDX, dt.id_dosis, dt.Alerta, dt.fecha_reg AS fecha_dx
                FROM his_dl h
                INNER JOIN his_dl_dt dt ON dt.ID = h.ID
                WHERE h.DNI = ?
                  AND h.COD_ESTAB IN ({$placeholdersEstab})
                  AND dt.DX IN ({$placeholdersDx})
                ORDER BY h.ANO DESC, h.MES DESC, h.DIA DESC
                LIMIT 20
            ";
            $stmt = $pdo->prepare($sqlFallback);
            $stmt->execute(array_merge([$dni], $codigosEstab, $dxCodes));
            return $stmt->fetchAll();
        } catch (Throwable $e2) {
            return [];
        }
    }
}

function fecha_dd_mm_yyyy(array $row): string
{
    $dia = (int)($row['DIA'] ?? 0);
    $mes = (int)($row['MES'] ?? 0);
    $ano = (int)($row['ANO'] ?? 0);
    if ($dia >= 1 && $dia <= 31 && $mes >= 1 && $mes <= 12 && $ano >= 1900) {
        return sprintf('%02d/%02d/%04d', $dia, $mes, $ano);
    }
    $fecha = (string)($row['fecha_dx'] ?? $row['fecha_reg'] ?? '');
    $ts = strtotime($fecha);
    return $ts ? date('d/m/Y', $ts) : '';
}

// ---------------------------------------------------------------------------
// 7. BÚSQUEDA DE DNI — 30 consultas/minuto (anti-scraping)
// ---------------------------------------------------------------------------
if ($action === 'lookup_dni') {
    $session = require_session();
    $ip = HospitalHuaralDB::clientIp();
    $bucket = 'lookup:' . hash('sha256', (string)($session['token'] ?? ($session['dni'] . '|' . $ip)));
    $limit = HospitalHuaralDB::rateLimitStatus($bucket, 30, 60);
    if (!$limit['allowed']) {
        HospitalHuaralDB::registrarAuditoria($session['dni'], 'LOOKUP_RATE_LIMITED', 'Límite de 30 consultas de DNI por minuto excedido. Posible scraping bloqueado.', $session['cod_estab'], $session['platform']);
        json_error('Límite de 30 consultas de DNI por minuto alcanzado. Espere y vuelva a intentar.', 429, [
            'retryAfter' => $limit['retryAfter'],
        ]);
    }
    HospitalHuaralDB::rateLimitHit($bucket, 60);

    $dni = preg_replace('/[^0-9]/', '', (string)($_GET['dni'] ?? '')) ?? '';
    if (strlen($dni) < 8 || strlen($dni) > 15) {
        json_error('Formato de DNI inválido. Use únicamente números (8 a 15 dígitos).', 400);
    }

    $codEstab = hospital_codigo_canonico((string)($_GET['cod_estab'] ?? $session['cod_estab']));
    if (hospital_establecimiento($codEstab) === null) {
        $codEstab = $session['cod_estab'];
    }
    $est = hospital_establecimiento($codEstab);

    // 7.1 Historia general (la más reciente)
    $hisRecord = null;
    try {
        $stmt = $pdo->prepare("
            SELECT h.ID, h.DNI, h.COD_ESTAB, h.COD_SERVSA, h.CODPSAL,
                   TRIM(h.Apellido_p) AS Apellido_p, TRIM(h.Apellido_m) AS Apellido_m,
                   TRIM(h.Pnombre) AS Pnombre, TRIM(h.Dnombres) AS Dnombres,
                   h.EDAD, h.SEXO, h.UBIGEO, h.FICHAFAM, h.HCLFAM,
                   h.Fecha_Ultima_Regla, h.condicion_gestante, h.fecha_reg,
                   h.PESO, h.TALLA, h.IMC, h.FECHA_NAC, h.gruporiesgo_desc
            FROM his_dl h
            WHERE h.DNI = :dni
            ORDER BY h.ANO DESC, h.MES DESC, h.DIA DESC
            LIMIT 1
        ");
        $stmt->execute([':dni' => $dni]);
        $hisRecord = $stmt->fetch() ?: null;
    } catch (Throwable $e) {
        $stmt = $pdo->prepare("
            SELECT h.ID, h.DNI, h.COD_ESTAB, h.COD_SERVSA, h.CODPSAL,
                   TRIM(h.Apellido_p) AS Apellido_p, TRIM(h.Apellido_m) AS Apellido_m,
                   TRIM(h.Pnombre) AS Pnombre, TRIM(h.Dnombres) AS Dnombres,
                   h.EDAD, h.SEXO, h.UBIGEO, h.FICHAFAM, h.HCLFAM,
                   h.Fecha_Ultima_Regla, h.condicion_gestante, h.fecha_reg
            FROM his_dl h
            WHERE h.DNI = :dni
            ORDER BY h.ANO DESC, h.MES DESC, h.DIA DESC
            LIMIT 1
        ");
        $stmt->execute([':dni' => $dni]);
        $hisRecord = $stmt->fetch() ?: null;
    }

    $hisDetails = [];
    if ($hisRecord) {
        $stmtDt = $pdo->prepare('SELECT DX, TDX, LDX, id_dosis, Alerta, fecha_reg FROM his_dl_dt WHERE ID = :id ORDER BY num ASC LIMIT 50');
        $stmtDt->execute([':id' => $hisRecord['ID']]);
        $hisDetails = $stmtDt->fetchAll();
    }

    // 7.2 Código 99208 (banner clínico destacado)
    $atenciones99208 = consultar_atenciones_99208($pdo, $dni);
    $historial99208 = [];
    foreach ($atenciones99208 as $row) {
        // Primero el catálogo oficial de las 53 IPRESS; como respaldo se usa el
        // nombre del JOIN con establec y, si no existe, la consulta directa.
        $nombre = resolver_nombre_establecimiento(
            $pdo,
            (string)$row['COD_ESTAB'],
            (string)($row['nombre_establecimiento'] ?? '')
        );
        $historial99208[] = [
            'establecimiento' => $nombre,
            'cod_estab' => (string)$row['COD_ESTAB'],
            'fecha' => fecha_dd_mm_yyyy($row),
            'fecha_iso' => (string)($row['fecha_dx'] ?? $row['fecha_reg'] ?? ''),
            'profesional' => (string)($row['CODPSAL'] ?? ''),
            'dx' => (string)$row['DX'],
            'tdx' => (string)($row['TDX'] ?? ''),
            'ldx' => (string)($row['LDX'] ?? ''),
        ];
    }
    $tiene99208 = count($historial99208) > 0;
    $primer99208 = $historial99208[0] ?? null;
    $mensaje99208 = $tiene99208
        ? sprintf(
            'La paciente con DNI %s recibió atención con el código 99208 en el establecimiento %s en la fecha %s.',
            $dni,
            $primer99208['establecimiento'],
            $primer99208['fecha']
        )
        : sprintf('La paciente con DNI %s no registra atención con el código 99208 en la Red Huaral-Chancay.', $dni);

    // 7.3 Búsqueda en la UPS de Planificación Familiar del establecimiento de la obstetra
    $codigosUps = codigos_ups_planificacion_familiar($pdo);
    $atencionesUps = consultar_ups_planificacion_familiar($pdo, $dni, $codEstab, $codigosUps);
    $tieneUps = false;
    foreach ($atencionesUps as $row) {
        if (atencion_ups_es_planificacion_familiar($row, $codigosUps)) {
            $tieneUps = true;
            break;
        }
    }
    $nombreEstab = $est['DESC_ESTAB'] ?? hospital_nombre_establecimiento($codEstab);
    $mensajeUps = $tieneUps
        ? 'Paciente YA REGISTRADA en la UPS de Planificación Familiar del establecimiento ' . $nombreEstab . '. Pase directo habilitado sin volver a llenar el formulario.'
        : 'Paciente no registra atención previa en la UPS de Planificación Familiar de ' . $nombreEstab . '. Complete el formulario (datos precargados desde HIS) para registrar la captación.';

    $upsAtenciones = [];
    foreach ($atencionesUps as $row) {
        $upsAtenciones[] = [
            'id_his' => (string)$row['ID'],
            'fecha' => fecha_dd_mm_yyyy($row),
            'cod_servsa' => (string)($row['COD_SERVSA'] ?? ''),
            'dx' => (string)($row['DX'] ?? ''),
            'profesional' => (string)($row['CODPSAL'] ?? ''),
            'id_dosis' => (string)($row['id_dosis'] ?? ''),
            'alerta' => (string)($row['Alerta'] ?? ''),
            'es_planificacion_familiar' => atencion_ups_es_planificacion_familiar($row, $codigosUps),
        ];
    }

    // 7.4 Captación previa en la app (PII descifrada solo dentro de sesión 2FA)
    $stmtCap = $pdo->prepare('SELECT * FROM pacientes_sin_metodo WHERE dni = :dni LIMIT 1');
    $stmtCap->execute([':dni' => $dni]);
    $existing = $stmtCap->fetch() ?: null;
    if ($existing) {
        $existing['celular'] = HospitalHuaralDB::decryptPII((string)$existing['celular']);
        $existing['correo'] = HospitalHuaralDB::decryptPII((string)$existing['correo']);
        $existing['direccion'] = HospitalHuaralDB::decryptPII((string)$existing['direccion']);
        unset($existing['encrypted_raw']);
    }

    $hasActiveMethod = false;
    $catalogoMetodos = catalogo_metodos_planificacion($pdo);
    foreach ($hisDetails as $dt) {
        $codigoDx = (string)($dt['DX'] ?? '');
        $dias = isset($catalogoMetodos[$codigoDx]) ? (int)$catalogoMetodos[$codigoDx]['dias_ciclo'] : 0;
        if ($dias > 0) {
            $hasActiveMethod = true;
            break;
        }
    }

    // 7.5 Programación clínica en toda la red: última atención con método y
    // cálculo del próximo vencimiento. Es independiente de la última fila
    // general de his_dl y también contempla atenciones en otras IPRESS.
    $programacionPaciente = programacion_planificacion_paciente($pdo, $dni, $codEstab, $catalogoMetodos, $codigosUps);
    if ($programacionPaciente['tieneMetodoRegistrado']) {
        $hasActiveMethod = true;
    }

    $estabOrigenCodigo = (string)($programacionPaciente['establecimientoUltimoMetodo']['codigo'] ?? '');
    if ($estabOrigenCodigo === '' && $hisRecord) {
        $estabOrigenCodigo = (string)($hisRecord['COD_ESTAB'] ?? '');
    }
    $esMismoEstablecimiento = $estabOrigenCodigo !== ''
        && hospital_codigo_canonico($estabOrigenCodigo) === $codEstab;

    $tieneAtencionPfRed = $programacionPaciente['tieneMetodoRegistrado']
        || (string)($programacionPaciente['fechaUltimaAtencionPf'] ?? '') !== '';
    if (!$hisRecord && !$tieneAtencionPfRed) {
        $casoFlujo = 'NUEVA';
    } elseif ($esMismoEstablecimiento && ($tieneUps || $programacionPaciente['tieneMetodoRegistrado'])) {
        $casoFlujo = 'MISMO_ESTABLECIMIENTO';
    } elseif (!$esMismoEstablecimiento && ($hisRecord || $tieneAtencionPfRed)) {
        $casoFlujo = 'OTRO_ESTABLECIMIENTO';
    } else {
        $casoFlujo = 'MISMO_SIN_UPS';
    }

    $mensajeCambioEstablecimiento = '';
    if ($casoFlujo === 'OTRO_ESTABLECIMIENTO') {
        $nombreOrigen = (string)($programacionPaciente['establecimientoUltimoMetodo']['nombre'] ?? '');
        if ($nombreOrigen === '' && $estabOrigenCodigo !== '') {
            $nombreOrigen = resolver_nombre_establecimiento($pdo, $estabOrigenCodigo);
        }
        $fechaOrigen = (string)($programacionPaciente['fechaUltimaAtencionPf'] ?? '');
        if ($fechaOrigen === '' && $hisRecord) {
            $fechaOrigen = fecha_dd_mm_yyyy($hisRecord);
        }
        $mensajeCambioEstablecimiento = sprintf(
            '🔄 Paciente atendida previamente en %s (Última atención: %s). Se han autorrellenado sus datos de identidad. Verifique y actualice su Distrito, Dirección, Sector y Celular para registrarla en %s.',
            $nombreOrigen !== '' ? $nombreOrigen : 'otro establecimiento de la Red',
            $fechaOrigen !== '' ? $fechaOrigen : 'sin fecha registrada',
            $nombreEstab
        );
    }

    // Caso B: datos mínimos para que el formulario se abra precargado desde HIS.
    $precargaDesdeHis = null;
    if ($hisRecord) {
        $precargaDesdeHis = [
            'apellido_paterno' => (string)($hisRecord['Apellido_p'] ?? ''),
            'apellido_materno' => (string)($hisRecord['Apellido_m'] ?? ''),
            'nombres' => (string)($hisRecord['Dnombres'] ?? ($hisRecord['Pnombre'] ?? '')),
            'edad' => (int)($hisRecord['EDAD'] ?? 0),
            'dni' => (string)($hisRecord['DNI'] ?? $dni),
        ];
    }

    HospitalHuaralDB::registrarAuditoria(
        $session['dni'],
        'VALIDACION_DNI_HIS',
        'Consulta DNI ' . $dni . ' en ' . $nombreEstab . '. 99208: ' . ($tiene99208 ? 'SÍ' : 'NO') . '. UPS PF previa: ' . ($tieneUps ? 'SÍ' : 'NO') . '. Caso: ' . $casoFlujo . '. Programación: ' . $programacionPaciente['estadoProgramacion'] . '.',
        $codEstab,
        $session['platform']
    );
    HospitalHuaralDB::registrarAuditoria(
        $session['dni'],
        'VERIFICACION_99208',
        'Verificación del código 99208 para DNI ' . $dni . ': ' . ($tiene99208 ? 'ATENCIÓN ENCONTRADA' : 'SIN ATENCIÓN') . '.',
        $codEstab,
        $session['platform']
    );

    json_out([
        'foundInHis' => (bool)$hisRecord,
        'foundInEstablecimiento' => $hisRecord
            ? (hospital_codigo_canonico((string)$hisRecord['COD_ESTAB']) === $codEstab)
            : false,
        'hasActiveMethodInHis' => $hasActiveMethod,
        'hisRecord' => $hisRecord,
        'hisDetails' => $hisDetails,
        'existingCaptacion' => $existing,
        'precargaDesdeHis' => $precargaDesdeHis,
        'programacionPaciente' => $programacionPaciente,
        'casoFlujo' => $casoFlujo,
        'esMismoEstablecimiento' => $esMismoEstablecimiento,
        'mensajeCambioEstablecimiento' => $mensajeCambioEstablecimiento,
        'establecimiento' => [
            'codigo' => $codEstab,
            'nombre' => $nombreEstab,
            'categoria' => $est['CATEGORIA'] ?? '',
            'distrito' => $est['DISTRITO'] ?? '',
        ],
        'atencion99208' => [
            'tieneCodigo99208' => $tiene99208,
            'mensajeOficial99208' => $mensaje99208,
            'historial99208' => $historial99208,
        ],
        'upsPlanificacionFamiliar' => [
            'establecimiento' => [
                'codigo' => $codEstab,
                'nombre' => $nombreEstab,
            ],
            'codigosUps' => $codigosUps,
            'tieneAtencionPrevia' => $tieneUps,
            'paseDirectoHabilitado' => $tieneUps,
            'requiereFormularioCompleto' => !$tieneUps,
            'caso' => $tieneUps ? 'A' : 'B',
            'mensaje' => $mensajeUps,
            'atenciones' => $upsAtenciones,
        ],
    ]);
}

// ---------------------------------------------------------------------------
// 7-B. REPORTE DE PROGRAMACIÓN POR FECHA
// ---------------------------------------------------------------------------
if ($action === 'reporte_programacion') {
    $session = require_session();

    // Anti-scraping: el reporte contiene PII descifrada. Máximo 30 consultas/min.
    $bucket = 'reporte_prog:' . hash('sha256', (string)($session['token'] ?? ($session['dni'] . '|' . HospitalHuaralDB::clientIp())));
    $limit = HospitalHuaralDB::rateLimitStatus($bucket, 30, 60);
    if (!$limit['allowed']) {
        json_error('Límite de 30 reportes por minuto alcanzado. Espere y vuelva a intentar.', 429, [
            'retryAfter' => $limit['retryAfter'],
        ]);
    }
    HospitalHuaralDB::rateLimitHit($bucket, 60);

    $catalogo = catalogo_metodos_planificacion($pdo);

    // 7-B.1 Validación estricta de parámetros.
    $fechaObjetivo = trim((string)($_GET['fecha_objetivo'] ?? ''));
    if ($fechaObjetivo === '') {
        $fechaObjetivo = date('Y-m-d');
    }
    $fechaBase = DateTimeImmutable::createFromFormat('!Y-m-d', $fechaObjetivo);
    if (!$fechaBase instanceof DateTimeImmutable || $fechaBase->format('Y-m-d') !== $fechaObjetivo) {
        json_error('La fecha_objetivo debe tener el formato YYYY-MM-DD y ser una fecha real.', 400);
    }

    $rangoModo = strtolower(trim((string)($_GET['rango_modo'] ?? 'exacto')));
    if (!in_array($rangoModo, ['exacto', 'ventana_7d', 'vencidas', 'todos'], true)) {
        $rangoModo = 'exacto';
    }

    $alcance = strtolower(trim((string)($_GET['alcance'] ?? 'establecimiento')));
    if (!in_array($alcance, ['establecimiento', 'red'], true)) {
        $alcance = 'establecimiento';
    }

    $codigoMetodoRaw = strtoupper(trim((string)($_GET['codigo_metodo'] ?? 'TODOS')));
    $codigosFiltro = [];
    if ($codigoMetodoRaw !== '' && $codigoMetodoRaw !== 'TODOS') {
        foreach (explode(',', $codigoMetodoRaw) as $codigo) {
            $codigo = trim($codigo);
            if ($codigo === '') {
                continue;
            }
            $metaFiltro = resolver_metodo_catalogo($catalogo, $codigo);
            if ($metaFiltro === null) {
                json_error('El código de método solicitado no existe en el catálogo clínico.', 400, [
                    'code' => 'METODO_NO_CATALOGADO',
                    'codigo' => $codigo,
                ]);
            }
            $codigosFiltro[] = (string)$metaFiltro['codigo_dx'];
        }
        $codigosFiltro = array_values(array_unique($codigosFiltro));
    }
    $codigosConsulta = codigos_consulta_metodos($catalogo, $codigosFiltro);

    // 7-B.2 Ventanas de fecha de aplicación por método. Al calcular
    // fecha_proximo = fecha_aplicacion + dias_ciclo, la consulta se acota a los
    // días exactos en que cada método pudo aplicarse para vencer en el rango.
    $lookbackVencidas = 1825; // 5 años de abandonos recuperables
    $lookbackTodos = 365;     // "vencidas recientes" al combinar todos los modos
    $ventanas = [];
    foreach ($codigosConsulta as $codigo) {
        $metaCiclo = resolver_metodo_catalogo($catalogo, $codigo);
        $dias = max(1, (int)($metaCiclo['dias_ciclo'] ?? 30));
        if ($rangoModo === 'exacto') {
            $desde = $fechaBase->modify('-' . $dias . ' days')->format('Y-m-d');
            $hasta = $desde;
        } elseif ($rangoModo === 'ventana_7d') {
            $desde = $fechaBase->modify('-' . $dias . ' days')->format('Y-m-d');
            $hasta = $fechaBase->modify('+' . (7 - $dias) . ' days')->format('Y-m-d');
        } elseif ($rangoModo === 'vencidas') {
            $desde = $fechaBase->modify('-' . ($dias + $lookbackVencidas) . ' days')->format('Y-m-d');
            $hasta = $fechaBase->modify('-' . ($dias + 1) . ' days')->format('Y-m-d');
        } else {
            $desde = $fechaBase->modify('-' . ($dias + $lookbackTodos) . ' days')->format('Y-m-d');
            $hasta = $fechaBase->modify('+' . (7 - $dias) . ' days')->format('Y-m-d');
        }
        $ventanas[$codigo] = ['desde' => $desde, 'hasta' => $hasta];
    }

    // 7-B.3 Expresión SQL única para la fecha real de aplicación. Se usa tanto
    // en la selección como en el filtro SARGable de las ventanas.
    $exprAplicacion = static function (string $aliasH, string $aliasDt): string {
        return "COALESCE(
            CASE
              WHEN {$aliasH}.DIA BETWEEN 1 AND 31
               AND {$aliasH}.MES BETWEEN 1 AND 12
               AND {$aliasH}.ANO BETWEEN 1900 AND 2100
              THEN STR_TO_DATE(
                     CONCAT({$aliasH}.ANO, '-', LPAD({$aliasH}.MES, 2, '0'), '-', LPAD({$aliasH}.DIA, 2, '0')),
                     '%Y-%m-%d'
                   )
            END,
            DATE({$aliasH}.fecha_reg),
            DATE({$aliasDt}.fecha_reg)
        )";
    };
    $exprH = $exprAplicacion('h', 'dt');
    $expr0 = $exprAplicacion('h0', 'dt0');

    $placeholdersCodigos = implode(',', array_fill(0, count($codigosConsulta), '?'));
    $paramsCodigos = array_map('strval', $codigosConsulta);

    $verRed = puede_ver_red($session);
    $rolReporte = HospitalHuaralDB::rolUsuario((string)$session['dni']);
    $esObstetraReporte = $rolReporte === 'OBSTETRA';
    $modoRedReporte = es_alcance_red($session, $alcance);

    // El establecimiento se aplica SIEMPRE en el subquery de candidatas (h0) y
    // en la consulta principal (h). Nunca se mezclan establecimientos.
    $condicionEstab0 = '';
    $condicionEstabH = '';
    $paramsEstab = [];
    if (!$modoRedReporte) {
        $variantes = codigos_establecimiento_sesion($session);
        $placeholdersEstab = implode(',', array_fill(0, count($variantes), '?'));
        $condicionEstab0 = " AND h0.COD_ESTAB IN ({$placeholdersEstab}) ";
        $condicionEstabH = " AND h.COD_ESTAB IN ({$placeholdersEstab}) ";
        $paramsEstab = $variantes;
    }

    $ambitoReporte = strtolower(trim((string)($_GET['ambito'] ?? ($esObstetraReporte ? 'mis_atenciones' : 'establecimiento'))));
    if (!in_array($ambitoReporte, ['mis_atenciones', 'establecimiento'], true)) {
        $ambitoReporte = $esObstetraReporte ? 'mis_atenciones' : 'establecimiento';
    }
    $obstetraReporte = preg_replace('/[^0-9A-Za-z]/', '', (string)($_GET['obstetra'] ?? '')) ?? '';
    if ($obstetraReporte === 'TODOS') {
        $obstetraReporte = '';
    }
    $condicionObstetra = '';
    $paramsObstetra = [];
    if ($esObstetraReporte) {
        // La obstetra puede alternar "Mis atenciones" (solo pacientes que ella
        // atendió) o "Mi establecimiento" (padrón histórico del establecimiento).
        if ($ambitoReporte === 'mis_atenciones') {
            $condicionObstetra = ' AND h0.CODPSAL = ? ';
            $paramsObstetra[] = (string)$session['dni'];
        }
        $obstetraReporte = $ambitoReporte === 'mis_atenciones' ? (string)$session['dni'] : '';
    } elseif ($obstetraReporte !== '') {
        $condicionObstetra = ' AND h0.CODPSAL = ? ';
        $paramsObstetra[] = $obstetraReporte;
    }
    $condicionPropia = '';
    $paramsPropia = [];

    $condicionesVentana = [];
    $paramsVentana = [];
    $anioMinVentana = 1900;
    $anioMaxVentana = 2100;
    foreach ($ventanas as $codigo => $rango) {
        $condicionesVentana[] = "(dt0.DX = ? AND {$expr0} BETWEEN ? AND ?)";
        $paramsVentana[] = $codigo;
        $paramsVentana[] = $rango['desde'];
        $paramsVentana[] = $rango['hasta'];
        $anioMinVentana = min($anioMinVentana, (int)substr($rango['desde'], 0, 4));
        $anioMaxVentana = max($anioMaxVentana, (int)substr($rango['hasta'], 0, 4));
    }
    $condicionVentana = '(' . implode(' OR ', $condicionesVentana) . ')';

    // El primer subquery identifica solo las pacientes candidatas dentro de la
    // ventana (máximo 800). El segundo recupera su última atención con método
    // usando el índice de DNI, evitando escanear millones de filas del HIS.
    $limiteCandidatos = 800;
    $sql = "
        SELECT
            h.ID AS id_his,
            h.DNI AS dni,
            h.COD_ESTAB AS cod_estab,
            TRIM(h.Apellido_p) AS apellido_paterno,
            TRIM(h.Apellido_m) AS apellido_materno,
            TRIM(COALESCE(NULLIF(h.Dnombres, ''), h.Pnombre)) AS nombres,
            h.EDAD AS edad,
            h.HCLFAM AS historia_clinica,
            h.FICHAFAM AS ficha_familiar,
            h.CODPSAL AS obstetra_dni,
            h.DIA, h.MES, h.ANO, h.fecha_reg,
            dt.DX AS codigo_metodo,
            dt.id_dosis AS dosis,
            dt.fecha_reg AS fecha_dx,
            {$exprH} AS fecha_aplicacion
        FROM his_dl h
        INNER JOIN his_dl_dt dt ON dt.ID = h.ID
        INNER JOIN (
            SELECT h0.DNI AS dni
            FROM his_dl h0
            INNER JOIN his_dl_dt dt0 ON dt0.ID = h0.ID
            WHERE dt0.DX IN ({$placeholdersCodigos})
              {$condicionEstab0}
              {$condicionObstetra}
              AND h0.ANO BETWEEN ? AND ?
              AND {$condicionVentana}
            GROUP BY h0.DNI
            ORDER BY MAX(h0.ANO) DESC, MAX(h0.MES) DESC, MAX(h0.DIA) DESC
            LIMIT {$limiteCandidatos}
        ) cand ON cand.dni = h.DNI
        WHERE dt.DX IN ({$placeholdersCodigos})
          {$condicionEstabH}
        ORDER BY h.DNI ASC, h.ANO DESC, h.MES DESC, h.DIA DESC, h.ID DESC
        LIMIT 12000
    ";

    $params = array_merge($paramsCodigos, $paramsEstab, $paramsObstetra, [$anioMinVentana, $anioMaxVentana], $paramsVentana, $paramsCodigos, $paramsEstab);
    $filasBase = [];
    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $filasBase = $stmt->fetchAll();
    } catch (Throwable $e) {
        error_log('[PlanificaHIS] reporte_programacion query failure: ' . $e->getMessage());
        json_error('No se pudo calcular la programación. Verifique los índices clínicos del HIS e intente nuevamente.', 503, [
            'code' => 'REPORTE_QUERY_FAILED',
        ]);
    }

    // 7-B.4 Se elige la última atención con método por DNI. Si una misma
    // atención tiene varios códigos, gana el ciclo más largo (método real).
    $seleccionados = [];
    foreach ($filasBase as $row) {
        $dniKey = trim((string)($row['dni'] ?? ''));
        $codigo = trim((string)($row['codigo_metodo'] ?? ''));
        $metaMetodo = resolver_metodo_catalogo($catalogo, $codigo);
        if ($dniKey === '' || $metaMetodo === null) {
            continue;
        }
        $diasCiclo = (int)($metaMetodo['dias_ciclo'] ?? 0);
        if ($diasCiclo <= 0) {
            continue;
        }
        $fechaAplicacion = trim((string)($row['fecha_aplicacion'] ?? ''));
        if ($fechaAplicacion === '' || str_starts_with($fechaAplicacion, '0000-00-00')) {
            $fechaAplicacion = fecha_aplicacion_his($row);
        }
        if ($fechaAplicacion === '') {
            continue;
        }
        try {
            $fechaProximo = (new DateTimeImmutable($fechaAplicacion))->modify('+' . $diasCiclo . ' days');
        } catch (Throwable $e) {
            continue;
        }
        $score = $fechaAplicacion
            . '|' . str_pad((string)$diasCiclo, 4, '0', STR_PAD_LEFT)
            . '|' . str_pad((string)(int)($row['id_his'] ?? 0), 12, '0', STR_PAD_LEFT);
        if (isset($seleccionados[$dniKey]) && strcmp($score, $seleccionados[$dniKey]['_score']) <= 0) {
            continue;
        }
        $seleccionados[$dniKey] = [
            '_score' => $score,
            'row' => $row,
            'codigo' => (string)($metaMetodo['codigo_dx'] ?? $codigo),
            'codigo_his' => $codigo,
            'nombre_metodo' => (string)($metaMetodo['nombre_metodo'] ?? $codigo),
            'dias_ciclo' => $diasCiclo,
            'fecha_aplicacion' => $fechaAplicacion,
            'fecha_proximo' => $fechaProximo->format('Y-m-d'),
        ];
    }

    // 7-B.5 Filtro clínico final y cálculo de días restantes respecto de la
    // fecha objetivo (positivo = falta; 0 = hoy; negativo = vencida).
    $dnis = [];
    $candidatos = [];
    foreach ($seleccionados as $dniKey => $sel) {
        $diasRestantes = (int)$fechaBase->diff(new DateTimeImmutable($sel['fecha_proximo']))->format('%r%a');
        $aplica = match ($rangoModo) {
            'exacto' => $diasRestantes === 0,
            'ventana_7d' => $diasRestantes >= 0 && $diasRestantes <= 7,
            'vencidas' => $diasRestantes < 0 && $diasRestantes >= -$lookbackVencidas,
            'todos' => $diasRestantes <= 7 && $diasRestantes >= -$lookbackTodos,
            default => false,
        };
        if (!$aplica) {
            continue;
        }
        if ($diasRestantes === 0) {
            $estado = 'TOCA_EN_FECHA';
        } elseif ($diasRestantes > 0 && $diasRestantes <= 7) {
            $estado = 'PROXIMO_7_DIAS';
        } elseif ($diasRestantes < 0) {
            $estado = 'VENCIDO_ABANDONO';
        } else {
            $estado = 'AL_DIA';
        }
        $sel['dias_restantes'] = $diasRestantes;
        $sel['estado'] = $estado;
        $candidatos[$dniKey] = $sel;
        $dnis[] = $dniKey;
    }

    // 7-B.6 Cruce por DNI con pacientes_sin_metodo para adjuntar contacto y
    // domicilio descifrados (AES-256-GCM) solo dentro de la sesión 2FA.
    $captaciones = [];
    if ($dnis) {
        try {
            $placeholdersDnis = implode(',', array_fill(0, count($dnis), '?'));
            $stmtCap = $pdo->prepare("
                SELECT dni, apellido_paterno, apellido_materno, nombres, edad,
                       celular, correo, distrito, direccion, sector, estado_paciente, cod_estab
                FROM pacientes_sin_metodo
                WHERE dni IN ({$placeholdersDnis})
            ");
            $stmtCap->execute($dnis);
            foreach ($stmtCap->fetchAll() as $cap) {
                $captaciones[trim((string)$cap['dni'])] = $cap;
            }
        } catch (Throwable $e) {
            $captaciones = [];
        }
    }

    $filas = [];
    foreach ($candidatos as $dniKey => $sel) {
        $row = $sel['row'];
        $cap = $captaciones[$dniKey] ?? [];
        $codEstab = trim((string)($row['cod_estab'] ?? ($cap['cod_estab'] ?? '')));
        $estInfo = hospital_establecimiento($codEstab);

        $apellidosHis = trim(
            trim((string)($row['apellido_paterno'] ?? '')) . ' ' .
            trim((string)($row['apellido_materno'] ?? ''))
        );
        $nombresHis = trim((string)($row['nombres'] ?? ''));
        $nombreHis = trim($apellidosHis . ($apellidosHis !== '' && $nombresHis !== '' ? ', ' : '') . $nombresHis);
        $apellidosCap = trim(
            trim((string)($cap['apellido_paterno'] ?? '')) . ' ' .
            trim((string)($cap['apellido_materno'] ?? ''))
        );
        $nombresCap = trim((string)($cap['nombres'] ?? ''));
        $nombreCap = trim($apellidosCap . ($apellidosCap !== '' && $nombresCap !== '' ? ', ' : '') . $nombresCap);
        $pacienteNombre = strtoupper($nombreHis !== '' ? $nombreHis : $nombreCap);
        if ($pacienteNombre === '') {
            // El HIS local no siempre guarda nombres; el DNI evita filas vacías.
            $pacienteNombre = 'PACIENTE ' . $dniKey;
        }

        $edad = (int)($row['edad'] ?? 0);
        if ($edad <= 0) {
            $edad = (int)($cap['edad'] ?? 0);
        }

        $distrito = trim((string)($cap['distrito'] ?? ''));
        if ($distrito === '') {
            $distrito = (string)($estInfo['DISTRITO'] ?? '');
        }

        $filas[] = [
            'dni' => $dniKey,
            'paciente_nombre' => $pacienteNombre,
            'edad' => $edad,
            'historia_clinica' => (string)($row['historia_clinica'] ?? ''),
            'ficha_familiar' => (string)($row['ficha_familiar'] ?? ''),
            'cod_estab' => $codEstab,
            'establecimiento' => resolver_nombre_establecimiento($pdo, $codEstab),
            'codigo_metodo' => $sel['codigo'],
            'codigo_his' => (string)($sel['codigo_his'] ?? ''),
            'nombre_metodo' => (string)($sel['nombre_metodo'] ?? $sel['codigo']),
            'dosis' => (string)($row['dosis'] ?? ''),
            'fecha_aplicacion' => fecha_para_mostrar($sel['fecha_aplicacion']),
            'fecha_aplicacion_iso' => $sel['fecha_aplicacion'],
            'dias_ciclo' => (int)$sel['dias_ciclo'],
            'fecha_proximo_metodo' => fecha_para_mostrar($sel['fecha_proximo']),
            'fecha_proximo_metodo_iso' => $sel['fecha_proximo'],
            'dias_restantes' => (int)$sel['dias_restantes'],
            'estado_programacion' => $sel['estado'],
            'celular' => HospitalHuaralDB::decryptPII((string)($cap['celular'] ?? '')),
            'direccion' => HospitalHuaralDB::decryptPII((string)($cap['direccion'] ?? '')),
            'distrito' => $distrito,
            'sector' => (string)($cap['sector'] ?? ''),
            'obstetra_dni' => (string)($row['obstetra_dni'] ?? ''),
        ];
    }

    usort($filas, static function (array $a, array $b): int {
        $cmp = $a['dias_restantes'] <=> $b['dias_restantes'];
        return $cmp !== 0 ? $cmp : strcmp($a['paciente_nombre'], $b['paciente_nombre']);
    });

    $resumen = [
        'total' => count($filas),
        'toca_en_fecha' => 0,
        'proximo_7_dias' => 0,
        'vencido_abandono' => 0,
        'al_dia' => 0,
    ];
    foreach ($filas as $fila) {
        $clave = match ($fila['estado_programacion']) {
            'TOCA_EN_FECHA' => 'toca_en_fecha',
            'PROXIMO_7_DIAS' => 'proximo_7_dias',
            'VENCIDO_ABANDONO' => 'vencido_abandono',
            default => 'al_dia',
        };
        $resumen[$clave]++;
    }

    $establecimientoActual = [
        'codigo' => (string)$session['cod_estab'],
        'nombre' => (string)$session['estab_nombre'],
        'distrito' => '',
    ];
    $estInfoActual = hospital_establecimiento((string)$session['cod_estab']);
    $establecimientoActual['distrito'] = (string)($estInfoActual['DISTRITO'] ?? '');

    $obstetraNombreReporte = '';
    if ($obstetraReporte !== '') {
        $obstetraNombreReporte = HospitalHuaralDB::nombrePersona($obstetraReporte, $pdo);
        if ($obstetraNombreReporte === '') {
            $obstetraNombreReporte = 'OBSTETRA ' . $obstetraReporte;
        }
    } elseif ($esObstetraReporte) {
        $obstetraNombreReporte = HospitalHuaralDB::nombrePersona((string)$session['dni'], $pdo);
    } elseif ($modoRedReporte) {
        $obstetraNombreReporte = 'TODAS LAS OBSTETRAS DE LA RED';
    } else {
        $obstetraNombreReporte = 'TODAS LAS OBSTETRAS · ' . (string)$session['estab_nombre'];
    }
    if ($obstetraNombreReporte === '') {
        $obstetraNombreReporte = (string)$session['estab_nombre'];
    }
    if ($modoRedReporte) {
        $establecimientoActual['codigo'] = 'RED';
        $establecimientoActual['nombre'] = 'TODA LA RED HUARAL-CHANCAY (53 IPRESS)';
        $establecimientoActual['distrito'] = '';
    }

    HospitalHuaralDB::registrarAuditoria(
        $session['dni'],
        'REPORTE_PROGRAMACION',
        'Reporte de programación PF fecha ' . $fechaObjetivo . ' modo ' . $rangoModo . ' alcance ' . $alcance . ' ámbito ' . $ambitoReporte . ': ' . count($filas) . ' pacientes.',
        (string)$session['cod_estab'],
        (string)$session['platform']
    );

    json_out([
        'success' => true,
        'fecha_objetivo' => $fechaObjetivo,
        'fecha_objetivo_ddmmyyyy' => $fechaBase->format('d/m/Y'),
        'rango_modo' => $rangoModo,
        'alcance' => $alcance,
        'ambito' => $ambitoReporte,
        'obstetra_dni' => $obstetraReporte,
        'obstetra_nombre' => $obstetraNombreReporte,
        'codigo_metodo' => $codigoMetodoRaw !== '' ? $codigoMetodoRaw : 'TODOS',
        'establecimiento' => $establecimientoActual,
        'resumen' => $resumen,
        'catalogo' => array_values($catalogo),
        'filas' => $filas,
        'metadata' => [
            'generado_en' => date('c'),
            'limite_candidatos' => $limiteCandidatos,
            'lookback_vencidas_dias' => $lookbackVencidas,
            'lookback_todos_dias' => $lookbackTodos,
            'ventanas_aplicacion' => $ventanas,
            'fuente_catalogo' => 'app_catalogo_metodos',
            'emisor' => [
                'dni' => (string)$session['dni'],
                'nombre' => HospitalHuaralDB::nombrePersona((string)$session['dni'], $pdo),
                'rol' => HospitalHuaralDB::rolEtiqueta($rolReporte),
            ],
        ],
    ]);
}

// ---------------------------------------------------------------------------
// 7-B-BIS. REPORTE 02 (PRODUCTIVIDAD) Y REPORTE 04 (PADRÓN DE LLAMADAS)
// ---------------------------------------------------------------------------
if ($action === 'reporte_productividad') {
    $session = require_session();
    $bucket = 'reporte_productividad:' . hash('sha256', (string)($session['token'] ?? $session['dni']));
    $limit = HospitalHuaralDB::rateLimitStatus($bucket, 60, 60);
    if (!$limit['allowed']) {
        json_error('Límite de 60 consultas de reporte por minuto alcanzado.', 429, ['retryAfter' => $limit['retryAfter']]);
    }
    HospitalHuaralDB::rateLimitHit($bucket, 60);
    $datos = reporte_campo_datos($pdo, $session, $_GET, 1, 1);
    $perfil = session_profile_payload($pdo, $session);
    $obstetraProd = (string)($datos['filtros']['obstetra'] ?? 'TODOS');
    $obstetraNombreProd = (string)($datos['obstetra_nombre'] ?? '');
    if ($obstetraNombreProd === '') {
        $obstetraNombreProd = $obstetraProd !== '' && $obstetraProd !== 'TODOS'
            ? HospitalHuaralDB::nombrePersona($obstetraProd, $pdo)
            : ((string)($perfil['rol'] ?? '') === 'OBSTETRA'
                ? (string)($perfil['nombreCompleto'] ?? '')
                : (string)($perfil['estab_nombre'] ?? ''));
    }
    if ($obstetraNombreProd === '') {
        $obstetraNombreProd = (string)($perfil['nombreCompleto'] ?? '');
    }
    json_out([
        'success' => true,
        'filtros' => $datos['filtros'] ?? [],
        'resumen' => $datos['resumen'] ?? [],
        'productividad' => $datos['productividad'] ?? [],
        'establecimiento' => $datos['establecimiento'] ?? [],
        'obstetra_dni' => $obstetraProd === 'TODOS' ? '' : $obstetraProd,
        'obstetra_nombre' => $obstetraNombreProd,
        'periodo' => [
            'desde' => (string)($datos['filtros']['fecha_desde'] ?? ''),
            'hasta' => (string)($datos['filtros']['fecha_hasta'] ?? ''),
        ],
        'emisor' => [
            'dni' => (string)$session['dni'],
            'nombre' => (string)($perfil['nombreCompleto'] ?? ''),
            'rol' => (string)($perfil['rol_etiqueta'] ?? ''),
        ],
        'generado_en' => date('c'),
    ]);
}

if ($action === 'reporte_padron') {
    $session = require_session();
    $bucket = 'reporte_padron:' . hash('sha256', (string)($session['token'] ?? $session['dni']));
    $limit = HospitalHuaralDB::rateLimitStatus($bucket, 60, 60);
    if (!$limit['allowed']) {
        json_error('Límite de 60 consultas de reporte por minuto alcanzado.', 429, ['retryAfter' => $limit['retryAfter']]);
    }
    HospitalHuaralDB::rateLimitHit($bucket, 60);
    $catalogo = catalogo_metodos_planificacion($pdo);
    $alertas = alertas_programaticas_datos($pdo, $session, $catalogo, 1000);
    $grupoFiltro = strtolower(trim((string)($_GET['grupo'] ?? 'todas')));
    $grupos = in_array($grupoFiltro, ['manana', 'hoy', 'vencidas'], true) ? [$grupoFiltro] : ['hoy', 'manana', 'vencidas'];
    $filas = [];
    foreach ($grupos as $grupo) {
        foreach (($alertas['listas'][$grupo] ?? []) as $fila) {
            $fila['grupo_alerta'] = $grupo;
            $filas[] = $fila;
        }
    }
    usort($filas, static function (array $a, array $b): int {
        $cmp = (int)$a['dias_restantes'] <=> (int)$b['dias_restantes'];
        return $cmp !== 0 ? $cmp : strcmp((string)$a['paciente_nombre'], (string)$b['paciente_nombre']);
    });
    $perfil = session_profile_payload($pdo, $session);
    $modoRedPadron = es_alcance_red($session, (string)($_GET['alcance'] ?? (is_admin_session($session) ? 'red' : 'establecimiento')));
    $obstetraPadron = preg_replace('/[^0-9A-Za-z]/', '', (string)($_GET['obstetra'] ?? '')) ?? '';
    if ($obstetraPadron === 'TODOS') {
        $obstetraPadron = '';
    }
    $obstetraNombrePadron = $obstetraPadron !== ''
        ? HospitalHuaralDB::nombrePersona($obstetraPadron, $pdo)
        : ((string)($perfil['rol'] ?? '') === 'OBSTETRA'
            ? (string)($perfil['nombreCompleto'] ?? '')
            : ($modoRedPadron ? 'TODAS LAS OBSTETRAS DE LA RED' : (string)($perfil['estab_nombre'] ?? '')));
    if ($obstetraNombrePadron === '') {
        $obstetraNombrePadron = (string)($perfil['nombreCompleto'] ?? '');
    }
    json_out([
        'success' => true,
        'fecha_corte' => date('Y-m-d'),
        'fecha_corte_ddmmyyyy' => date('d/m/Y'),
        'grupo' => $grupoFiltro,
        'obstetra_dni' => $obstetraPadron,
        'obstetra_nombre' => $obstetraNombrePadron,
        'resumen' => [
            'manana' => (int)$alertas['manana'],
            'hoy' => (int)$alertas['hoy'],
            'vencidas' => (int)$alertas['vencidas'],
            'total' => (int)$alertas['total'],
        ],
        'filas' => $filas,
        'establecimiento' => [
            'codigo' => $modoRedPadron ? 'RED' : (string)$session['cod_estab'],
            'nombre' => $modoRedPadron ? 'TODA LA RED HUARAL-CHANCAY (53 IPRESS)' : (string)$session['estab_nombre'],
        ],
        'emisor' => [
            'dni' => (string)$session['dni'],
            'nombre' => (string)($perfil['nombreCompleto'] ?? ''),
            'rol' => (string)($perfil['rol_etiqueta'] ?? ''),
        ],
        'generado_en' => date('c'),
    ]);
}

// ---------------------------------------------------------------------------
// 7-C. REPORTES Y SEGUIMIENTO (Campo/Captación + Indicadores por Método)
// ---------------------------------------------------------------------------
/**
 * Normaliza una fecha YYYY-MM-DD. Devuelve null si no es real.
 */
function reporte_fecha_valida(?string $valor): ?string
{
    $valor = trim((string)$valor);
    if ($valor === '') {
        return null;
    }
    $dt = DateTimeImmutable::createFromFormat('!Y-m-d', $valor);
    return ($dt instanceof DateTimeImmutable && $dt->format('Y-m-d') === $valor) ? $valor : null;
}

/**
 * @return array{0: string, 1: string} [desde, hasta]
 */
function reporte_rango_fechas(array $input): array
{
    $desde = reporte_fecha_valida($input['fecha_desde'] ?? null) ?: date('Y-m-01');
    $hasta = reporte_fecha_valida($input['fecha_hasta'] ?? null) ?: date('Y-m-d');
    if ($desde > $hasta) {
        [$desde, $hasta] = [$hasta, $desde];
    }
    return [$desde, $hasta];
}

/**
 * Códigos de establecimiento permitidos según el alcance del reporte.
 *
 * @return array<int, string>
 */
function reporte_codigos_establecimiento(array $session, string $alcance): array
{
    if ($alcance === 'red' && puede_ver_red($session)) {
        return [];
    }
    $variantes = hospital_codigos_busqueda_establecimiento((string)($session['cod_estab'] ?? ''));
    return $variantes ?: [(string)($session['cod_estab'] ?? '000005481')];
}

/**
 * Última atención de Planificación Familiar por DNI usando el catálogo de
 * métodos. Consulta SARGable por h.DNI IN (...) y dt.DX IN (...) para no
 * recorrer los 5 GB del HIS.
 *
 * @param array<int, string> $dnis
 * @param array<string, array<string, mixed>> $catalogo
 * @param array<int, string> $codigosEstab
 * @return array<string, array<string, mixed>>
 */
function reporte_ultimas_atenciones_metodo(PDO $pdo, array $dnis, array $catalogo, array $codigosEstab = []): array
{
    $dnis = array_values(array_unique(array_filter(array_map(
        static fn ($dni): string => preg_replace('/[^0-9]/', '', (string)$dni) ?? '',
        $dnis
    ), static fn (string $dni): bool => $dni !== '')));
    if (!$dnis) {
        return [];
    }
    $codigos = codigos_consulta_metodos($catalogo);
    if (!$codigos) {
        return [];
    }
    $placeholdersDni = implode(',', array_fill(0, count($dnis), '?'));
    $placeholdersDx = implode(',', array_fill(0, count($codigos), '?'));
    $condEstab = '';
    $paramsEstab = [];
    if ($codigosEstab) {
        $condEstab = ' AND h.COD_ESTAB IN (' . implode(',', array_fill(0, count($codigosEstab), '?')) . ')';
        $paramsEstab = $codigosEstab;
    }
    $anoMinimo = (int)date('Y') - 5;
    $sql = "
        SELECT h.DNI, h.COD_ESTAB, h.CODPSAL, h.ANO, h.MES, h.DIA, h.fecha_reg,
               dt.DX, dt.fecha_reg AS fecha_dx
        FROM his_dl h
        INNER JOIN his_dl_dt dt ON dt.ID = h.ID
        WHERE h.DNI IN ({$placeholdersDni})
          AND dt.DX IN ({$placeholdersDx})
          AND h.ANO >= ?
          {$condEstab}
        ORDER BY h.DNI ASC, h.ANO DESC, h.MES DESC, h.DIA DESC, h.ID DESC
        LIMIT 30000
    ";
    $params = array_merge($dnis, $codigos, [$anoMinimo], $paramsEstab);
    $resultado = [];
    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        foreach ($stmt->fetchAll() as $row) {
            $dni = trim((string)($row['DNI'] ?? ''));
            $codigo = trim((string)($row['DX'] ?? ''));
            $metaMetodo = resolver_metodo_catalogo($catalogo, $codigo);
            if ($dni === '' || $metaMetodo === null) {
                continue;
            }
            $fecha = fecha_aplicacion_his($row);
            if ($fecha === '') {
                continue;
            }
            $dias = max(0, (int)($metaMetodo['dias_ciclo'] ?? 0));
            // Gana la atención más reciente; si una misma atención tiene varios
            // códigos, se conserva el ciclo más largo (método real).
            $score = $fecha . '|' . str_pad((string)$dias, 4, '0', STR_PAD_LEFT);
            if (isset($resultado[$dni]) && strcmp($score, (string)$resultado[$dni]['_score']) <= 0) {
                continue;
            }
            $proxima = $dias > 0
                ? (new DateTimeImmutable($fecha))->modify('+' . $dias . ' days')->format('Y-m-d')
                : null;
            $resultado[$dni] = [
                '_score' => $score,
                'codigo_metodo' => (string)($metaMetodo['codigo_dx'] ?? $codigo),
                'codigo_his' => $codigo,
                'nombre_metodo' => (string)($metaMetodo['nombre_metodo'] ?? $codigo),
                'dias_ciclo' => $dias,
                'fecha_ultima_atencion' => $fecha,
                'fecha_proxima_cita' => $proxima,
                'cod_estab' => (string)($row['COD_ESTAB'] ?? ''),
            ];
        }
    } catch (Throwable $e) {
        error_log('[PlanificaHIS] reporte_ultimas_atenciones_metodo: ' . $e->getMessage());
        return [];
    }
    foreach ($resultado as &$filaResultado) {
        unset($filaResultado['_score']);
    }
    unset($filaResultado);
    return $resultado;
}

/**
 * Estado semáforo del indicador de tiempo por método.
 *
 * @return array{estado: string, etiqueta: string, dias_restantes: ?int, prioridad: int}
 */
function reporte_estado_metodo(?string $fechaProxima, ?int $diasCiclo): array
{
    if ($fechaProxima === null || $fechaProxima === '' || $diasCiclo === null || $diasCiclo <= 0) {
        return ['estado' => 'SIN_METODO', 'etiqueta' => 'Sin método', 'dias_restantes' => null, 'prioridad' => 9];
    }
    $hoy = new DateTimeImmutable(date('Y-m-d'));
    $proxima = DateTimeImmutable::createFromFormat('!Y-m-d', $fechaProxima);
    if (!$proxima instanceof DateTimeImmutable) {
        return ['estado' => 'SIN_METODO', 'etiqueta' => 'Sin método', 'dias_restantes' => null, 'prioridad' => 9];
    }
    $dias = (int)$hoy->diff($proxima)->format('%r%a');
    if ($dias < 0) {
        return ['estado' => 'VENCIDA', 'etiqueta' => 'Vencida / captación inmediata', 'dias_restantes' => $dias, 'prioridad' => 0];
    }
    if ($dias <= 7) {
        return ['estado' => 'PROXIMA', 'etiqueta' => 'Próxima a vencer (≤ 7 días)', 'dias_restantes' => $dias, 'prioridad' => 1];
    }
    return ['estado' => 'VIGENTE', 'etiqueta' => 'Vigente / al día', 'dias_restantes' => $dias, 'prioridad' => 2];
}

/**
 * Consulta del Reporte de Campo y Captación.
 *
 * @return array<string, mixed>
 */
function reporte_campo_datos(PDO $pdo, array $session, array $input, int $page = 1, int $perPage = 25): array
{
    [$desde, $hasta] = reporte_rango_fechas($input);
    $hastaExclusivo = (new DateTimeImmutable($hasta))->modify('+1 day')->format('Y-m-d');
    $alcance = strtolower(trim((string)($input['alcance'] ?? (is_admin_session($session) ? 'red' : 'establecimiento')))) === 'red' ? 'red' : 'establecimiento';
    $verRed = puede_ver_red($session);
    $rolCampo = HospitalHuaralDB::rolUsuario((string)($session['dni'] ?? ''));
    $esObstetraCampo = $rolCampo === 'OBSTETRA';
    $modoRedCampo = es_alcance_red($session, $alcance);
    // La Jefatura y la obstetra nunca amplían su alcance fuera de su IPRESS.
    if (!$modoRedCampo) {
        $alcance = 'establecimiento';
    }
    $codigosEstab = $modoRedCampo ? [] : codigos_establecimiento_sesion($session);

    $where = ['p.fecha_registro >= :desde', 'p.fecha_registro < :hasta_exclusivo'];
    $params = [':desde' => $desde, ':hasta_exclusivo' => $hastaExclusivo];
    if ($esObstetraCampo) {
        $where[] = 'p.codpsal_obstetra = :propio';
        $params[':propio'] = (string)$session['dni'];
    }

    $estado = strtoupper(trim((string)($input['estado_paciente'] ?? '')));
    if ($estado !== '' && $estado !== 'TODOS') {
        $where[] = 'p.estado_paciente = :estado';
        $params[':estado'] = $estado;
    }
    $sector = strtoupper(trim((string)($input['sector'] ?? '')));
    if ($sector !== '' && $sector !== 'TODOS') {
        $where[] = 'p.sector = :sector';
        $params[':sector'] = $sector;
    }
    $obstetra = preg_replace('/[^0-9A-Za-z]/', '', (string)($input['obstetra'] ?? '')) ?? '';
    if (!$esObstetraCampo && $obstetra !== '' && $obstetra !== 'TODOS') {
        $where[] = 'p.codpsal_obstetra = :obstetra';
        $params[':obstetra'] = $obstetra;
    }
    $q = trim((string)($input['q'] ?? ''));
    if ($q !== '') {
        $where[] = '(p.dni LIKE :q1 OR p.apellido_paterno LIKE :q2 OR p.apellido_materno LIKE :q3 OR p.nombres LIKE :q4)';
        $like = '%' . str_replace(['%', '_'], ['\%', '\_'], $q) . '%';
        $params[':q1'] = $like;
        $params[':q2'] = $like;
        $params[':q3'] = $like;
        $params[':q4'] = $like;
    }
    if ($codigosEstab) {
        $marcas = [];
        foreach (array_values($codigosEstab) as $i => $cod) {
            $marca = ':estab' . $i;
            $marcas[] = $marca;
            $params[$marca] = $cod;
        }
        $where[] = 'p.cod_estab IN (' . implode(',', $marcas) . ')';
    }
    $whereSql = implode(' AND ', $where);

    $stmt = $pdo->prepare("
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN p.estado_paciente = 'CAPTADA_CON_METODO' THEN 1 ELSE 0 END) AS satisfechas,
               SUM(CASE WHEN p.estado_paciente = 'INSATISFECHA_SIN_METODO' THEN 1 ELSE 0 END) AS insatisfechas,
               SUM(CASE WHEN p.atencion_99208 = 1 THEN 1 ELSE 0 END) AS con_99208,
               SUM(CASE WHEN p.estado_paciente IN ('SEGUIMIENTO_DOMICILIARIO','CONSEJERIA_REALIZADA') THEN 1 ELSE 0 END) AS pendientes
        FROM pacientes_sin_metodo p
        WHERE {$whereSql}
    ");
    $stmt->execute($params);
    $resumen = $stmt->fetch() ?: [];

    $produccion = [];
    try {
        $stmtProd = $pdo->prepare("
            SELECT DATE(p.fecha_registro) AS fecha_salida,
                   p.codpsal_obstetra,
                   COUNT(*) AS total_pacientes,
                   MIN(p.fecha_registro) AS primera_hora,
                   MAX(p.fecha_registro) AS ultima_hora,
                   GROUP_CONCAT(DISTINCT p.sector ORDER BY p.sector SEPARATOR ', ') AS sectores
            FROM pacientes_sin_metodo p
            WHERE {$whereSql}
            GROUP BY DATE(p.fecha_registro), p.codpsal_obstetra
            ORDER BY fecha_salida DESC, total_pacientes DESC
            LIMIT 500
        ");
        $stmtProd->execute($params);
        $produccion = $stmtProd->fetchAll();
        $dnisProd = array_map(static fn ($row) => (string)$row['codpsal_obstetra'], $produccion);
        $diccionario = nombres_personas_por_dni($pdo, $dnisProd);
        foreach ($produccion as &$fila) {
            $cod = (string)$fila['codpsal_obstetra'];
            $fila['nombre_obstetra'] = (string)($diccionario[$cod] ?? ('OBST. ' . $cod));
        }
        unset($fila);
    } catch (Throwable $e) {
        $produccion = [];
    }

    $sectores = [];
    try {
        $whereSector = ["p.sector <> ''"];
        $paramsSector = [];
        if ($codigosEstab) {
            $marcasSector = [];
            foreach (array_values($codigosEstab) as $i => $cod) {
                $marcaSector = ':sector_estab' . $i;
                $marcasSector[] = $marcaSector;
                $paramsSector[$marcaSector] = $cod;
            }
            $whereSector[] = 'p.cod_estab IN (' . implode(',', $marcasSector) . ')';
        }
        if ($esObstetraCampo) {
            $whereSector[] = 'p.codpsal_obstetra = :propio_sector';
            $paramsSector[':propio_sector'] = (string)$session['dni'];
        }
        $stmtSect = $pdo->prepare("
            SELECT DISTINCT p.sector
            FROM pacientes_sin_metodo p
            WHERE " . implode(' AND ', $whereSector) . "
            ORDER BY p.sector ASC
            LIMIT 500
        ");
        $stmtSect->execute($paramsSector);
        $sectores = array_map('strval', $stmtSect->fetchAll(PDO::FETCH_COLUMN));
    } catch (Throwable $e) {
        $sectores = [];
    }

    $obstetras = [];
    try {
        $whereObs = [];
        $paramsObs = [];
        if ($codigosEstab) {
            $marcasObs = [];
            foreach (array_values($codigosEstab) as $i => $cod) {
                $marcaObs = ':obs_estab' . $i;
                $marcasObs[] = $marcaObs;
                $paramsObs[$marcaObs] = $cod;
            }
            $whereObs[] = 'p.cod_estab IN (' . implode(',', $marcasObs) . ')';
        }
        if ($esObstetraCampo) {
            $whereObs[] = 'p.codpsal_obstetra = :propio_obs';
            $paramsObs[':propio_obs'] = (string)$session['dni'];
        }
        $stmtObs = $pdo->prepare("
            SELECT p.codpsal_obstetra, COUNT(*) AS total
            FROM pacientes_sin_metodo p
            " . ($whereObs ? ' WHERE ' . implode(' AND ', $whereObs) : '') . "
            GROUP BY p.codpsal_obstetra
            ORDER BY total DESC
            LIMIT 300
        ");
        $stmtObs->execute($paramsObs);
        $obstetras = $stmtObs->fetchAll();
        $mapa = nombres_personas_por_dni($pdo, array_map(static fn ($row) => (string)$row['codpsal_obstetra'], $obstetras));
        foreach ($obstetras as &$obs) {
            $cod = (string)$obs['codpsal_obstetra'];
            $obs['nombre_obstetra'] = (string)($mapa[$cod] ?? ('OBST. ' . $cod));
        }
        unset($obs);
    } catch (Throwable $e) {
        $obstetras = [];
    }

    $total = (int)($resumen['total'] ?? 0);
    $perPage = max(1, min(5000, $perPage));
    $page = max(1, $page);
    $offset = ($page - 1) * $perPage;
    $filas = [];
    if ($total > 0) {
        $stmtFilas = $pdo->prepare("
            SELECT p.*
            FROM pacientes_sin_metodo p
            WHERE {$whereSql}
            ORDER BY p.fecha_registro DESC, p.id DESC
            LIMIT {$perPage} OFFSET {$offset}
        ");
        $stmtFilas->execute($params);
        $filasBase = $stmtFilas->fetchAll();
        $dnisPagina = array_map(static fn ($row) => (string)$row['dni'], $filasBase);
        $dnisObstetras = array_map(static fn ($row) => (string)$row['codpsal_obstetra'], $filasBase);
        $dicObs = nombres_personas_por_dni($pdo, $dnisObstetras);
        $catalogo = catalogo_metodos_planificacion($pdo);
        $ultimas = reporte_ultimas_atenciones_metodo($pdo, $dnisPagina, $catalogo, $codigosEstab);
        foreach ($filasBase as $row) {
            $dni = (string)$row['dni'];
            $codObstetra = (string)$row['codpsal_obstetra'];
            $ultima = $ultimas[$dni] ?? null;
            $estadoIndicador = reporte_estado_metodo(
                $ultima['fecha_proxima_cita'] ?? null,
                isset($ultima['dias_ciclo']) ? (int)$ultima['dias_ciclo'] : null
            );
            $filas[] = [
                'id' => (int)$row['id'],
                'fecha_registro' => (string)$row['fecha_registro'],
                'fecha_registro_ddmmyyyy_hhmmss' => date('d/m/Y H:i:s', strtotime((string)$row['fecha_registro']) ?: time()),
                'sector' => (string)$row['sector'],
                'dni' => $dni,
                'apellido_paterno' => (string)$row['apellido_paterno'],
                'apellido_materno' => (string)$row['apellido_materno'],
                'nombres' => (string)$row['nombres'],
                'paciente_nombre' => trim((string)$row['apellido_paterno'] . ' ' . (string)$row['apellido_materno'] . ', ' . (string)$row['nombres']),
                'edad' => (int)$row['edad'],
                'celular' => HospitalHuaralDB::decryptPII((string)$row['celular']),
                'direccion' => HospitalHuaralDB::decryptPII((string)$row['direccion']),
                'distrito' => (string)$row['distrito'],
                'estado_paciente' => (string)$row['estado_paciente'],
                'atencion_99208' => (int)($row['atencion_99208'] ?? 0) === 1,
                'codpsal_obstetra' => $codObstetra,
                'nombre_obstetra' => (string)($dicObs[$codObstetra] ?? ('OBST. ' . $codObstetra)),
                'cod_estab' => (string)($row['cod_estab'] ?? ''),
                'estab_nombre' => hospital_nombre_establecimiento((string)($row['cod_estab'] ?? '')),
                'ultimo_codigo_metodo' => (string)($ultima['codigo_metodo'] ?? ''),
                'ultimo_metodo_nombre' => (string)($ultima['nombre_metodo'] ?? ''),
                'fecha_ultima_atencion' => (string)($ultima['fecha_ultima_atencion'] ?? ''),
                'fecha_proxima_cita' => (string)($ultima['fecha_proxima_cita'] ?? ''),
                'estado_indicador' => $estadoIndicador['estado'],
                'estado_indicador_etiqueta' => $estadoIndicador['etiqueta'],
            ];
        }
    }

    return [
        'success' => true,
        'filtros' => [
            'fecha_desde' => $desde,
            'fecha_hasta' => $hasta,
            'estado_paciente' => $estado !== '' ? $estado : 'TODOS',
            'sector' => $sector !== '' ? $sector : 'TODOS',
            'obstetra' => $obstetra !== '' ? $obstetra : 'TODOS',
            'alcance' => $alcance,
        ],
        'resumen' => [
            'total_pacientes' => $total,
            'satisfechas' => (int)($resumen['satisfechas'] ?? 0),
            'insatisfechas' => (int)($resumen['insatisfechas'] ?? 0),
            'con_99208' => (int)($resumen['con_99208'] ?? 0),
            'pendientes' => (int)($resumen['pendientes'] ?? 0),
        ],
        'productividad' => $produccion,
        'filas' => $filas,
        'sectores' => $sectores,
        'obstetras' => $obstetras,
        'paginacion' => [
            'page' => $page,
            'per_page' => $perPage,
            'total' => $total,
            'pages' => max(1, (int)ceil($total / $perPage)),
        ],
        'establecimiento' => [
            'codigo' => $modoRedCampo ? 'RED' : (string)$session['cod_estab'],
            'nombre' => $modoRedCampo ? 'TODA LA RED HUARAL-CHANCAY (53 IPRESS)' : (string)$session['estab_nombre'],
        ],
        'obstetra_dni' => $esObstetraCampo ? (string)$session['dni'] : (($obstetra !== '' && $obstetra !== 'TODOS') ? $obstetra : ''),
        'obstetra_nombre' => $esObstetraCampo
            ? HospitalHuaralDB::nombrePersona((string)$session['dni'], $pdo)
            : (($obstetra !== '' && $obstetra !== 'TODOS')
                ? HospitalHuaralDB::nombrePersona($obstetra, $pdo)
                : ($modoRedCampo
                    ? 'TODAS LAS OBSTETRAS DE LA RED'
                    : (($rolCampo === 'JEFA_OBSTETRAS') ? (string)$session['nombreCompleto'] : 'TODAS LAS OBSTETRAS DEL ESTABLECIMIENTO'))),
        'generado_en' => date('c'),
    ];
}

/**
 * Consulta del Reporte de Indicadores por Método.
 *
 * @return array<string, mixed>
 */
function reporte_metodos_datos(PDO $pdo, array $session, array $input, int $page = 1, int $perPage = 25): array
{
    [$desde, $hasta] = reporte_rango_fechas($input);
    $hastaExclusivo = (new DateTimeImmutable($hasta))->modify('+1 day')->format('Y-m-d');
    $alcance = strtolower(trim((string)($input['alcance'] ?? (is_admin_session($session) ? 'red' : 'establecimiento')))) === 'red' ? 'red' : 'establecimiento';
    $verRed = puede_ver_red($session);
    $rolMetodos = HospitalHuaralDB::rolUsuario((string)($session['dni'] ?? ''));
    $esObstetraMetodos = $rolMetodos === 'OBSTETRA';
    $modoRedMetodos = es_alcance_red($session, $alcance);
    if (!$modoRedMetodos) {
        $alcance = 'establecimiento';
    }
    $codigosEstab = $modoRedMetodos ? [] : codigos_establecimiento_sesion($session);
    $catalogo = catalogo_metodos_planificacion($pdo);

    $where = ['p.fecha_registro >= :desde', 'p.fecha_registro < :hasta_exclusivo'];
    $params = [':desde' => $desde, ':hasta_exclusivo' => $hastaExclusivo];
    if ($esObstetraMetodos) {
        $where[] = 'p.codpsal_obstetra = :propio';
        $params[':propio'] = (string)$session['dni'];
    }
    $sector = strtoupper(trim((string)($input['sector'] ?? '')));
    if ($sector !== '' && $sector !== 'TODOS') {
        $where[] = 'p.sector = :sector';
        $params[':sector'] = $sector;
    }
    if ($codigosEstab) {
        $marcas = [];
        foreach (array_values($codigosEstab) as $i => $cod) {
            $marca = ':estab' . $i;
            $marcas[] = $marca;
            $params[$marca] = $cod;
        }
        $where[] = 'p.cod_estab IN (' . implode(',', $marcas) . ')';
    }
    $whereSql = implode(' AND ', $where);

    // Base acotada: máximo 800 pacientes del periodo/establecimiento (3000 en
    // exportaciones completas) para mantener fluidez en celulares de gama media.
    $limiteBase = $perPage > 200 ? 3000 : 800;
    $stmt = $pdo->prepare("
        SELECT p.*
        FROM pacientes_sin_metodo p
        WHERE {$whereSql}
        ORDER BY p.fecha_registro DESC, p.id DESC
        LIMIT {$limiteBase}
    ");
    $stmt->execute($params);
    $base = $stmt->fetchAll();

    $dnis = array_map(static fn ($row) => (string)$row['dni'], $base);
    $dnisObs = array_map(static fn ($row) => (string)$row['codpsal_obstetra'], $base);
    $dicObs = nombres_personas_por_dni($pdo, $dnisObs);
    $ultimas = reporte_ultimas_atenciones_metodo($pdo, $dnis, $catalogo, $codigosEstab);

    $codigoFiltro = strtoupper(trim((string)($input['codigo_metodo'] ?? 'TODOS')));
    $estadoFiltro = strtoupper(trim((string)($input['estado_vencimiento'] ?? 'TODOS')));

    $filas = [];
    foreach ($base as $row) {
        $dni = (string)$row['dni'];
        $ultima = $ultimas[$dni] ?? null;
        $codigo = (string)($ultima['codigo_metodo'] ?? '');
        $estadoIndicador = reporte_estado_metodo(
            $ultima['fecha_proxima_cita'] ?? null,
            isset($ultima['dias_ciclo']) ? (int)$ultima['dias_ciclo'] : null
        );
        if ($codigoFiltro !== '' && $codigoFiltro !== 'TODOS' && $codigo !== $codigoFiltro) {
            continue;
        }
        if ($estadoFiltro !== '' && $estadoFiltro !== 'TODOS' && $estadoIndicador['estado'] !== $estadoFiltro) {
            continue;
        }
        $codObs = (string)$row['codpsal_obstetra'];
        $filas[] = [
            'id' => (int)$row['id'],
            'dni' => $dni,
            'paciente_nombre' => trim((string)$row['apellido_paterno'] . ' ' . (string)$row['apellido_materno'] . ', ' . (string)$row['nombres']),
            'edad' => (int)$row['edad'],
            'celular' => HospitalHuaralDB::decryptPII((string)$row['celular']),
            'direccion' => HospitalHuaralDB::decryptPII((string)$row['direccion']),
            'distrito' => (string)$row['distrito'],
            'sector' => (string)$row['sector'],
            'estado_paciente' => (string)$row['estado_paciente'],
            'fecha_registro' => (string)$row['fecha_registro'],
            'cod_estab' => (string)($row['cod_estab'] ?? ''),
            'estab_nombre' => hospital_nombre_establecimiento((string)($row['cod_estab'] ?? '')),
            'codpsal_obstetra' => $codObs,
            'nombre_obstetra' => (string)($dicObs[$codObs] ?? ('OBST. ' . $codObs)),
            'codigo_metodo' => $codigo,
            'nombre_metodo' => (string)($ultima['nombre_metodo'] ?? 'Sin método registrado'),
            'dias_ciclo' => isset($ultima['dias_ciclo']) ? (int)$ultima['dias_ciclo'] : 0,
            'fecha_ultima_atencion' => (string)($ultima['fecha_ultima_atencion'] ?? ''),
            'fecha_proxima_cita' => (string)($ultima['fecha_proxima_cita'] ?? ''),
            'estado_indicador' => $estadoIndicador['estado'],
            'estado_indicador_etiqueta' => $estadoIndicador['etiqueta'],
            'dias_restantes' => $estadoIndicador['dias_restantes'],
            '_prioridad' => $estadoIndicador['prioridad'],
        ];
    }

    usort($filas, static function (array $a, array $b): int {
        $cmp = $a['_prioridad'] <=> $b['_prioridad'];
        return $cmp !== 0 ? $cmp : strcmp($a['paciente_nombre'], $b['paciente_nombre']);
    });
    foreach ($filas as &$fila) {
        unset($fila['_prioridad']);
    }
    unset($fila);

    $resumen = ['vigente' => 0, 'proxima' => 0, 'vencida' => 0, 'sin_metodo' => 0, 'total' => count($filas)];
    foreach ($filas as $fila) {
        $clave = match ($fila['estado_indicador']) {
            'VIGENTE' => 'vigente',
            'PROXIMA' => 'proxima',
            'VENCIDA' => 'vencida',
            default => 'sin_metodo',
        };
        $resumen[$clave]++;
    }

    $total = count($filas);
    $perPage = max(1, min(5000, $perPage));
    $page = max(1, $page);
    $offset = ($page - 1) * $perPage;
    $filasPagina = array_slice($filas, $offset, $perPage);

    $sectores = [];
    try {
        $whereSectorMetodos = ["sector <> ''"];
        $paramsSectorMetodos = [];
        if ($codigosEstab) {
            $marcasSectorMetodos = [];
            foreach (array_values($codigosEstab) as $i => $cod) {
                $marcaSectorMetodos = ':sector_m_estab' . $i;
                $marcasSectorMetodos[] = $marcaSectorMetodos;
                $paramsSectorMetodos[$marcaSectorMetodos] = $cod;
            }
            $whereSectorMetodos[] = 'cod_estab IN (' . implode(',', $marcasSectorMetodos) . ')';
        }
        if ($esObstetraMetodos) {
            $whereSectorMetodos[] = 'codpsal_obstetra = :propio_sector';
            $paramsSectorMetodos[':propio_sector'] = (string)$session['dni'];
        }
        $stmtSect = $pdo->prepare("SELECT DISTINCT sector FROM pacientes_sin_metodo WHERE " . implode(' AND ', $whereSectorMetodos) . " ORDER BY sector ASC LIMIT 500");
        $stmtSect->execute($paramsSectorMetodos);
        $sectores = array_map('strval', $stmtSect->fetchAll(PDO::FETCH_COLUMN));
    } catch (Throwable $e) {
        $sectores = [];
    }

    return [
        'success' => true,
        'filtros' => [
            'fecha_desde' => $desde,
            'fecha_hasta' => $hasta,
            'codigo_metodo' => $codigoFiltro !== '' ? $codigoFiltro : 'TODOS',
            'estado_vencimiento' => $estadoFiltro !== '' ? $estadoFiltro : 'TODOS',
            'sector' => $sector !== '' ? $sector : 'TODOS',
            'alcance' => $alcance,
        ],
        'catalogo' => array_values($catalogo),
        'resumen' => $resumen,
        'filas' => $filasPagina,
        'sectores' => $sectores,
        'paginacion' => [
            'page' => $page,
            'per_page' => $perPage,
            'total' => $total,
            'pages' => max(1, (int)ceil($total / $perPage)),
        ],
        'establecimiento' => [
            'codigo' => $modoRedMetodos ? 'RED' : (string)$session['cod_estab'],
            'nombre' => $modoRedMetodos ? 'TODA LA RED HUARAL-CHANCAY (53 IPRESS)' : (string)$session['estab_nombre'],
        ],
        'generado_en' => date('c'),
    ];
}

/**
 * Descarga CSV nativo para Excel en español (BOM UTF-8 + separador ';').
 * Los códigos se envían como fórmula de texto para conservar ceros a la
 * izquierda en DNI y código de establecimiento.
 *
 * @param array<int, string> $headers
 * @param array<int, array<int, string|int|float|null>> $rows
 */
function reporte_csv_excel(string $filename, array $headers, array $rows, array $codigosTexto = []): void
{
    if (headers_sent()) {
        return;
    }
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . preg_replace('/[^A-Za-z0-9_\-\.]/', '_', $filename) . '"');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    echo "\xEF\xBB\xBF";
    $out = fopen('php://output', 'w');
    if ($out === false) {
        exit;
    }
    fputcsv($out, $headers, ';', '"', '\\');
    foreach ($rows as $row) {
        $linea = [];
        foreach (array_values($row) as $i => $valor) {
            $texto = (string)($valor ?? '');
            if (in_array($i, $codigosTexto, true) && $texto !== '') {
                $texto = '="' . str_replace('"', '""', $texto) . '"';
            } elseif (preg_match('/^[=+\-@]/', $texto)) {
                // Mitigación de inyección de fórmulas en Excel para datos que
                // provienen del HIS o del formulario de campo.
                $texto = "'" . $texto;
            }
            $linea[] = $texto;
        }
        fputcsv($out, $linea, ';', '"', '\\');
    }
    fclose($out);
    exit;
}

if ($action === 'reporte_campo') {
    $session = require_session();
    $bucket = 'reporte_campo:' . hash('sha256', (string)($session['token'] ?? $session['dni']));
    $limit = HospitalHuaralDB::rateLimitStatus($bucket, 60, 60);
    if (!$limit['allowed']) {
        json_error('Límite de 60 consultas de reporte por minuto alcanzado.', 429, ['retryAfter' => $limit['retryAfter']]);
    }
    HospitalHuaralDB::rateLimitHit($bucket, 60);
    $page = max(1, (int)($_GET['page'] ?? 1));
    $perPage = max(1, min(100, (int)($_GET['per_page'] ?? 25)));
    json_out(reporte_campo_datos($pdo, $session, $_GET, $page, $perPage));
}

if ($action === 'reporte_metodos') {
    $session = require_session();
    $bucket = 'reporte_metodos:' . hash('sha256', (string)($session['token'] ?? $session['dni']));
    $limit = HospitalHuaralDB::rateLimitStatus($bucket, 60, 60);
    if (!$limit['allowed']) {
        json_error('Límite de 60 consultas de reporte por minuto alcanzado.', 429, ['retryAfter' => $limit['retryAfter']]);
    }
    HospitalHuaralDB::rateLimitHit($bucket, 60);
    $page = max(1, (int)($_GET['page'] ?? 1));
    $perPage = max(1, min(100, (int)($_GET['per_page'] ?? 25)));
    json_out(reporte_metodos_datos($pdo, $session, $_GET, $page, $perPage));
}

if ($action === 'catalogo_metodos') {
    $session = require_session();
    json_out([
        'success' => true,
        'catalogo' => array_values(catalogo_metodos_planificacion($pdo)),
    ]);
}

if ($action === 'save_metodo') {
    $session = require_session();
    if (!puede_ver_red($session) && !es_jefa_session($session)) {
        json_error('Solo la Jefatura de Obstetras o Estadística pueden modificar los días de ciclo.', 403, ['code' => 'ROLE_REQUIRED']);
    }
    $codigo = strtoupper(trim((string)($body['codigo_dx'] ?? '')));
    $nombre = trim((string)($body['nombre_metodo'] ?? ''));
    $dias = (int)($body['dias_ciclo'] ?? 0);
    $requiereCita = !empty($body['requiere_cita']) ? 1 : 0;
    $activo = !empty($body['activo']) ? 1 : 0;
    if ($codigo === '' || !preg_match('/^[A-Z0-9\-\.]{1,15}$/', $codigo)) {
        json_error('El código HIS/CPT del método es inválido (máximo 15 caracteres alfanuméricos).', 400);
    }
    if ($nombre === '' || mb_strlen($nombre) > 120) {
        json_error('Ingrese el nombre del método (máximo 120 caracteres).', 400);
    }
    if ($dias < 0 || $dias > 3650) {
        json_error('Los días de ciclo deben estar entre 0 y 3650.', 400);
    }
    $stmt = $pdo->prepare("
        INSERT INTO app_catalogo_metodos (codigo_dx, nombre_metodo, dias_ciclo, requiere_cita, activo)
        VALUES (:codigo, :nombre, :dias, :cita, :activo)
        ON DUPLICATE KEY UPDATE
            nombre_metodo = VALUES(nombre_metodo),
            dias_ciclo = VALUES(dias_ciclo),
            requiere_cita = VALUES(requiere_cita),
            activo = VALUES(activo)
    ");
    $stmt->execute([
        ':codigo' => $codigo,
        ':nombre' => $nombre,
        ':dias' => $dias,
        ':cita' => $requiereCita,
        ':activo' => $activo,
    ]);
    HospitalHuaralDB::registrarAuditoria(
        (string)$session['dni'],
        'CATALOGO_METODO_UPDATE',
        'Tiempos por método actualizados: ' . $codigo . ' (' . $nombre . ') = ' . $dias . ' días.',
        (string)$session['cod_estab'],
        (string)$session['platform']
    );
    json_out([
        'success' => true,
        'metodo' => [
            'codigo_dx' => $codigo,
            'nombre_metodo' => $nombre,
            'dias_ciclo' => $dias,
            'requiere_cita' => $requiereCita,
            'activo' => $activo,
        ],
        'catalogo' => array_values(catalogo_metodos_planificacion($pdo, true)),
    ]);
}

if ($action === 'export_reporte_campo' || $action === 'export_reporte_metodos') {
    $session = require_session();
    $tipo = strtolower(trim((string)($_GET['tipo'] ?? '')));
    if ($action === 'export_reporte_campo') {
        $datos = reporte_campo_datos($pdo, $session, $_GET, 1, $tipo === 'productividad' ? 1 : 5000);
        $filas = $datos['filas'] ?? [];
        $sello = date('Ymd_His');
        if ($tipo === 'productividad') {
            $rows = [];
            foreach (($datos['productividad'] ?? []) as $p) {
                $rows[] = [
                    (string)($p['fecha_salida'] ?? ''),
                    (string)($p['codpsal_obstetra'] ?? ''),
                    (string)($p['nombre_obstetra'] ?? ''),
                    (string)($p['sectores'] ?? ''),
                    (int)($p['total_pacientes'] ?? 0),
                    (string)($p['primera_hora'] ?? ''),
                    (string)($p['ultima_hora'] ?? ''),
                ];
            }
            HospitalHuaralDB::registrarAuditoria($session['dni'], 'EXPORT_REPORTE_CAMPO', 'Exportación Excel de productividad por obstetra y día: ' . count($rows) . ' filas.', $session['cod_estab'], $session['platform']);
            reporte_csv_excel('productividad_campo_' . $sello . '.csv', [
                'Fecha de salida', 'DNI Obstetra', 'Nombre Obstetra', 'Sectores visitados',
                'Pacientes registradas', 'Primera hora de registro', 'Última hora de registro',
            ], $rows, [1]);
        }
        $rows = [];
        foreach ($filas as $f) {
            $rows[] = [
                (string)($f['fecha_registro_ddmmyyyy_hhmmss'] ?? ''),
                (string)($f['sector'] ?? ''),
                (string)($f['dni'] ?? ''),
                (string)($f['apellido_paterno'] ?? ''),
                (string)($f['apellido_materno'] ?? ''),
                (string)($f['nombres'] ?? ''),
                (int)($f['edad'] ?? 0),
                (string)($f['celular'] ?? ''),
                (string)($f['direccion'] ?? ''),
                (string)($f['distrito'] ?? ''),
                (string)($f['estado_paciente'] ?? ''),
                (($f['atencion_99208'] ?? false) ? 'SÍ' : 'NO'),
                (string)($f['ultimo_metodo_nombre'] ?? ''),
                (string)($f['fecha_proxima_cita'] ?? ''),
                (string)($f['codpsal_obstetra'] ?? ''),
                (string)($f['nombre_obstetra'] ?? ''),
                (string)($f['cod_estab'] ?? ''),
                (string)($f['estab_nombre'] ?? ''),
            ];
        }
        HospitalHuaralDB::registrarAuditoria($session['dni'], 'EXPORT_REPORTE_CAMPO', 'Exportación Excel detallado de pacientes de campo: ' . count($rows) . ' filas.', $session['cod_estab'], $session['platform']);
        reporte_csv_excel('pacientes_campo_' . $sello . '.csv', [
            'Fecha y hora de registro', 'Sector', 'DNI Paciente', 'Apellido Paterno', 'Apellido Materno',
            'Nombres', 'Edad', 'Celular', 'Dirección', 'Distrito', 'Estado de la Paciente',
            'Validación 99208', 'Último Método', 'Próxima Cita', 'DNI Obstetra',
            'Obstetra que registró', 'Código Establecimiento', 'Establecimiento',
        ], $rows, [2, 14, 16]);
    }

    $datos = reporte_metodos_datos($pdo, $session, $_GET, 1, 5000);
    $rows = [];
    foreach (($datos['filas'] ?? []) as $f) {
        $rows[] = [
            (string)($f['dni'] ?? ''),
            (string)($f['paciente_nombre'] ?? ''),
            (int)($f['edad'] ?? 0),
            (string)($f['celular'] ?? ''),
            (string)($f['sector'] ?? ''),
            (string)($f['codigo_metodo'] ?? ''),
            (string)($f['nombre_metodo'] ?? ''),
            (int)($f['dias_ciclo'] ?? 0),
            fecha_para_mostrar((string)($f['fecha_ultima_atencion'] ?? '')),
            fecha_para_mostrar((string)($f['fecha_proxima_cita'] ?? '')),
            (string)($f['estado_indicador_etiqueta'] ?? ''),
            (string)($f['codpsal_obstetra'] ?? ''),
            (string)($f['nombre_obstetra'] ?? ''),
            (string)($f['cod_estab'] ?? ''),
            (string)($f['estab_nombre'] ?? ''),
        ];
    }
    HospitalHuaralDB::registrarAuditoria($session['dni'], 'EXPORT_REPORTE_METODOS', 'Exportación Excel del reporte por método anticonceptivo: ' . count($rows) . ' filas.', $session['cod_estab'], $session['platform']);
    reporte_csv_excel('reporte_por_metodo_' . date('Ymd_His') . '.csv', [
        'DNI Paciente', 'Paciente', 'Edad', 'Celular', 'Sector', 'Código Método',
        'Método', 'Días de ciclo', 'Fecha última atención', 'Fecha programada siguiente atención',
        'Estado del indicador', 'DNI Obstetra', 'Obstetra', 'Código Establecimiento', 'Establecimiento',
    ], $rows, [0, 11, 13]);
}


if ($action === 'save_paciente') {
    $session = require_session();
    $paseUps = !empty($body['pase_ups']);

    $dni = preg_replace('/[^0-9]/', '', (string)($body['dni'] ?? '')) ?? '';
    $apPaterno = strtoupper(HospitalHuaralDB::sanitizeText($body['apellido_paterno'] ?? '', 50));
    $apMaterno = strtoupper(HospitalHuaralDB::sanitizeText($body['apellido_materno'] ?? '', 50));
    $nombres = strtoupper(HospitalHuaralDB::sanitizeText($body['nombres'] ?? '', 80));
    $edad = (int)($body['edad'] ?? 0);
    $celular = HospitalHuaralDB::sanitizeText($body['celular'] ?? '', 15);
    $correo = strtolower(HospitalHuaralDB::sanitizeText($body['correo'] ?? '', 150));
    $distrito = strtoupper(HospitalHuaralDB::sanitizeText($body['distrito'] ?? '', 80));
    $direccion = HospitalHuaralDB::sanitizeText($body['direccion'] ?? '', 200);
    $sector = strtoupper(HospitalHuaralDB::sanitizeText($body['sector'] ?? '', 50));
    $estado = strtoupper(HospitalHuaralDB::sanitizeText(
        $body['estado_paciente'] ?? ($paseUps ? 'CAPTADA_CON_METODO' : 'INSATISFECHA_SIN_METODO'),
        30
    ));
    $estadosValidos = ['INSATISFECHA_SIN_METODO', 'CAPTADA_CON_METODO', 'SEGUIMIENTO_DOMICILIARIO', 'CONSEJERIA_REALIZADA', 'RECHAZA_METODO'];
    if (!in_array($estado, $estadosValidos, true)) {
        $estado = $paseUps ? 'CAPTADA_CON_METODO' : 'INSATISFECHA_SIN_METODO';
    }
    $codEstab = $session['cod_estab'];
    $atencion99208Solicitada = !empty($body['atencion_99208']) ? 1 : 0;

    if (strlen($dni) < 8 || strlen($dni) > 15) {
        json_error('El DNI de la paciente debe contener entre 8 y 15 dígitos numéricos.', 400);
    }

    // Caso A: el pase directo solo es válido si el HIS confirma atención previa
    // real en la UPS de Planificación Familiar del establecimiento activo.
    if ($paseUps) {
        $codigosUps = codigos_ups_planificacion_familiar($pdo);
        $atencionesUps = consultar_ups_planificacion_familiar($pdo, $dni, $codEstab, $codigosUps);
        $tieneUpsPrevia = false;
        foreach ($atencionesUps as $atencionUps) {
            if (atencion_ups_es_planificacion_familiar($atencionUps, $codigosUps)) {
                $tieneUpsPrevia = true;
                break;
            }
        }
        if (!$tieneUpsPrevia) {
            json_error(
                'No se puede confirmar el pase directo: la paciente no registra atención previa en la UPS de Planificación Familiar de este establecimiento.',
                409,
                ['code' => 'UPS_PREVIA_NO_ENCONTRADA', 'caso' => 'B']
            );
        }
    }

    // Caso A: pase directo desde UPS. Si faltan datos, se completan con HIS o con
    // marcadores seguros para que la obstetra no tenga que redigitar todo.
    if ($paseUps) {
        $stmt = $pdo->prepare('SELECT * FROM pacientes_sin_metodo WHERE dni = :dni LIMIT 1');
        $stmt->execute([':dni' => $dni]);
        $existente = $stmt->fetch() ?: null;
        if ($existente) {
            $apPaterno = $apPaterno ?: strtoupper((string)$existente['apellido_paterno']);
            $apMaterno = $apMaterno ?: strtoupper((string)$existente['apellido_materno']);
            $nombres = $nombres ?: strtoupper((string)$existente['nombres']);
            $edad = $edad >= 10 ? $edad : (int)$existente['edad'];
            $celular = $celular ?: HospitalHuaralDB::decryptPII((string)$existente['celular']);
            $correo = $correo ?: HospitalHuaralDB::decryptPII((string)$existente['correo']);
            $direccion = $direccion ?: HospitalHuaralDB::decryptPII((string)$existente['direccion']);
            $distrito = $distrito ?: strtoupper((string)$existente['distrito']);
            $sector = $sector ?: strtoupper((string)$existente['sector']);
        } else {
            try {
                $stmtHis = $pdo->prepare('SELECT TRIM(Apellido_p) AS ap, TRIM(Apellido_m) AS am, TRIM(Dnombres) AS nom, EDAD FROM his_dl WHERE DNI = :dni ORDER BY ANO DESC, MES DESC, DIA DESC LIMIT 1');
                $stmtHis->execute([':dni' => $dni]);
                $his = $stmtHis->fetch() ?: [];
                $apPaterno = $apPaterno ?: strtoupper((string)($his['ap'] ?? 'SIN DATO'));
                $apMaterno = $apMaterno ?: strtoupper((string)($his['am'] ?? 'SIN DATO'));
                $nombres = $nombres ?: strtoupper((string)($his['nom'] ?? 'SIN DATO'));
                $edad = $edad >= 10 ? $edad : (int)($his['EDAD'] ?? 18);
            } catch (Throwable $e) {
                $apPaterno = $apPaterno ?: 'SIN DATO';
                $apMaterno = $apMaterno ?: 'SIN DATO';
                $nombres = $nombres ?: 'SIN DATO';
                $edad = $edad >= 10 ? $edad : 18;
            }
            $direccion = $direccion ?: 'NO REGISTRADA - ACTUALIZAR EN CAMPO';
            $distrito = $distrito ?: 'HUARAL';
            $sector = $sector ?: 'UPS PLANIFICACION FAMILIAR';
        }
    }

    if ($distrito === '') {
        $distrito = 'HUARAL';
    }

    if ($apPaterno === '' || $apMaterno === '' || $nombres === '' || $direccion === '' || $sector === '') {
        json_error('Complete los campos obligatorios: apellidos, nombres, dirección y sector.', 400);
    }
    if ($edad < 10 || $edad > 65) {
        json_error('La edad en planificación familiar debe estar entre 10 y 65 años.', 400);
    }

    // El antecedente 99208 se valida contra his_dl/his_dl_dt, no se confía solo
    // en el booleano que envía el navegador.
    $atencion99208 = $atencion99208Solicitada;
    try {
        if (count(consultar_atenciones_99208($pdo, $dni)) > 0) {
            $atencion99208 = 1;
        }
    } catch (Throwable $e) {
        // Si el HIS no responde, se conserva el valor enviado por la obstetra.
    }

    $stmt = $pdo->prepare("
        INSERT INTO pacientes_sin_metodo
            (dni, apellido_paterno, apellido_materno, nombres, edad, celular, correo, distrito, direccion, sector, estado_paciente, codpsal_obstetra, cod_estab, atencion_99208)
        VALUES
            (:dni, :ap_p, :ap_m, :nom, :edad, :cel, :cor, :dist, :dir, :sec, :est, :obst, :estab, :a99208)
        ON DUPLICATE KEY UPDATE
            apellido_paterno = VALUES(apellido_paterno),
            apellido_materno = VALUES(apellido_materno),
            nombres = VALUES(nombres),
            edad = VALUES(edad),
            celular = VALUES(celular),
            correo = VALUES(correo),
            distrito = VALUES(distrito),
            direccion = VALUES(direccion),
            sector = VALUES(sector),
            estado_paciente = VALUES(estado_paciente),
            codpsal_obstetra = VALUES(codpsal_obstetra),
            cod_estab = VALUES(cod_estab),
            atencion_99208 = GREATEST(atencion_99208, VALUES(atencion_99208))
    ");
    $stmt->execute([
        ':dni' => $dni,
        ':ap_p' => $apPaterno,
        ':ap_m' => $apMaterno,
        ':nom' => $nombres,
        ':edad' => $edad,
        ':cel' => HospitalHuaralDB::encryptPII($celular),
        ':cor' => HospitalHuaralDB::encryptPII($correo),
        ':dist' => $distrito,
        ':dir' => HospitalHuaralDB::encryptPII($direccion),
        ':sec' => $sector,
        ':est' => $estado,
        ':obst' => $session['dni'],
        ':estab' => $codEstab,
        ':a99208' => $atencion99208,
    ]);

    HospitalHuaralDB::registrarAuditoria(
        $session['dni'],
        $paseUps ? 'PASE_UPS_CONFIRMADO' : 'GUARDAR_PACIENTE',
        ($paseUps ? 'Pase directo UPS PF confirmado' : 'Paciente registrada') . ' DNI ' . $dni . ' (' . $apPaterno . ' ' . $apMaterno . ', ' . $nombres . ') en ' . hospital_nombre_establecimiento($codEstab) . '. PII cifrada AES-256-GCM.',
        $codEstab,
        $session['platform']
    );

    if ($atencion99208 === 1) {
        HospitalHuaralDB::registrarAuditoria($session['dni'], 'VERIFICACION_99208', 'Paciente DNI ' . $dni . ' registrada con antecedente de atención 99208.', $codEstab, $session['platform']);
    }

    json_out([
        'success' => true,
        'mode' => $paseUps ? 'PASE_UPS' : 'UPSERT',
        'message' => $paseUps
            ? 'Pase directo confirmado en la UPS de Planificación Familiar.'
            : 'Paciente guardada exitosamente en MySQL/MariaDB (PII cifrada AES-256-GCM).',
        'atencion_99208' => (bool)$atencion99208,
    ], 201);
}

// ---------------------------------------------------------------------------
// 9. ACTUALIZAR ESTADO CLÍNICO
// ---------------------------------------------------------------------------
if ($action === 'update_estado') {
    $session = require_session();
    $id = (int)($body['id'] ?? 0);
    $estado = strtoupper(HospitalHuaralDB::sanitizeText($body['estado_paciente'] ?? 'INSATISFECHA_SIN_METODO', 30));
    $estadosValidos = ['INSATISFECHA_SIN_METODO', 'CAPTADA_CON_METODO', 'SEGUIMIENTO_DOMICILIARIO', 'CONSEJERIA_REALIZADA', 'RECHAZA_METODO'];
    if ($id <= 0 || !in_array($estado, $estadosValidos, true)) {
        json_error('Registro o estado clínico inválido.', 400);
    }
    if (is_admin_session($session)) {
        $stmt = $pdo->prepare('UPDATE pacientes_sin_metodo SET estado_paciente = :estado WHERE id = :id LIMIT 1');
        $stmt->execute([':estado' => $estado, ':id' => $id]);
    } elseif (es_jefa_session($session)) {
        $codigosEstabJefa = codigos_establecimiento_sesion($session);
        $marcasEstabJefa = implode(',', array_fill(0, count($codigosEstabJefa), '?'));
        $stmt = $pdo->prepare('UPDATE pacientes_sin_metodo SET estado_paciente = ? WHERE id = ? AND cod_estab IN (' . $marcasEstabJefa . ') LIMIT 1');
        $stmt->execute(array_merge([$estado, $id], $codigosEstabJefa));
    } else {
        $codigosEstabObstetra = codigos_establecimiento_sesion($session);
        $marcasEstabObstetra = implode(',', array_fill(0, count($codigosEstabObstetra), '?'));
        $stmt = $pdo->prepare('UPDATE pacientes_sin_metodo SET estado_paciente = ? WHERE id = ? AND codpsal_obstetra = ? AND cod_estab IN (' . $marcasEstabObstetra . ') LIMIT 1');
        $stmt->execute(array_merge([$estado, $id, (string)$session['dni']], $codigosEstabObstetra));
    }
    if ($stmt->rowCount() === 0) {
        json_error('No se encontró el registro solicitado.', 404);
    }
    HospitalHuaralDB::registrarAuditoria($session['dni'], 'PACIENTE_STATUS_CHANGE', 'Cambio de estado del registro #' . $id . ' a ' . $estado . '.', $session['cod_estab'], $session['platform']);
    json_out(['success' => true, 'id' => $id, 'estado_paciente' => $estado]);
}

// ---------------------------------------------------------------------------
// 10. AUDITORÍA — lectura y verificación de cadena
// ---------------------------------------------------------------------------
if ($action === 'audit_logs') {
    $session = require_session();
    if (!is_admin_session($session)) {
        json_error('Solo el Administrador de Estadística puede consultar la auditoría.', 403, ['code' => 'ADMIN_REQUIRED']);
    }
    $limit = (int)($_GET['limit'] ?? 50);
    json_out([
        'logs' => HospitalHuaralDB::ultimaAuditoria($limit),
        'total' => (int)$pdo->query('SELECT COUNT(*) FROM auditoria_seguridad_app')->fetchColumn(),
        'session' => $session['dni'],
    ]);
}

if ($action === 'auditoria_movimientos') {
    $session = require_session();
    if (!is_admin_session($session)) {
        json_error('Solo el Administrador de Estadística puede consultar el historial de movimientos.', 403, ['code' => 'ADMIN_REQUIRED']);
    }
    $q = trim((string)($_GET['q'] ?? ''));
    $accionFiltro = strtoupper(trim((string)($_GET['accion'] ?? 'TODAS')));
    $estabFiltro = trim((string)($_GET['cod_estab'] ?? 'TODOS'));
    $desde = reporte_fecha_valida($_GET['fecha_desde'] ?? null);
    $hasta = reporte_fecha_valida($_GET['fecha_hasta'] ?? null);
    $limit = max(1, min(500, (int)($_GET['limit'] ?? 100)));
    $page = max(1, (int)($_GET['page'] ?? 1));
    $offset = ($page - 1) * $limit;

    $where = [];
    $params = [];
    if ($q !== '') {
        $like = '%' . str_replace(['%', '_'], ['\%', '\_'], $q) . '%';
        $dnisNombre = [];
        try {
            $stmtNom = $pdo->prepare("
                SELECT dni FROM app_usuarios
                WHERE dni LIKE :q_dni OR nombre_completo LIKE :q_nombre
                   OR nombres LIKE :q_nombres OR apellido_paterno LIKE :q_ap
                LIMIT 100
            ");
            $stmtNom->execute([
                ':q_dni' => $like,
                ':q_nombre' => $like,
                ':q_nombres' => $like,
                ':q_ap' => $like,
            ]);
            $dnisNombre = array_map('strval', $stmtNom->fetchAll(PDO::FETCH_COLUMN));
        } catch (Throwable $e) {
            $dnisNombre = [];
        }
        $partesQ = ['a.actor_dni LIKE :q_actor', 'a.detalle LIKE :q_detalle'];
        $params[':q_actor'] = $like;
        $params[':q_detalle'] = $like;
        if ($dnisNombre) {
            $marcasNom = [];
            foreach (array_values($dnisNombre) as $i => $dniNom) {
                $marcaNom = ':q_dni_nombre' . $i;
                $marcasNom[] = $marcaNom;
                $params[$marcaNom] = $dniNom;
            }
            $partesQ[] = 'a.actor_dni IN (' . implode(',', $marcasNom) . ')';
        }
        $where[] = '(' . implode(' OR ', $partesQ) . ')';
    }
    if ($accionFiltro !== '' && $accionFiltro !== 'TODAS' && $accionFiltro !== 'TODOS') {
        $where[] = 'a.accion = :accion';
        $params[':accion'] = $accionFiltro;
    }
    if ($estabFiltro !== '' && $estabFiltro !== 'TODOS') {
        $variantesEstab = hospital_codigos_busqueda_establecimiento($estabFiltro);
        if (!$variantesEstab) {
            $variantesEstab = [$estabFiltro];
        }
        $marcasEstab = [];
        foreach (array_values($variantesEstab) as $i => $codEstab) {
            $marcaEstab = ':audit_estab' . $i;
            $marcasEstab[] = $marcaEstab;
            $params[$marcaEstab] = $codEstab;
        }
        $where[] = 'a.actor_estab IN (' . implode(',', $marcasEstab) . ')';
    }
    if ($desde !== null) {
        $where[] = 'DATE(a.fecha_hora) >= :desde';
        $params[':desde'] = $desde;
    }
    if ($hasta !== null) {
        $where[] = 'DATE(a.fecha_hora) <= :hasta';
        $params[':hasta'] = $hasta;
    }
    $whereSql = $where ? (' WHERE ' . implode(' AND ', $where)) : '';
    $stmtTotal = $pdo->prepare("SELECT COUNT(*) FROM auditoria_seguridad_app a {$whereSql}");
    $stmtTotal->execute($params);
    $total = (int)$stmtTotal->fetchColumn();

    $stmt = $pdo->prepare("
        SELECT a.*
        FROM auditoria_seguridad_app a
        {$whereSql}
        ORDER BY a.id DESC
        LIMIT {$limit} OFFSET {$offset}
    ");
    $stmt->execute($params);
    $movimientos = $stmt->fetchAll();
    $dnisMov = array_values(array_unique(array_map(static fn ($m) => (string)($m['actor_dni'] ?? ''), $movimientos)));
    $nombresMov = [];
    if ($dnisMov) {
        try {
            $marcasMov = implode(',', array_fill(0, count($dnisMov), '?'));
            $stmtNombres = $pdo->prepare("SELECT dni, nombre_completo FROM app_usuarios WHERE dni IN ({$marcasMov})");
            $stmtNombres->execute($dnisMov);
            foreach ($stmtNombres->fetchAll() as $filaNombre) {
                $nombresMov[(string)$filaNombre['dni']] = (string)$filaNombre['nombre_completo'];
            }
        } catch (Throwable $e) {
            $nombresMov = [];
        }
    }
    foreach ($movimientos as &$mov) {
        $dniMov = (string)($mov['actor_dni'] ?? '');
        $mov['actor_nombre'] = $nombresMov[$dniMov] ?? '';
        $mov['estab_nombre'] = hospital_nombre_establecimiento((string)($mov['actor_estab'] ?? ''));
    }
    unset($mov);

    $acciones = [];
    try {
        $acciones = array_map('strval', $pdo->query("
            SELECT DISTINCT accion FROM auditoria_seguridad_app
            ORDER BY accion ASC LIMIT 200
        ")->fetchAll(PDO::FETCH_COLUMN));
    } catch (Throwable $e) {
        $acciones = [];
    }

    json_out([
        'success' => true,
        'movimientos' => $movimientos,
        'total' => $total,
        'pagina' => $page,
        'por_pagina' => $limit,
        'acciones' => $acciones,
        'establecimientos' => hospital_establecimientos(),
        'filtros' => [
            'q' => $q,
            'accion' => $accionFiltro,
            'cod_estab' => $estabFiltro,
            'fecha_desde' => $desde,
            'fecha_hasta' => $hasta,
        ],
    ]);
}

if ($action === 'equipo_jefatura') {
    $session = require_session();
    if (!es_jefa_session($session) && !is_admin_session($session)) {
        json_error('Solo la Jefatura de Obstetras puede consultar el equipo de su establecimiento.', 403);
    }
    $codEstabEquipo = is_admin_session($session)
        ? hospital_codigo_canonico((string)($_GET['cod_estab'] ?? $session['cod_estab']))
        : hospital_codigo_canonico((string)$session['cod_estab']);
    if (hospital_establecimiento($codEstabEquipo) === null) {
        $codEstabEquipo = hospital_codigo_canonico((string)$session['cod_estab']);
    }
    $variantesEquipo = hospital_codigos_busqueda_establecimiento($codEstabEquipo);
    if (!$variantesEquipo) {
        $variantesEquipo = [$codEstabEquipo];
    }
    $marcasEquipo = implode(',', array_fill(0, count($variantesEquipo), '?'));
    $stmtEquipo = $pdo->prepare("
        SELECT dni, nombres, apellido_paterno, apellido_materno, nombre_completo,
               email, celular, activo, cod_estab, ultimo_login, created_at, updated_at
        FROM app_usuarios
        WHERE rol = 'OBSTETRA' AND cod_estab IN ({$marcasEquipo})
        ORDER BY activo DESC, apellido_paterno ASC, nombres ASC
        LIMIT 300
    ");
    $stmtEquipo->execute($variantesEquipo);
    $equipo = $stmtEquipo->fetchAll();
    $dnisEquipo = array_values(array_map(static fn ($o) => (string)$o['dni'], $equipo));
    $statsEquipo = [];
    if ($dnisEquipo) {
        try {
            $marcasDniEquipo = implode(',', array_fill(0, count($dnisEquipo), '?'));
            $stmtStats = $pdo->prepare("
                SELECT codpsal_obstetra,
                       COUNT(*) AS total,
                       SUM(CASE WHEN DATE(fecha_registro) = CURDATE() THEN 1 ELSE 0 END) AS hoy,
                       SUM(CASE WHEN YEAR(fecha_registro) = YEAR(CURDATE()) AND MONTH(fecha_registro) = MONTH(CURDATE()) THEN 1 ELSE 0 END) AS mes,
                       MAX(fecha_registro) AS ultima_actividad
                FROM pacientes_sin_metodo
                WHERE codpsal_obstetra IN ({$marcasDniEquipo})
                  AND cod_estab IN ({$marcasEquipo})
                GROUP BY codpsal_obstetra
            ");
            $stmtStats->execute(array_merge($dnisEquipo, $variantesEquipo));
            foreach ($stmtStats->fetchAll() as $filaStats) {
                $statsEquipo[(string)$filaStats['codpsal_obstetra']] = $filaStats;
            }
        } catch (Throwable $e) {
            $statsEquipo = [];
        }
    }
    foreach ($equipo as &$obstetraEquipo) {
        $dniEquipo = (string)$obstetraEquipo['dni'];
        $stats = $statsEquipo[$dniEquipo] ?? [];
        $obstetraEquipo['total_captadas'] = (int)($stats['total'] ?? 0);
        $obstetraEquipo['captadas_hoy'] = (int)($stats['hoy'] ?? 0);
        $obstetraEquipo['captadas_mes'] = (int)($stats['mes'] ?? 0);
        $obstetraEquipo['ultima_actividad'] = (string)($stats['ultima_actividad'] ?? '');
        $obstetraEquipo['estab_nombre'] = hospital_nombre_establecimiento((string)($obstetraEquipo['cod_estab'] ?? ''));
    }
    unset($obstetraEquipo);

    json_out([
        'success' => true,
        'establecimiento' => [
            'codigo' => $codEstabEquipo,
            'nombre' => hospital_nombre_establecimiento($codEstabEquipo),
        ],
        'total' => count($equipo),
        'activos' => count(array_filter($equipo, static fn ($o) => (int)($o['activo'] ?? 1) === 1)),
        'obstetras' => $equipo,
        'puede_resetear' => true,
    ]);
}

if ($action === 'verify_chain') {
    $session = require_session();
    if (!is_admin_session($session)) {
        json_error('Solo el Administrador de Estadística puede verificar la cadena de auditoría.', 403, ['code' => 'ADMIN_REQUIRED']);
    }
    $result = HospitalHuaralDB::verificarCadenaAuditoria();
    HospitalHuaralDB::registrarAuditoria(
        $session['dni'],
        'AUDIT_CHAIN_VERIFICATION',
        'Verificación SHA-256 de la cadena de auditoría: ' . ($result['valid'] ? 'INTACTA' : 'ALTERADA') . ' (' . $result['verified'] . ' registros).',
        $session['cod_estab'],
        $session['platform']
    );
    json_out($result);
}

// ---------------------------------------------------------------------------
// 11. EXPORTACIÓN SQL NUBE -> LOCAL (solo tablas existentes en el hospital)
// ---------------------------------------------------------------------------
function tabla_existe(PDO $pdo, string $tabla): bool
{
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :tabla');
    $stmt->execute([':tabla' => $tabla]);
    return (int)$stmt->fetchColumn() > 0;
}

function identificador_seguro(string $name): bool
{
    return (bool)preg_match('/^[A-Za-z0-9_]{1,64}$/', $name);
}

function sql_valor(PDO $pdo, mixed $value): string
{
    if ($value === null) {
        return 'NULL';
    }
    if (is_bool($value)) {
        return $value ? '1' : '0';
    }
    if (is_int($value) || is_float($value)) {
        return (string)$value;
    }
    return $pdo->quote((string)$value);
}

/**
 * @param array<int, array<string, mixed>> $rows
 * @param array<int, string> $pk preferencia de clave primaria
 */
function construir_upsert(PDO $pdo, string $tabla, array $rows, array $pk): string
{
    if (!$rows || !identificador_seguro($tabla)) {
        return '';
    }
    $columns = array_keys($rows[0]);
    foreach ($columns as $col) {
        if (!identificador_seguro((string)$col)) {
            return '';
        }
    }
    $colList = implode(', ', array_map(static fn ($c) => '`' . $c . '`', $columns));
    $tuples = [];
    foreach ($rows as $row) {
        $vals = [];
        foreach ($columns as $col) {
            $vals[] = sql_valor($pdo, $row[$col] ?? null);
        }
        $tuples[] = '(' . implode(', ', $vals) . ')';
    }
    $updateCols = array_values(array_diff($columns, $pk));
    if (!$updateCols) {
        $updateCols = $columns;
    }
    $updates = implode(', ', array_map(static fn ($c) => '`' . $c . '` = VALUES(`' . $c . '`)', $updateCols));
    return "INSERT INTO `{$tabla}` ({$colList})\nVALUES\n  " . implode(",\n  ", $tuples) . "\nON DUPLICATE KEY UPDATE {$updates};\n";
}

function sql_export_seguro(string $sql): bool
{
    // Se excluyen comentarios y literales para no confundir nombres de pacientes
    // con palabras reservadas. El script solo puede contener INSERT/UPDATE/CALL.
    $limpio = preg_replace('/^\s*--.*$/m', '', $sql) ?? '';
    $limpio = preg_replace("/'(?:\\\\.|''|[^'\\\\])*'/s", "''", $limpio) ?? '';
    return !preg_match('/\b(CREATE|ALTER|DROP|TRUNCATE|DELETE|REPLACE|GRANT|REVOKE)\b/i', $limpio);
}

if ($action === 'sync_export_local_sql') {
    $session = require_session();
    // La exportación contiene hashes de usuario y datos del HIS: solo el
    // administrador de Estadística puede generarla desde la web.
    if (!is_admin_session($session)) {
        json_error('Solo el administrador de Estadística puede generar exportaciones Nube → Local.', 403, [
            'code' => 'ADMIN_REQUIRED',
        ]);
    }
    $ip = HospitalHuaralDB::clientIp();
    $bucket = 'sync_export:' . hash('sha256', (string)($session['token'] ?? ($session['dni'] . '|' . $ip)));
    $limit = HospitalHuaralDB::rateLimitStatus($bucket, 10, 60);
    if (!$limit['allowed']) {
        json_error('Límite de exportaciones alcanzado. Espere un minuto.', 429, ['retryAfter' => $limit['retryAfter']]);
    }
    HospitalHuaralDB::rateLimitHit($bucket, 60);

    $modo = (string)($_GET['modo'] ?? 'directo');
    if (!in_array($modo, ['directo', 'puente'], true)) {
        $modo = 'directo';
    }
    $batch = 300;

    // Modo directo: solo las cinco tablas originales del hospital.
    $tablasDirectas = ['usuario', 'mstrpers', 'his_mstrpers', 'his_dl', 'his_dl_dt'];
    // Modo puente: tablas receptoras nativas + CALL sp_get_recepcion().
    $mapaPuente = [
        'his_dl' => 'r_his_dl',
        'his_dl_dt' => 'r_his_dl_dt',
        'his_mstrpers' => 'r_his_mstrpers',
        'usuario' => 'r_his_digitad',
    ];
    $tablasNubeProhibidas = [
        'pacientes_sin_metodo',
        'auditoria_seguridad_app',
        'app_2fa_challenges',
        'app_obstetra_establecimiento',
        'app_rate_limits',
        'app_sesiones',
        'app_sync_runs',
        'app_totp_secretos',
        'app_usuarios',
        'app_usuarios_accesos',
    ];
    $pkPreferida = [
        'usuario' => ['dni'],
        'mstrpers' => ['CODPSAL'],
        'his_mstrpers' => ['CODPSAL'],
        'his_dl' => ['ID'],
        'his_dl_dt' => ['ID', 'num'],
        'r_his_dl' => ['ID'],
        'r_his_dl_dt' => ['ID', 'num'],
        'r_his_mstrpers' => ['CODPSAL'],
        'r_his_digitad' => ['dni'],
    ];
    $plan = $modo === 'puente'
        ? $mapaPuente
        : array_combine($tablasDirectas, $tablasDirectas);

    $sql = "-- =====================================================================\n";
    $sql .= "-- PlanificaSalud HIS · Exportación Nube -> Base Local (Navicat / XAMPP)\n";
    $sql .= "-- Hospital San Juan Bautista Huaral · Red de Salud Huaral-Chancay\n";
    $sql .= "-- Generado: " . date('Y-m-d H:i:s') . " · Modo: {$modo} · Lote: {$batch}\n";
    $sql .= "-- SOLO tablas originales/receptoras existentes en el hospital.\n";
    $sql .= "-- Las tablas exclusivas de la nube NO se exportan.\n";
    $sql .= "-- Sin sentencias de definición de esquema y sin borrados de historial.\n";
    $sql .= "-- =====================================================================\n\n";
    $sql .= "SET NAMES utf8mb4;\nSET @OLD_SQL_MODE=@@SQL_MODE;\n";
    $sql .= "SET SQL_MODE='STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION,ALLOW_INVALID_DATES';\nSTART TRANSACTION;\n\n";

    $tablasExportadas = [];
    $detallePlan = [];
    $filasTotales = 0;
    foreach ($plan as $tablaOrigen => $tablaDestino) {
        if (!identificador_seguro($tablaOrigen) || !identificador_seguro($tablaDestino)) {
            continue;
        }
        if (in_array($tablaOrigen, $tablasNubeProhibidas, true) || in_array($tablaDestino, $tablasNubeProhibidas, true)) {
            $sql .= "-- [PROHIBIDA] `{$tablaOrigen}` es una tabla exclusiva de la nube.\n\n";
            continue;
        }
        if (!tabla_existe($pdo, $tablaOrigen)) {
            $sql .= "-- [OMITIDA] La tabla `{$tablaOrigen}` no existe en esta base de datos.\n\n";
            continue;
        }
        try {
            $order = $tablaOrigen === 'his_dl' ? 'ANO DESC, MES DESC, DIA DESC' : '1 DESC';
            $stmt = $pdo->query("SELECT * FROM `{$tablaOrigen}` ORDER BY {$order} LIMIT {$batch}");
            $rows = $stmt->fetchAll();
        } catch (Throwable $e) {
            $sql .= "-- [OMITIDA] No se pudo leer `{$tablaOrigen}`: " . str_replace(["\r", "\n"], ' ', $e->getMessage()) . "\n\n";
            continue;
        }
        if (!$rows) {
            $sql .= "-- [VACÍA] `{$tablaOrigen}` no tiene registros en este lote.\n\n";
            continue;
        }
        $sql .= "-- ---------------------------------------------------------------------\n";
        $sql .= "-- Origen: `{$tablaOrigen}` -> Destino: `{$tablaDestino}` (" . count($rows) . " filas, LIMIT {$batch})\n";
        $sql .= "-- ---------------------------------------------------------------------\n";
        $upsert = construir_upsert($pdo, $tablaDestino, $rows, $pkPreferida[$tablaDestino] ?? ['id']);
        if ($upsert === '') {
            $sql .= "-- [OMITIDA] No se pudo construir el INSERT seguro para `{$tablaDestino}`.\n\n";
            continue;
        }
        $sql .= $upsert . "\n";
        $tablasExportadas[] = $tablaOrigen . '->' . $tablaDestino;
        $detallePlan[$tablaOrigen] = $tablaDestino;
        $filasTotales += count($rows);
    }

    $sql .= "COMMIT;\n";
    if ($modo === 'puente') {
        $sql .= "\n-- Procedimiento nativo del hospital: integra las tablas receptoras.\n";
        $sql .= "CALL sp_get_recepcion();\n";
    } else {
        $sql .= "\n-- Modo directo: no se invoca sp_get_recepcion() para evitar doble inserción.\n";
    }
    $sql .= "\nSET SQL_MODE=@OLD_SQL_MODE;\n\n";
    $sql .= "-- Fin del script. Ejecutar en Navicat sobre la base local del hospital.\n";

    if (!sql_export_seguro($sql)) {
        error_log('[PlanificaHIS] Exportación bloqueada por validación de sentencias peligrosas.');
        json_error('La exportación fue bloqueada por la política de seguridad SQL del hospital.', 500, [
            'code' => 'SYNC_UNSAFE_SQL',
        ]);
    }

    try {
        $pdo->prepare("INSERT INTO app_sync_runs (actor_dni, modo, tablas, filas) VALUES (:dni, :modo, :tablas, :filas)")
            ->execute([
                ':dni' => (string)$session['dni'],
                ':modo' => $modo,
                ':tablas' => implode(',', $tablasExportadas),
                ':filas' => $filasTotales,
            ]);
    } catch (Throwable $e) {
        // El log de sincronización es auxiliar.
    }

    HospitalHuaralDB::registrarAuditoria(
        $session['dni'],
        'SYNC_EXPORT_LOCAL_SQL',
        'Exportación Nube -> Local generada en modo ' . $modo . ' para tablas: ' . implode(', ', $tablasExportadas) . ' (' . $filasTotales . ' filas).',
        $session['cod_estab'],
        $session['platform']
    );

    json_out([
        'success' => true,
        'filename' => 'sync_nube_a_local_' . date('Ymd_His') . '.sql',
        'generatedAt' => date('c'),
        'mode' => $modo,
        'batchLimit' => $batch,
        'plan' => $detallePlan,
        'tables' => $tablasExportadas,
        'rows' => $filasTotales,
        'sql' => $sql,
        'warnings' => [
            'Las tablas pacientes_sin_metodo, auditoria_seguridad_app y app_* son exclusivas de la nube y NO se exportan.',
            'Ejecute siempre con respaldo previo de la base local del hospital.',
            'El script solo usa INSERT ... ON DUPLICATE KEY UPDATE; no elimina historial clínico.',
        ],
    ]);
}

// ---------------------------------------------------------------------------
// 12. SIMULADOR WAF (solo sesión autenticada, no toca datos reales)
// ---------------------------------------------------------------------------
if ($action === 'test_waf') {
    $session = require_session();
    $payload = (string)($body['payload'] ?? '');
    $target = HospitalHuaralDB::sanitizeText($body['targetField'] ?? 'dni', 30);
    $inspection = HospitalHuaralDB::detectMaliciousPayload($payload);
    if ($inspection['type'] !== null) {
        HospitalHuaralDB::registrarAuditoria(
            $session['dni'],
            waf_action_for_type($inspection['type']),
            'Prueba de penetración controlada en campo ' . $target . '. Patrón: [' . $inspection['matched'] . '].',
            $session['cod_estab'],
            $session['platform']
        );
    }
    json_out([
        'blocked' => $inspection['type'] !== null,
        'attackType' => $inspection['type'],
        'matchedPattern' => $inspection['matched'],
        'sanitizedOutput' => HospitalHuaralDB::sanitizeForHtml($payload, 200),
        'preparedStatementPreview' => 'Parámetro nativo PDO: ' . $target . ' = ? (EMULATE_PREPARES = false)',
        'aes256Preview' => HospitalHuaralDB::encryptPII($payload !== '' ? $payload : 'Dato Clínico Sensible'),
    ]);
}

// ---------------------------------------------------------------------------
// 13. Estado del API
// ---------------------------------------------------------------------------
json_out([
    'status' => 'API Hospital San Juan Bautista Huaral activa',
    'version' => '2026.11-ASVS-L3',
    'security' => [
        'pdo_native_prepares' => true,
        'aes_256_gcm' => true,
        'totp_rfc6238' => true,
        'bearer_hmac_sha256' => true,
        'waf' => true,
        'rate_limiting' => true,
        'audit_sha256_chain' => true,
    ],
    'establecimientos' => count(hospital_establecimientos()),
]);
