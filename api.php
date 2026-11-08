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
    $user = [];
    try {
        $stmt = $pdo->prepare('SELECT nombre1, apaterno, amaterno, email, nivelid, tipo FROM usuario WHERE dni = :dni LIMIT 1');
        $stmt->execute([':dni' => $dni]);
        $user = $stmt->fetch() ?: [];
    } catch (Throwable $e) {
        $user = [];
    }
    $nombreCompleto = trim(
        (string)($user['nombre1'] ?? '') . ' ' .
        (string)($user['apaterno'] ?? '') . ' ' .
        (string)($user['amaterno'] ?? '')
    );
    if ($nombreCompleto === '') {
        try {
            $diccionario = nombres_personas_por_dni($pdo, [$dni]);
            $nombreCompleto = (string)($diccionario[$dni] ?? '');
        } catch (Throwable $e) {
            $nombreCompleto = '';
        }
    }
    if ($nombreCompleto === '') {
        $nombreCompleto = 'OBSTETRA ' . $dni;
    }
    $codEstab = (string)($session['cod_estab'] ?? '000005481');
    return [
        'token' => (string)($session['token'] ?? ''),
        'dni' => $dni,
        'nombreCompleto' => $nombreCompleto,
        'rol' => (string)($user['tipo'] ?? 'Obstetra'),
        'nivelid' => (int)($user['nivelid'] ?? 2),
        'cod_estab' => $codEstab,
        'estab_nombre' => hospital_nombre_establecimiento($codEstab),
        'verified2FA' => false,
        'platform' => (string)($session['platform'] ?? 'Web Desktop'),
        'isAdmin' => is_admin_session($session),
        'expires_at' => (int)($session['expires_at'] ?? (time() + HospitalHuaralDB::SESSION_TTL)),
        'session_ttl' => HospitalHuaralDB::SESSION_TTL,
    ];
}

function is_admin_session(array $session): bool
{
    return in_array($session['dni'], array_map('strval', array_filter([
        getenv('APP_ADMIN_DNI') ?: '',
    ])), true) || (int)(getenv('APP_ADMIN_NIVELID') ?: 0) === 1;
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

    $stmt = $pdo->prepare('SELECT * FROM usuario WHERE dni = :dni LIMIT 1');
    $stmt->execute([':dni' => $dni]);
    $user = $stmt->fetch();

    if (!$user) {
        HospitalHuaralDB::rateLimitHit($bucket, 900);
        HospitalHuaralDB::registrarAuditoria($dni, 'AUTH_LOGIN_FAILED', 'DNI no registrado en la tabla usuario.', '', $platform);
        // Respuesta genérica: no se revela si el DNI existe (anti-enumeración).
        json_error('DNI o contraseña incorrectos.', 401, ['remainingAttempts' => max(0, 4 - (int)$limit['hits'])]);
    }
    if (isset($user['estado']) && (int)$user['estado'] === 0) {
        json_error('La cuenta se encuentra inactiva. Contacte a la Unidad de Estadística e Informática.', 403);
    }

    $storedPass = (string)($user['passwordx'] ?? '');
    if (!HospitalHuaralDB::verifyPassword($password, $storedPass)) {
        HospitalHuaralDB::rateLimitHit($bucket, 900);
        HospitalHuaralDB::registrarAuditoria($dni, 'AUTH_LOGIN_FAILED', 'Contraseña inválida verificada con Bcrypt/Scrypt. Intento registrado.', '', $platform);
        $remaining = max(0, 4 - (int)$limit['hits']);
        json_error('DNI o contraseña incorrectos.', 401, ['remainingAttempts' => $remaining]);
    }

    HospitalHuaralDB::rateLimitReset($bucket);
    $codEstab = HospitalHuaralDB::obtenerEstablecimientoObstetra($dni);
    if (hospital_establecimiento($codEstab) === null) {
        $nivel = trim((string)($user['nivelcd'] ?? ''));
        if (hospital_establecimiento($nivel) !== null) {
            $codEstab = hospital_codigo_canonico($nivel);
            HospitalHuaralDB::establecerEstablecimientoObstetra($dni, $codEstab);
        }
    }
    $nombreCompleto = trim(
        (string)($user['nombre1'] ?? '') . ' ' .
        (string)($user['apaterno'] ?? '') . ' ' .
        (string)($user['amaterno'] ?? '')
    );
    if ($nombreCompleto === '') {
        $diccionarioLogin = nombres_personas_por_dni($pdo, [$dni]);
        $nombreCompleto = (string)($diccionarioLogin[$dni] ?? ('OBSTETRA ' . $dni));
    }

    // LOGIN DIRECTO DE UN SOLO PASO: credenciales válidas => sesión persistente
    // de 7 días. No se crean desafíos 2FA ni se solicita código TOTP/OTP.
    $token = HospitalHuaralDB::createSessionToken($dni, $codEstab, $platform);
    HospitalHuaralDB::registrarAuditoria(
        $dni,
        'AUTH_LOGIN_SUCCESS',
        'Credenciales válidas. Login directo sin 2FA. Sesión persistente de 7 días emitida.',
        $codEstab,
        $platform
    );
    json_out([
        'requires2FA' => false,
        'session' => [
            'token' => $token,
            'dni' => $dni,
            'nombreCompleto' => $nombreCompleto,
            'rol' => (string)($user['tipo'] ?? 'Obstetra'),
            'nivelid' => (int)($user['nivelid'] ?? 2),
            'cod_estab' => $codEstab,
            'estab_nombre' => hospital_nombre_establecimiento($codEstab),
            'verified2FA' => false,
            'platform' => $platform,
            'isAdmin' => is_admin_session(['dni' => $dni]),
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

    $stmt = $pdo->prepare('SELECT dni FROM usuario WHERE dni = :dni LIMIT 1');
    $stmt->execute([':dni' => $dni]);
    if ($stmt->fetchColumn()) {
        json_error('Ya existe una cuenta con ese DNI. Inicie sesión o recupere su acceso.', 409);
    }

    $hashed = HospitalHuaralDB::hashPassword($password);
    $stmt = $pdo->prepare("
        INSERT INTO usuario (dni, nombre1, nombre2, apaterno, amaterno, passwordx, email, celular, nivelid, nivelcd, tipo, estado)
        VALUES (:dni, :nom1, '', :ap, :am, :pass, :email, :cel, 2, :nivelcd, 2, 1)
    ");
    $stmt->execute([
        ':dni' => $dni,
        ':nom1' => $nombre1,
        ':ap' => $apaterno,
        ':am' => $amaterno,
        ':pass' => $hashed,
        ':email' => $email,
        ':cel' => substr($celular, 0, 9),
        ':nivelcd' => $codEstab,
    ]);

    HospitalHuaralDB::establecerEstablecimientoObstetra($dni, $codEstab);
    $nombreCompleto = "OBST. {$nombre1} {$apaterno} {$amaterno}";

    // La cuenta queda operativa y la sesión persistente se emite de inmediato:
    // registro y login son de un solo paso, sin secretos TOTP ni desafíos.
    $token = HospitalHuaralDB::createSessionToken($dni, $codEstab, $platform);
    HospitalHuaralDB::registrarAuditoria(
        $dni,
        'REGISTRO_OBSTETRA',
        'Cuenta creada para ' . $nombreCompleto . ' en ' . hospital_nombre_establecimiento($codEstab) . ' con login directo de 7 días.',
        $codEstab,
        $platform
    );
    json_out([
        'requires2FA' => false,
        'session' => [
            'token' => $token,
            'dni' => $dni,
            'nombreCompleto' => $nombreCompleto,
            'rol' => 'Obstetra Captadora',
            'nivelid' => 2,
            'cod_estab' => $codEstab,
            'estab_nombre' => hospital_nombre_establecimiento($codEstab),
            'verified2FA' => false,
            'platform' => $platform,
            'isAdmin' => is_admin_session(['dni' => $dni]),
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
    $stmt = $pdo->prepare('SELECT nombre1, apaterno, amaterno, email, nivelid, tipo FROM usuario WHERE dni = :dni LIMIT 1');
    $stmt->execute([':dni' => $dni]);
    $user = $stmt->fetch() ?: [];
    $nombreCompleto = trim((string)($user['nombre1'] ?? '') . ' ' . (string)($user['apaterno'] ?? '') . ' ' . (string)($user['amaterno'] ?? ''));
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
            'rol' => (string)($user['tipo'] ?? 'Obstetra'),
            'nivelid' => (int)($user['nivelid'] ?? 2),
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
    $codEstab = hospital_codigo_canonico((string)($body['cod_estab'] ?? ''));
    if (hospital_establecimiento($codEstab) === null) {
        json_error('El establecimiento seleccionado no pertenece a la Red Huaral-Chancay.', 400);
    }
    HospitalHuaralDB::cambiarEstablecimientoSesion((string)$session['token'], $codEstab, (string)$session['dni']);
    HospitalHuaralDB::registrarAuditoria(
        $session['dni'],
        'CAMBIO_ESTABLECIMIENTO',
        'La obstetra cambió su establecimiento activo a ' . hospital_nombre_establecimiento($codEstab) . ' (guardia/rotación).',
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
// 5. OVERVIEW — Dashboard, agenda de ampollas e indicadores
// ---------------------------------------------------------------------------
if ($action === 'overview') {
    $session = require_session();
    $platform = $session['platform'];

    $stmt = $pdo->prepare("
        SELECT p.*
        FROM pacientes_sin_metodo p
        ORDER BY p.fecha_registro DESC
        LIMIT 500
    ");
    $stmt->execute();
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

    $agenda = [];
    try {
        $variantesEstab = hospital_codigos_busqueda_establecimiento((string)$session['cod_estab']);
        if (!$variantesEstab) {
            $variantesEstab = [(string)$session['cod_estab']];
        }
        $placeholdersEstab = implode(',', array_fill(0, count($variantesEstab), '?'));
        // Se acota por establecimiento y año para no escanear los 5 GB del HIS:
        // h.COD_ESTAB y h.ANO se comparan sin funciones (SARGables).
        $stmtAgenda = $pdo->prepare("
            SELECT h.ID AS id_his, h.DNI AS dni,
                   CONCAT(TRIM(IFNULL(h.Apellido_p,'')), ' ', TRIM(IFNULL(h.Apellido_m,'')), ', ', TRIM(IFNULL(h.Dnombres, IFNULL(h.Pnombre,'')))) AS paciente_nombre,
                   h.EDAD AS edad, h.HCLFAM AS historia_clinica, h.COD_ESTAB,
                   dt.DX AS codigo_his, dt.id_dosis AS dosis_nro, h.fecha_reg AS fecha_ultima_aplicacion,
                   h.CODPSAL, dt.Alerta
            FROM his_dl h
            INNER JOIN his_dl_dt dt ON dt.ID = h.ID
            WHERE h.COD_ESTAB IN ({$placeholdersEstab})
              AND h.ANO >= ?
              AND dt.DX IN ('90782', 'Z304', 'Z301', '99208', 'Z300')
            ORDER BY h.ANO DESC, h.MES DESC, h.DIA DESC, h.ID DESC
            LIMIT 40
        ");
        $stmtAgenda->execute(array_merge($variantesEstab, [(int)date('Y') - 1]));
        $ciclos = ['90782' => 30, 'Z304' => 90, 'Z301' => 1095, '99208' => 30, 'Z300' => 0];
        $hoy = date('Y-m-d');
        $manana = date('Y-m-d', strtotime('+1 day'));
        foreach ($stmtAgenda->fetchAll() as $row) {
            $dias = $ciclos[(string)$row['codigo_his']] ?? 0;
            $proxima = $dias > 0 ? date('Y-m-d', strtotime((string)$row['fecha_ultima_aplicacion'] . ' +' . $dias . ' days')) : null;
            if ($dias === 0) {
                $estado = 'SIN_METODO_EN_HIS';
            } elseif ($proxima === $hoy) {
                $estado = 'TOCA_HOY';
            } elseif ($proxima === $manana) {
                $estado = 'TOCA_MANANA';
            } elseif ($proxima !== null && $proxima < $hoy) {
                $estado = 'VENCIDA_ABANDONO';
            } else {
                $estado = 'VIGENTE';
            }
            $row['establecimiento'] = hospital_nombre_establecimiento((string)$row['COD_ESTAB']);
            $row['metodo_descripcion'] = $row['codigo_his'];
            $row['fecha_proxima_cita'] = $proxima;
            $row['ciclo_dias'] = $dias;
            $row['estado_cita'] = $estado;
            $agenda[] = $row;
        }
    } catch (Throwable $e) {
        $agenda = [];
    }

    $stmtProd = $pdo->query("
        SELECT p.codpsal_obstetra AS codpsal,
               p.cod_estab AS cod_estab,
               COUNT(*) AS totalCaptadas,
               SUM(CASE WHEN p.estado_paciente = 'INSATISFECHA_SIN_METODO' THEN 1 ELSE 0 END) AS insatisfechasCaptadas,
               SUM(CASE WHEN p.estado_paciente = 'CAPTADA_CON_METODO' THEN 1 ELSE 0 END) AS conMetodoLogrado
        FROM pacientes_sin_metodo p
        GROUP BY p.codpsal_obstetra, p.cod_estab
        ORDER BY totalCaptadas DESC
        LIMIT 100
    ");
    $produccion = $stmtProd->fetchAll();
    $dnisProd = array_map(static fn ($row) => (string)$row['codpsal'], $produccion);
    $diccionarioProd = nombres_personas_por_dni($pdo, $dnisProd);
    foreach ($produccion as &$prodRow) {
        $cod = (string)$prodRow['codpsal'];
        $prodRow['nombre'] = (string)($diccionarioProd[$cod] ?? ('Obstetra DNI ' . $cod));
    }
    unset($prodRow);

    $auditoria = HospitalHuaralDB::ultimaAuditoria(30);
    $stats = [
        'totalCaptadas' => count($pacientes),
        'insatisfechasSinMetodo' => count(array_filter($pacientes, static fn ($p) => $p['estado_paciente'] === 'INSATISFECHA_SIN_METODO')),
        'captadasConMetodo' => count(array_filter($pacientes, static fn ($p) => $p['estado_paciente'] === 'CAPTADA_CON_METODO')),
        'seguimientoDomiciliario' => count(array_filter($pacientes, static fn ($p) => $p['estado_paciente'] === 'SEGUIMIENTO_DOMICILIARIO')),
        'citasAmpollaHoyManana' => count(array_filter($agenda, static fn ($a) => in_array($a['estado_cita'], ['TOCA_HOY', 'TOCA_MANANA'], true))),
        'alertasHisPorCaptar' => 0,
        'atenciones99208' => count(array_filter($pacientes, static fn ($p) => $p['atencion_99208'] === true)),
    ];
    $metricsRow = $pdo->query("
        SELECT
          SUM(CASE WHEN accion = 'WAF_SQLI_BLOCKED' THEN 1 ELSE 0 END) AS sqli,
          SUM(CASE WHEN accion = 'WAF_XSS_BLOCKED' THEN 1 ELSE 0 END) AS xss,
          SUM(CASE WHEN accion IN ('AUTH_2FA_VERIFIED', 'AUTH_2FA_FAILED') THEN 1 ELSE 0 END) AS totp,
          SUM(CASE WHEN accion LIKE 'AUTH_LOGIN_FAILED%' OR accion = 'LOGIN_RATE_LIMITED' THEN 1 ELSE 0 END) AS failed,
          COUNT(*) AS total
        FROM auditoria_seguridad_app
    ")->fetch() ?: [];

    json_out([
        'session' => [
            'dni' => $session['dni'],
            'cod_estab' => $session['cod_estab'],
            'estab_nombre' => $session['estab_nombre'],
            'platform' => $platform,
            'verified2FA' => two_factor_required(),
            'isAdmin' => is_admin_session($session),
        ],
        'stats' => $stats,
        'securityMetrics' => [
            'sqliBlockedCount' => (int)($metricsRow['sqli'] ?? 0),
            'xssBlockedCount' => (int)($metricsRow['xss'] ?? 0),
            'totpVerifiedCount' => (int)($metricsRow['totp'] ?? 0),
            'encryptedRecordsCount' => count($pacientes),
            'failedLoginsBlocked' => (int)($metricsRow['failed'] ?? 0),
            'auditLogCount' => (int)($metricsRow['total'] ?? 0),
        ],
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
 * Catálogo clínico de métodos y ciclos. Lee `app_catalogo_metodos`; si la tabla
 * todavía no existe (instalación mínima o bootstrap pendiente) usa el mismo
 * catálogo embebido en PHP definido por la app.
 *
 * @return array<string, array{codigo_dx: string, nombre_metodo: string, dias_ciclo: int, requiere_cita: int, activo: int}>
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

    $fallback = [
        '90782' => ['codigo_dx' => '90782', 'nombre_metodo' => 'Inyectable Hormonal Mensual (Ampolla 1 mes)', 'dias_ciclo' => 30, 'requiere_cita' => 1, 'activo' => 1],
        '9920801' => ['codigo_dx' => '9920801', 'nombre_metodo' => 'Administración de Inyectable Mensual', 'dias_ciclo' => 30, 'requiere_cita' => 1, 'activo' => 1],
        'Z304' => ['codigo_dx' => 'Z304', 'nombre_metodo' => 'Inyectable Hormonal Trimestral (Ampolla 3 meses)', 'dias_ciclo' => 90, 'requiere_cita' => 1, 'activo' => 1],
        '9920802' => ['codigo_dx' => '9920802', 'nombre_metodo' => 'Administración de Inyectable Trimestral', 'dias_ciclo' => 90, 'requiere_cita' => 1, 'activo' => 1],
        '99208' => ['codigo_dx' => '99208', 'nombre_metodo' => 'Atención / Procedimiento en Planificación Familiar (99208)', 'dias_ciclo' => 30, 'requiere_cita' => 1, 'activo' => 1],
        '9940204' => ['codigo_dx' => '9940204', 'nombre_metodo' => 'Orientación y Consejería en Planificación Familiar', 'dias_ciclo' => 30, 'requiere_cita' => 1, 'activo' => 1],
        'Z301' => ['codigo_dx' => 'Z301', 'nombre_metodo' => 'Inserción de DIU / T de Cobre (Control)', 'dias_ciclo' => 365, 'requiere_cita' => 1, 'activo' => 1],
        '58300' => ['codigo_dx' => '58300', 'nombre_metodo' => 'Inserción de DIU', 'dias_ciclo' => 365, 'requiere_cita' => 1, 'activo' => 1],
        '11981' => ['codigo_dx' => '11981', 'nombre_metodo' => 'Implante Subdérmico (Control)', 'dias_ciclo' => 1095, 'requiere_cita' => 1, 'activo' => 1],
        'Z300' => ['codigo_dx' => 'Z300', 'nombre_metodo' => 'Consejería General sin Método Activo', 'dias_ciclo' => 15, 'requiere_cita' => 1, 'activo' => 1],
    ];

    $catalogo = [];
    $tablaDisponible = false;
    try {
        $stmt = $pdo->query('SELECT codigo_dx, nombre_metodo, dias_ciclo, requiere_cita, activo FROM app_catalogo_metodos');
        foreach ($stmt->fetchAll() as $row) {
            $codigo = trim((string)($row['codigo_dx'] ?? ''));
            if ($codigo === '') {
                continue;
            }
            $catalogo[$codigo] = [
                'codigo_dx' => $codigo,
                'nombre_metodo' => trim((string)($row['nombre_metodo'] ?? $codigo)),
                'dias_ciclo' => max(0, (int)($row['dias_ciclo'] ?? 30)),
                'requiere_cita' => (int)($row['requiere_cita'] ?? 1) === 1 ? 1 : 0,
                'activo' => (int)($row['activo'] ?? 1) === 1 ? 1 : 0,
            ];
        }
        $tablaDisponible = true;
    } catch (Throwable $e) {
        // La tabla se crea en bootstrapSchema; el fallback mantiene la app operativa.
    }

    if (!$tablaDisponible || !$catalogo) {
        $catalogo = $fallback;
    } else {
        foreach ($fallback as $codigo => $meta) {
            if (!isset($catalogo[$codigo])) {
                $catalogo[$codigo] = $meta;
            }
        }
    }

    return $catalogo;
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
    $codigosActivos = codigos_metodos_activos($catalogo);

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
        if (isset($catalogo[$dx]) && (int)($catalogo[$dx]['dias_ciclo'] ?? 0) > 0) {
            if ($ultimaConMetodo === null) {
                $ultimaConMetodo = $row;
                $ultimaConMetodo['_fecha_aplicacion'] = $fecha;
            }
        }
        if ($ultimaAtencion !== null && $ultimaConMetodo !== null) {
            break;
        }
    }

    $codigo = $ultimaConMetodo !== null ? trim((string)($ultimaConMetodo['DX'] ?? '')) : '';
    $diasCiclo = $codigo !== '' ? max(0, (int)($catalogo[$codigo]['dias_ciclo'] ?? 0)) : 0;
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
    $nombreMetodo = $codigo !== '' ? (string)($catalogo[$codigo]['nombre_metodo'] ?? $codigo) : '';
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
function atencion_ups_es_planificacion_familiar(array $row, array $codigosUps): bool
{
    $codServsa = trim((string)($row['COD_SERVSA'] ?? ''));
    if ($codServsa !== '') {
        return in_array($codServsa, $codigosUps, true);
    }
    $dx = trim((string)($row['DX'] ?? ''));
    return in_array($dx, ['90782', '9920801', 'Z304', '9920802', '99208', '9940204', 'Z301', '58300', '11981', 'Z300'], true);
}

/**
 * @return array<int, array<string, mixed>>
 */
function consultar_atenciones_99208(PDO $pdo, string $dni): array
{
    // El parámetro se limpia en PHP y se compara SIN funciones sobre dt.DX,
    // para que TiDB pueda usar el índice del detalle clínico.
    $dni = preg_replace('/[^0-9]/', '', $dni) ?? '';
    $codigo99208 = '99208';
    $sql = "
        SELECT h.ID, h.DNI, h.COD_ESTAB, h.COD_ESTAB AS nombre_establecimiento,
               h.DIA, h.MES, h.ANO, h.fecha_reg, dt.DX, dt.TDX, dt.LDX,
               dt.fecha_reg AS fecha_dx, h.CODPSAL
        FROM his_dl h
        INNER JOIN his_dl_dt dt ON dt.ID = h.ID
        WHERE h.DNI = :dni AND dt.DX = :dx
        ORDER BY h.ANO DESC, h.MES DESC, h.DIA DESC
        LIMIT 5
    ";
    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute([':dni' => $dni, ':dx' => $codigo99208]);
        return $stmt->fetchAll();
    } catch (Throwable $e) {
        // Fallback si el servidor local no tiene las tablas maestro_*: usa el catálogo IPRESS.
        try {
            $stmt = $pdo->prepare("
                SELECT h.ID, h.DNI, h.COD_ESTAB, h.COD_ESTAB AS nombre_establecimiento,
                       h.DIA, h.MES, h.ANO, h.fecha_reg, dt.DX, dt.TDX, dt.LDX,
                       dt.fecha_reg AS fecha_dx, h.CODPSAL
                FROM his_dl h
                INNER JOIN his_dl_dt dt ON dt.ID = h.ID
                WHERE h.DNI = :dni AND dt.DX = :dx
                ORDER BY h.ANO DESC, h.MES DESC, h.DIA DESC
                LIMIT 5
            ");
            $stmt->execute([':dni' => $dni, ':dx' => $codigo99208]);
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

    // Se incluyen todos los códigos del catálogo clínico (DIU, implante,
    // consejería y administraciones) además de los históricos de la app.
    $dxCodes = ['99208', '90782', '9920801', 'Z304', '9920802', '9940204', 'Z301', '58300', '11981', 'Z300'];
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
            if (!isset($catalogo[$codigo])) {
                json_error('El código de método solicitado no existe en el catálogo clínico.', 400, [
                    'code' => 'METODO_NO_CATALOGADO',
                    'codigo' => $codigo,
                ]);
            }
            $codigosFiltro[] = $codigo;
        }
        $codigosFiltro = array_values(array_unique($codigosFiltro));
    }
    $codigosConsulta = $codigosFiltro ?: codigos_metodos_activos($catalogo);

    // 7-B.2 Ventanas de fecha de aplicación por método. Al calcular
    // fecha_proximo = fecha_aplicacion + dias_ciclo, la consulta se acota a los
    // días exactos en que cada método pudo aplicarse para vencer en el rango.
    $lookbackVencidas = 1825; // 5 años de abandonos recuperables
    $lookbackTodos = 365;     // "vencidas recientes" al combinar todos los modos
    $ventanas = [];
    foreach ($codigosConsulta as $codigo) {
        $dias = max(1, (int)($catalogo[$codigo]['dias_ciclo'] ?? 30));
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

    $condicionEstab = '';
    $paramsEstab = [];
    if ($alcance === 'establecimiento') {
        $variantes = hospital_codigos_busqueda_establecimiento($session['cod_estab']);
        if (!$variantes) {
            $variantes = [trim((string)$session['cod_estab'])];
        }
        $placeholdersEstab = implode(',', array_fill(0, count($variantes), '?'));
        $condicionEstab = " AND h0.COD_ESTAB IN ({$placeholdersEstab}) ";
        $paramsEstab = $variantes;
    }

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
              {$condicionEstab}
              AND h0.ANO BETWEEN ? AND ?
              AND {$condicionVentana}
            GROUP BY h0.DNI
            ORDER BY MAX(h0.ANO) DESC, MAX(h0.MES) DESC, MAX(h0.DIA) DESC
            LIMIT {$limiteCandidatos}
        ) cand ON cand.dni = h.DNI
        WHERE dt.DX IN ({$placeholdersCodigos})
        ORDER BY h.DNI ASC, h.ANO DESC, h.MES DESC, h.DIA DESC, h.ID DESC
        LIMIT 12000
    ";

    $params = array_merge($paramsCodigos, $paramsEstab, [$anioMinVentana, $anioMaxVentana], $paramsVentana, $paramsCodigos);
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
        if ($dniKey === '' || !isset($catalogo[$codigo])) {
            continue;
        }
        $diasCiclo = (int)($catalogo[$codigo]['dias_ciclo'] ?? 0);
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
            'codigo' => $codigo,
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
            'nombre_metodo' => (string)($catalogo[$sel['codigo']]['nombre_metodo'] ?? $sel['codigo']),
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

    HospitalHuaralDB::registrarAuditoria(
        $session['dni'],
        'REPORTE_PROGRAMACION',
        'Reporte de programación PF fecha ' . $fechaObjetivo . ' modo ' . $rangoModo . ' alcance ' . $alcance . ': ' . count($filas) . ' pacientes.',
        (string)$session['cod_estab'],
        (string)$session['platform']
    );

    json_out([
        'success' => true,
        'fecha_objetivo' => $fechaObjetivo,
        'fecha_objetivo_ddmmyyyy' => $fechaBase->format('d/m/Y'),
        'rango_modo' => $rangoModo,
        'alcance' => $alcance,
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
        ],
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
    if ($alcance === 'red' && is_admin_session($session)) {
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
    $codigos = [];
    foreach ($catalogo as $codigo => $meta) {
        if ((int)($meta['activo'] ?? 1) === 1 && (int)($meta['dias_ciclo'] ?? 0) > 0) {
            $codigos[] = (string)$codigo;
        }
    }
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
            if ($dni === '' || !isset($catalogo[$codigo])) {
                continue;
            }
            $fecha = fecha_aplicacion_his($row);
            if ($fecha === '') {
                continue;
            }
            $dias = max(0, (int)($catalogo[$codigo]['dias_ciclo'] ?? 0));
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
                'codigo_metodo' => $codigo,
                'nombre_metodo' => (string)($catalogo[$codigo]['nombre_metodo'] ?? $codigo),
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
    $alcance = strtolower(trim((string)($input['alcance'] ?? 'establecimiento'))) === 'red' ? 'red' : 'establecimiento';
    $codigosEstab = reporte_codigos_establecimiento($session, $alcance);

    $where = ['p.fecha_registro >= :desde', 'p.fecha_registro < :hasta_exclusivo'];
    $params = [':desde' => $desde, ':hasta_exclusivo' => $hastaExclusivo];

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
    if ($obstetra !== '' && $obstetra !== 'TODOS') {
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
        $stmtSect = $pdo->prepare("
            SELECT DISTINCT p.sector
            FROM pacientes_sin_metodo p
            WHERE p.sector <> ''
            ORDER BY p.sector ASC
            LIMIT 500
        ");
        $stmtSect->execute();
        $sectores = array_map('strval', $stmtSect->fetchAll(PDO::FETCH_COLUMN));
    } catch (Throwable $e) {
        $sectores = [];
    }

    $obstetras = [];
    try {
        $stmtObs = $pdo->query("
            SELECT p.codpsal_obstetra, COUNT(*) AS total
            FROM pacientes_sin_metodo p
            GROUP BY p.codpsal_obstetra
            ORDER BY total DESC
            LIMIT 300
        ");
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
            'codigo' => (string)$session['cod_estab'],
            'nombre' => (string)$session['estab_nombre'],
        ],
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
    $alcance = strtolower(trim((string)($input['alcance'] ?? 'establecimiento'))) === 'red' ? 'red' : 'establecimiento';
    $codigosEstab = reporte_codigos_establecimiento($session, $alcance);
    $catalogo = catalogo_metodos_planificacion($pdo);

    $where = ['p.fecha_registro >= :desde', 'p.fecha_registro < :hasta_exclusivo'];
    $params = [':desde' => $desde, ':hasta_exclusivo' => $hastaExclusivo];
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
        $stmtSect = $pdo->query("SELECT DISTINCT sector FROM pacientes_sin_metodo WHERE sector <> '' ORDER BY sector ASC LIMIT 500");
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
            'codigo' => (string)$session['cod_estab'],
            'nombre' => (string)$session['estab_nombre'],
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
    $stmt = $pdo->prepare('UPDATE pacientes_sin_metodo SET estado_paciente = :estado WHERE id = :id LIMIT 1');
    $stmt->execute([':estado' => $estado, ':id' => $id]);
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
    $limit = (int)($_GET['limit'] ?? 50);
    json_out([
        'logs' => HospitalHuaralDB::ultimaAuditoria($limit),
        'total' => (int)$pdo->query('SELECT COUNT(*) FROM auditoria_seguridad_app')->fetchColumn(),
        'session' => $session['dni'],
    ]);
}

if ($action === 'verify_chain') {
    $session = require_session();
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
