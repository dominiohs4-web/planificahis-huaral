<?php
/**
 * api.php — API REST clínica blindada
 * Hospital San Juan Bautista Huaral / Red de Salud Huaral-Chancay
 *
 * Endpoints principales:
 *   GET  ?action=establecimientos
 *   POST ?action=login | register_obstetra | logout
 *   GET  ?action=session_restore | overview | lookup_dni | audit_logs | reporte_campo | reporte_metodos
 *   POST ?action=save_paciente | update_estado | change_establecimiento | invalidar_alertas | save_metodo
 *        ?action=verify_chain | test_waf
 *
 * Seguridad: PDO nativo persistente, WAF SQLi/XSS, rate limiting,
 * Bearer Token HMAC-SHA256 + cookie HttpOnly, sesión persistente de 7 días
 * (sliding expiration), AES-256-GCM y cadena de auditoría SHA-256.
 */
declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/catalogo_establecimientos.php';

if (!defined('SUPER_ADMIN_DNI')) {
    define('SUPER_ADMIN_DNI', '75100725');
}

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
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private');
header('Pragma: no-cache');
header('Expires: 0');
header('Content-Security-Policy: default-src \'none\'; frame-ancestors \'none\'; base-uri \'none\'; form-action \'none\'; object-src \'none\'');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cross-Origin-Resource-Policy: same-origin');
header('X-Permitted-Cross-Domain-Policies: none');
header('Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=()');
header('Vary: Authorization, X-App-Token, Cookie');

// ---------------------------------------------------------------------------
// MANEJADOR GLOBAL DE ERRORES: NINGÚN endpoint puede devolver un HTTP 500
// vacío de Apache. Toda excepción se registra y se responde SIEMPRE JSON.
// ---------------------------------------------------------------------------
function api_emit_internal_error(Throwable $e): void
{
    error_log(
        '[PlanificaHIS API Error] ' . $e->getMessage()
        . ' en ' . $e->getFile() . ':' . $e->getLine()
    );
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    }
    echo json_encode([
        'error' => 'Ocurrió un error interno controlado en el servidor clínico. ' .
                   'El detalle técnico quedó registrado en el log para Estadística e Informática.',
        'code' => 'API_INTERNAL_ERROR',
        'action' => (string)($_GET['action'] ?? ''),
        'timestamp' => date('c'),
    ], JSON_UNESCAPED_UNICODE);
}

set_exception_handler(static function (Throwable $e): void {
    api_emit_internal_error($e);
});

register_shutdown_function(static function (): void {
    $err = error_get_last();
    if ($err === null) {
        return;
    }
    if (!in_array((int)$err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) {
        return;
    }
    api_emit_internal_error(new ErrorException(
        (string)$err['message'],
        0,
        (int)$err['type'],
        (string)$err['file'],
        (int)$err['line']
    ));
});

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
        header('Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With, X-Sync-Token, X-App-Token');
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
    $esSuperAdmin = hospital_es_super_admin($dni);
    $acceso = $dni !== '' ? HospitalHuaralDB::accesoUsuario($dni) : null;
    if ($acceso === null && !$esSuperAdmin) {
        json_error('Su cuenta no existe en la tabla única app_usuarios. Solicite al Administrador de Estadística que la active.', 403, [
            'code' => 'ACCESS_NOT_FOUND',
        ]);
    }
    if (!$esSuperAdmin && !HospitalHuaralDB::accesoActivo($dni)) {
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
    $codEstab = normalizarCodEstab((string)($session['cod_estab'] ?? ($acceso['cod_estab'] ?? '000005481')));
    if ($codEstab === '') {
        $codEstab = '000005481';
    }
    $codEstabAsignado = normalizarCodEstab((string)($acceso['cod_estab'] ?? ''));
    if ($codEstabAsignado === 'ALL' || hospital_establecimiento($codEstabAsignado) === null) {
        $codEstabAsignado = '';
    }
    $rol = HospitalHuaralDB::rolUsuario($dni);
    $esAdmin = is_admin_session([
        'dni' => $dni,
        'rol' => $rol,
        'puede_ver_red' => $session['puede_ver_red'] ?? ($acceso['puede_ver_red'] ?? 0),
    ]);
    $esRed = $esAdmin && $codEstab === 'ALL';
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
        'cod_estab_asignado' => $codEstabAsignado,
        'estab_nombre' => $esRed
            ? 'TODA LA RED HUARAL-CHANCAY (53 IPRESS)'
            : hospital_nombre_establecimiento($codEstab),
        'alcance_red' => $esRed,
        'verified2FA' => false,
        'platform' => (string)($session['platform'] ?? 'Web Desktop'),
        'isAdmin' => $esAdmin,
        'esSuperAdmin' => hospital_es_super_admin($dni),
        'protegido' => (int)($acceso['protegido'] ?? 0) === 1 || hospital_es_super_admin($dni),
        'isJefa' => es_jefa_session(['dni' => $dni]),
        'puedeVerRed' => $esAdmin,
        'puedeCambiarEstablecimiento' => $esAdmin,
        'puedeGestionarAccesos' => $esAdmin,
        'puedeResetearObstetra' => puede_resetear_obstetra(['dni' => $dni]),
        'accesoActivo' => HospitalHuaralDB::accesoActivo($dni),
        'expires_at' => (int)($session['expires_at'] ?? (time() + HospitalHuaralDB::SESSION_TTL)),
        'session_ttl' => HospitalHuaralDB::SESSION_TTL,
    ];
}

function rol_sesion(array $session): string
{
    return HospitalHuaralDB::rolUsuario((string)($session['dni'] ?? ''));
}

function es_super_admin_session(array $session): bool
{
    return hospital_es_super_admin((string)($session['dni'] ?? ''));
}

function es_admin_superior_session(array $session): bool
{
    return hospital_es_rol_admin_superior(rol_sesion($session));
}

function es_obstetra_session(array $session): bool
{
    return rol_sesion($session) === 'OBSTETRA';
}

/**
 * Bloquea cualquier intento de un actor distinto de la Cuenta Maestra de
 * modificar o desactivar el DNI 75100725. Registra auditoría forense y
 * responde con el JSON exacto exigido por la jefatura.
 */
function denegar_superadmin_protegido(array $session, string $dniObjetivo, string $contexto): void
{
    if (!hospital_es_super_admin($dniObjetivo)) {
        return;
    }
    if (hospital_es_super_admin((string)($session['dni'] ?? ''))) {
        return;
    }
    HospitalHuaralDB::registrarAuditoria(
        (string)($session['dni'] ?? ''),
        'INTENTO_MODIFICAR_SUPERADMIN',
        'Intento bloqueado de ' . $contexto . ' sobre la Cuenta Maestra DNI ' . SUPER_ADMIN_DNI . '.',
        (string)($session['cod_estab'] ?? ''),
        (string)($session['platform'] ?? 'Web Desktop')
    );
    json_out([
        'ok' => false,
        'error' => 'ACCESO DENEGADO: Usted no tiene privilegios para modificar datos ni desactivar la cuenta del Super Administrador Principal del Sistema.',
    ], 403);
}

/** ¿La cuenta objetivo es otro Administrador de Estadística? */
function es_admin_estadistica_objetivo(?array $acceso): bool
{
    if ($acceso === null) {
        return false;
    }
    return strtoupper(trim((string)($acceso['rol'] ?? ''))) === 'ADMIN_ESTADISTICA';
}

/**
 * Normaliza el tipo de documento a las siglas usadas por la PWA.
 * Acepta también los códigos COD_DOC del HIS (1, 2, 3, 4, 6).
 */
function tipo_documento_normalizado(?string $tipo): string
{
    $tipo = strtoupper(trim((string)$tipo));
    return match ($tipo) {
        '', 'DNI', '1', 'DOCUMENTO NACIONAL DE IDENTIDAD' => $tipo === '' ? '' : 'DNI',
        'CE', 'C.E.', 'CARNET DE EXTRANJERIA', 'CARNET DE EXTRANJERÍA', '2' => 'CE',
        'PASAPORTE', 'PASSPORT', '3' => 'PASAPORTE',
        'PTP', 'PERMISO TEMPORAL DE PERMANENCIA', '4' => 'PTP',
        'CNV', '6', 'OTRO', 'OTROS', 'SIS', 'CNV/SIS' => 'CNV',
        default => $tipo,
    };
}

/**
 * Valida y normaliza un documento según su tipo.
 *
 * @return array{ok: bool, tipo: string, documento: string, error: string}
 */
function validar_documento_paciente(string $documento, ?string $tipo = null): array
{
    $documento = strtoupper(preg_replace('/\s+/', '', trim($documento)) ?? '');
    $documento = preg_replace('/[^0-9A-Z\-]/', '', $documento) ?? '';
    $tipo = tipo_documento_normalizado($tipo);
    if ($tipo === '') {
        $tipo = preg_match('/^[0-9]{8}$/', $documento) ? 'DNI' : 'PASAPORTE';
    }
    $patrones = [
        'DNI' => '/^[0-9]{8}$/',
        'CE' => '/^[A-Z0-9]{9,12}$/',
        'PASAPORTE' => '/^[A-Z0-9]{6,12}$/',
        'PTP' => '/^[A-Z0-9\-]{6,15}$/',
        'CNV' => '/^[A-Z0-9\-]{6,15}$/',
    ];
    $patron = $patrones[$tipo] ?? null;
    if ($patron === null) {
        return ['ok' => false, 'tipo' => $tipo, 'documento' => $documento, 'error' => 'Tipo de documento no válido.'];
    }
    if ($documento === '' || !preg_match($patron, $documento)) {
        $mensajes = [
            'DNI' => 'El DNI debe tener exactamente 8 dígitos numéricos.',
            'CE' => 'El Carné de Extranjería debe tener entre 9 y 12 caracteres alfanuméricos.',
            'PASAPORTE' => 'El Pasaporte debe tener entre 6 y 12 caracteres alfanuméricos.',
            'PTP' => 'El Permiso Temporal de Permanencia debe tener entre 6 y 15 caracteres alfanuméricos.',
            'CNV' => 'El documento CNV/SIS debe tener entre 6 y 15 caracteres alfanuméricos.',
        ];
        return ['ok' => false, 'tipo' => $tipo, 'documento' => $documento, 'error' => $mensajes[$tipo] ?? 'Documento no válido.'];
    }
    return ['ok' => true, 'tipo' => $tipo, 'documento' => $documento, 'error' => ''];
}

/** Etiqueta legible del tipo de documento. */
function etiqueta_tipo_documento(?string $tipo): string
{
    return match (tipo_documento_normalizado($tipo)) {
        'DNI' => 'DNI',
        'CE' => 'Carné de Extranjería',
        'PASAPORTE' => 'Pasaporte',
        'PTP' => 'Permiso Temporal de Permanencia (PTP)',
        'CNV' => 'CNV / SIS u otro documento',
        default => 'Documento de identidad',
    };
}

function is_admin_session(array $session): bool
{
    $dni = (string)($session['dni'] ?? '');
    $rol = strtoupper(trim((string)($session['rol'] ?? '')));
    if ($rol === '' && $dni !== '') {
        $rol = HospitalHuaralDB::rolUsuario($dni);
    }
    $puedeVerRed = !empty($session['puede_ver_red']);
    if (!$puedeVerRed && $dni !== '') {
        $acceso = HospitalHuaralDB::accesoUsuario($dni) ?: [];
        $puedeVerRed = !empty($acceso['puede_ver_red']);
    }
    if (esAdminSuperior(['dni' => $dni, 'rol' => $rol, 'puede_ver_red' => $puedeVerRed])) {
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

/**
 * Alcance de red unificado: SUPER_ADMIN, ADMIN_ESTADISTICA, la Cuenta Maestra
 * 75100725 o cualquier cuenta marcada con `puede_ver_red = 1`.
 */
function puede_ver_red(array $session): bool
{
    return is_admin_session($session);
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
 * Códigos equivalentes del establecimiento de la sesión, cruzando las tablas
 * históricas de la Red (9 dígitos, 8 dígitos, sin ceros y código corto).
 * Para el alcance de red "ALL" devuelve [] (sin filtro).
 *
 * @return array<int, string>
 */
function codigos_establecimiento_sesion(array $session): array
{
    $codigo = trim((string)($session['cod_estab'] ?? ''));
    if ($codigo === '') {
        $acceso = HospitalHuaralDB::accesoUsuario((string)($session['dni'] ?? '')) ?: [];
        $codigo = trim((string)($acceso['cod_estab'] ?? ''));
    }
    $normalizado = normalizarCodEstab($codigo);
    if ($normalizado === 'ALL') {
        return [];
    }
    $pdo = HospitalHuaralDB::getConnection();
    $codigos = obtenerCodigosEstablecimientoEquivalentes($pdo, $normalizado);
    if ($codigos) {
        return $codigos;
    }
    $canonico = hospital_codigo_canonico($normalizado);
    $base = $canonico !== '' ? $canonico : $normalizado;
    $digitos = preg_replace('/[^0-9]/', '', $base) ?? '';
    if ($digitos === '') {
        return $base !== '' ? [$base] : [];
    }
    return array_values(array_unique([
        str_pad($digitos, 9, '0', STR_PAD_LEFT),
        str_pad($digitos, 8, '0', STR_PAD_LEFT),
        ltrim($digitos, '0') !== '' ? ltrim($digitos, '0') : '0',
    ]));
}

/**
 * ¿Existen atenciones en `his_dl` para algunos de los códigos equivalentes?
 * Se usa como interruptor de seguridad: si el HIS no reconoce el formato del
 * establecimiento, el filtro se desactiva automáticamente para no devolver
 * alertas/programación vacías.
 *
 * @param array<int, string> $codigos
 */
function his_dl_tiene_codigos(PDO $pdo, array $codigos): bool
{
    static $cache = [];
    $codigos = array_values(array_unique(array_filter(array_map(
        static fn ($codigo): string => trim((string)$codigo),
        $codigos
    ), static fn (string $codigo): bool => $codigo !== '')));
    if (!$codigos) {
        return false;
    }
    $clave = implode('|', $codigos);
    if (array_key_exists($clave, $cache)) {
        return $cache[$clave];
    }
    try {
        $marcas = implode(',', array_fill(0, count($codigos), '?'));
        $stmt = $pdo->prepare("SELECT 1 FROM his_dl WHERE COD_ESTAB IN ({$marcas}) LIMIT 1");
        $stmt->execute($codigos);
        return $cache[$clave] = (bool)$stmt->fetchColumn();
    } catch (Throwable $e) {
        return $cache[$clave] = false;
    }
}

/**
 * Códigos que deben aplicarse a consultas clínicas (alertas, agenda, KPI y
 * programación). Si `his_dl` no tiene filas para el establecimiento, se
 * devuelve [] para consultar toda la programación sin bloquear la atención.
 *
 * @return array<int, string>
 */
function codigos_establecimiento_consulta(PDO $pdo, array $session): array
{
    $codigos = codigos_establecimiento_sesion($session);
    if (!$codigos) {
        return [];
    }
    return his_dl_tiene_codigos($pdo, $codigos) ? $codigos : [];
}

/**
 * DNIs de obstetras activas asignadas a los establecimientos indicados. Se usa
 * como respaldo cuando `pacientes_sin_metodo.cod_estab` quedó guardado con un
 * formato distinto al del catálogo.
 *
 * @param array<int, string> $codigos
 * @return array<int, string>
 */
function dnis_obstetras_establecimiento(PDO $pdo, array $codigos): array
{
    $codigos = array_values(array_unique(array_filter(array_map(
        static fn ($codigo): string => trim((string)$codigo),
        $codigos
    ), static fn (string $codigo): bool => $codigo !== '')));
    if (!$codigos) {
        return [];
    }
    try {
        $marcas = implode(',', array_fill(0, count($codigos), '?'));
        $stmt = $pdo->prepare("
            SELECT DISTINCT dni
            FROM app_usuarios
            WHERE UPPER(TRIM(rol)) = 'OBSTETRA'
              AND activo = 1
              AND cod_estab IN ({$marcas})
        ");
        $stmt->execute($codigos);
        return array_values(array_filter(array_map(
            static fn ($dni): string => trim((string)$dni),
            $stmt->fetchAll(PDO::FETCH_COLUMN)
        ), static fn (string $dni): bool => $dni !== ''));
    } catch (Throwable $e) {
        return [];
    }
}

/**
 * Condición de alcance sobre `pacientes_sin_metodo` para el establecimiento.
 *  - ADMIN en ALL: sin filtro.
 *  - ADMIN con IPRESS: códigos equivalentes.
 *  - JEFA / OBSTETRA: códigos equivalentes + obstetras asignadas a su IPRESS.
 *
 * Devuelve placeholders nombrados con prefijo para poder combinarse con los
 * filtros de fecha/estado que ya usan parámetros nombrados.
 *
 * @return array{0: string, 1: array<string, string>}
 */
function condicion_alcance_establecimiento(PDO $pdo, array $session, string $alias = 'p', string $obstetraFiltro = '', string $prefijo = 'alc'): array
{
    $alias = preg_replace('/[^A-Za-z0-9_]/', '', $alias) ?: 'p';
    $prefijo = preg_replace('/[^A-Za-z0-9_]/', '', $prefijo) ?: 'alc';
    $esAdmin = is_admin_session($session);
    if ($esAdmin && normalizarCodEstab((string)($session['cod_estab'] ?? '')) === 'ALL') {
        if ($obstetraFiltro === '') {
            return ['', []];
        }
        return [
            $alias . '.codpsal_obstetra = :' . $prefijo . '_obstetra',
            [':' . $prefijo . '_obstetra' => $obstetraFiltro],
        ];
    }

    $codigos = codigos_establecimiento_sesion($session);
    $dnis = $esAdmin ? [] : dnis_obstetras_establecimiento($pdo, $codigos);
    $condiciones = [];
    $params = [];
    if ($codigos) {
        $marcas = [];
        foreach (array_values($codigos) as $i => $codigo) {
            $marca = ':' . $prefijo . '_estab' . $i;
            $marcas[] = $marca;
            $params[$marca] = $codigo;
        }
        $condiciones[] = $alias . '.cod_estab IN (' . implode(',', $marcas) . ')';
    }
    if ($dnis) {
        $marcasDni = [];
        foreach (array_values($dnis) as $i => $dni) {
            $marcaDni = ':' . $prefijo . '_dni' . $i;
            $marcasDni[] = $marcaDni;
            $params[$marcaDni] = $dni;
        }
        $condiciones[] = $alias . '.codpsal_obstetra IN (' . implode(',', $marcasDni) . ')';
    }
    if (!$condiciones) {
        return [$obstetraFiltro === '' ? '1=0' : $alias . '.codpsal_obstetra = :' . $prefijo . '_obstetra', $obstetraFiltro === '' ? [] : [':' . $prefijo . '_obstetra' => $obstetraFiltro]];
    }
    $sql = '(' . implode(' OR ', $condiciones) . ')';
    if ($obstetraFiltro !== '') {
        $sql .= ' AND ' . $alias . '.codpsal_obstetra = :' . $prefijo . '_obstetra';
        $params[':' . $prefijo . '_obstetra'] = $obstetraFiltro;
    }
    return [$sql, $params];
}

/**
 * Alcance de la pestaña Pacientes:
 *  - OBSTETRA: solo sus propias captaciones (sin bloquear por cod_estab).
 *  - JEFA: todo su establecimiento + captaciones de sus obstetras asignadas.
 *  - ADMIN: red completa en ALL o la IPRESS elegida.
 *
 * @return array{0: string, 1: array<string, string>}
 */
function condicion_alcance_pacientes(PDO $pdo, array $session, string $alias = 'p', string $obstetraFiltro = '', string $prefijo = 'alc'): array
{
    $alias = preg_replace('/[^A-Za-z0-9_]/', '', $alias) ?: 'p';
    $prefijo = preg_replace('/[^A-Za-z0-9_]/', '', $prefijo) ?: 'alc';
    $rol = rol_sesion($session);
    if ($rol === 'OBSTETRA' && !is_admin_session($session)) {
        return [
            $alias . '.codpsal_obstetra = :' . $prefijo . '_propio',
            [':' . $prefijo . '_propio' => (string)($session['dni'] ?? '')],
        ];
    }
    return condicion_alcance_establecimiento($pdo, $session, $alias, $obstetraFiltro, $prefijo);
}

/**
 * Establecimiento donde se REGISTRA una captación. Si el administrador está
 * en alcance "ALL", se usa la IPRESS asignada a su cuenta en app_usuarios.
 */
function establecimiento_registro_sesion(array $session): string
{
    $codigo = normalizarCodEstab((string)($session['cod_estab'] ?? ''));
    if ($codigo !== 'ALL' && hospital_establecimiento($codigo) !== null) {
        return $codigo;
    }
    $acceso = HospitalHuaralDB::accesoUsuario((string)($session['dni'] ?? '')) ?: [];
    $asignado = normalizarCodEstab((string)($acceso['cod_estab'] ?? ''));
    if ($asignado !== 'ALL' && hospital_establecimiento($asignado) !== null) {
        return $asignado;
    }
    return '000005481';
}

/**
 * Variantes indexables de un DNI de colegiado tal como puede estar guardado en
 * `his_dl.CODPSAL` (con o sin prefijo 0/1/2 y con ceros a la izquierda).
 * Se usan SOLO en filtros opcionales por obstetra; nunca como filtro forzado.
 *
 * @return array<int, string>
 */
function variantes_codpsal_dni(string $dni): array
{
    $dni = preg_replace('/[^0-9A-Za-z]/', '', $dni) ?? '';
    if ($dni === '') {
        return [];
    }
    $variantes = [$dni, '1' . $dni, '0' . $dni, '2' . $dni, ltrim($dni, '0')];
    return array_values(array_unique(array_filter(array_map('strval', $variantes), static fn (string $v): bool => trim($v) !== '')));
}

/**
 * Alcance de red: SOLO administradores superiores con sesión "ALL". Si el
 * administrador eligió una IPRESS concreta, no puede ampliar el alcance por
 * parámetro: el selector de la cabecera es la única fuente de verdad.
 */
function es_alcance_red(array $session, string $alcance = ''): bool
{
    if (!is_admin_session($session)) {
        return false;
    }
    return normalizarCodEstab((string)($session['cod_estab'] ?? '')) === 'ALL';
}

/**
 * Resuelve el alcance efectivo de CUALQUIER reporte aplicando la jerarquía:
 *  - OBSTETRA: siempre su propio DNI y su establecimiento (ignora parámetros).
 *  - JEFA_OBSTETRAS: siempre su establecimiento; puede elegir una obstetra
 *    suya o "TODAS", pero nunca otra IPRESS ni alcance de red.
 *  - ADMIN_ESTADISTICA / SUPER_ADMIN: red completa o establecimiento, con
 *    filtro opcional por obstetra.
 *
 * @return array{
 *   solo_mis: bool, dni_obstetra: string, codigos_estab: array<int, string>,
 *   alcance_red: bool, rol: string, es_jefa: bool, es_obstetra: bool
 * }
 */
function resolver_alcance_reporte(array $session, string $obstetraSolicitado = '', string $alcanceSolicitado = 'establecimiento'): array
{
    $rol = rol_sesion($session);
    $esJefa = $rol === 'JEFA_OBSTETRAS';
    $esAdmin = is_admin_session($session);
    $esObstetra = !$esAdmin && !$esJefa;
    $filtro = preg_replace('/[^0-9A-Za-z]/', '', $obstetraSolicitado) ?? '';
    if ($filtro === 'TODOS') {
        $filtro = '';
    }
    if ($esObstetra) {
        return [
            'solo_mis' => true,
            'dni_obstetra' => (string)($session['dni'] ?? ''),
            'codigos_estab' => codigos_establecimiento_sesion($session),
            'alcance_red' => false,
            'rol' => $rol,
            'es_jefa' => false,
            'es_obstetra' => true,
        ];
    }
    if ($esJefa) {
        return [
            'solo_mis' => false,
            'dni_obstetra' => $filtro,
            'codigos_estab' => codigos_establecimiento_sesion($session),
            'alcance_red' => false,
            'rol' => $rol,
            'es_jefa' => true,
            'es_obstetra' => false,
        ];
    }
    $alcanceRed = es_alcance_red($session, $alcanceSolicitado);
    return [
        'solo_mis' => false,
        'dni_obstetra' => $filtro,
        'codigos_estab' => $alcanceRed ? [] : codigos_establecimiento_sesion($session),
        'alcance_red' => $alcanceRed,
        'rol' => $rol,
        'es_jefa' => false,
        'es_obstetra' => false,
    ];
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
 * Convierte una fecha ISO YYYY-MM-DD en sus componentes enteros. Devuelve null
 * si la fecha no existe (por ejemplo 2026-02-31).
 *
 * @return array{0: int, 1: int, 2: int}|null
 */
function ymd_partes_fecha(string $iso): ?array
{
    $dt = DateTimeImmutable::createFromFormat('!Y-m-d', trim($iso));
    if (!$dt instanceof DateTimeImmutable || $dt->format('Y-m-d') !== trim($iso)) {
        return null;
    }
    return [(int)$dt->format('Y'), (int)$dt->format('n'), (int)$dt->format('j')];
}

/**
 * Condición de rango SARGable sobre las columnas enteras (ANO, MES, DIA) del
 * HIS. NUNCA usa STR_TO_DATE(CONCAT(...)): así TiDB Cloud puede usar los
 * índices compuestos sobre his_dl sin escanear los 5 GB de atenciones.
 *
 * Los parámetros posicionales se agregan a $params en el mismo orden en que
 * aparecen los `?` de la condición devuelta.
 */
function sql_condicion_rango_ymd(string $alias, string $desdeIso, string $hastaIso, array &$params): string
{
    $alias = preg_replace('/[^A-Za-z0-9_.]/', '', $alias) ?: 'h';
    $desde = ymd_partes_fecha($desdeIso);
    $hasta = ymd_partes_fecha($hastaIso);
    if ($desde === null || $hasta === null) {
        return '1 = 0';
    }
    [$y1, $m1, $d1] = $desde;
    [$y2, $m2, $d2] = $hasta;

    // Por seguridad, un rango invertido se normaliza.
    if ($y1 * 10000 + $m1 * 100 + $d1 > $y2 * 10000 + $m2 * 100 + $d2) {
        [$y1, $m1, $d1, $y2, $m2, $d2] = [$y2, $m2, $d2, $y1, $m1, $d1];
    }

    if ($y1 === $y2 && $m1 === $m2 && $d1 === $d2) {
        $params[] = $y1;
        $params[] = $m1;
        $params[] = $d1;
        return "({$alias}.ANO = ? AND {$alias}.MES = ? AND {$alias}.DIA = ?)";
    }

    if ($y1 === $y2 && $m1 === $m2) {
        $params[] = $y1;
        $params[] = $m1;
        $params[] = $d1;
        $params[] = $d2;
        return "({$alias}.ANO = ? AND {$alias}.MES = ? AND {$alias}.DIA BETWEEN ? AND ?)";
    }

    if ($y1 === $y2 && $m2 === $m1 + 1) {
        $params[] = $y1;
        $params[] = $m1;
        $params[] = $d1;
        $params[] = $m2;
        $params[] = $d2;
        return "({$alias}.ANO = ? AND (({$alias}.MES = ? AND {$alias}.DIA >= ?) OR ({$alias}.MES = ? AND {$alias}.DIA <= ?)))";
    }

    // Rangos largos (varios meses o años): se acota por ANO y por la clave
    // numérica YYYYMMDD calculada sobre columnas enteras, sin funciones.
    $params[] = $y1;
    $params[] = $y2;
    $params[] = $y1 * 10000 + $m1 * 100 + $d1;
    $params[] = $y2 * 10000 + $m2 * 100 + $d2;
    return "({$alias}.ANO BETWEEN ? AND ? AND ({$alias}.ANO * 10000 + {$alias}.MES * 100 + {$alias}.DIA) BETWEEN ? AND ?)";
}

/**
 * Comprueba una sola vez por request si un índice existe. Permite usar
 * FORCE INDEX solo cuando el índice ya fue creado, sin romper la app.
 */
function indice_existe(PDO $pdo, string $tabla, string $indice): bool
{
    static $cache = [];
    $clave = $tabla . '|' . $indice;
    if (array_key_exists($clave, $cache)) {
        return $cache[$clave];
    }
    try {
        $stmt = $pdo->prepare('SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?');
        $stmt->execute([$tabla, $indice]);
        return $cache[$clave] = ((int)$stmt->fetchColumn() > 0);
    } catch (Throwable $e) {
        return $cache[$clave] = false;
    }
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
    $esSuperRestore = hospital_es_super_admin((string)$session['dni']);
    if ((!$esSuperRestore && $accesoRestore === null) || (!$esSuperRestore && !HospitalHuaralDB::accesoActivo((string)$session['dni']))) {
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
                ':red' => hospital_es_rol_admin_superior((string)$preactivado['rol']) ? 1 : 0,
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
    if ((int)($user['activo'] ?? 1) !== 1 && !hospital_es_super_admin($dni)) {
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
        // Bcrypt se calcula UNA SOLA VEZ (cost 10) y se reutiliza en el UPDATE
        // y en la sesión. Antes se ejecutaba dos veces seguidas por login.
        $hashedInicial = HospitalHuaralDB::hashPassword($password);
        $pdo->prepare('UPDATE app_usuarios SET clave_hash = :pass WHERE dni = :dni LIMIT 1')
            ->execute([':pass' => $hashedInicial, ':dni' => $dni]);
        $user['clave_hash'] = $hashedInicial;
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

    $rol = HospitalHuaralDB::rolUsuario($dni);
    $esAdmin = esAdminSuperior([
        'dni' => $dni,
        'rol' => $rol,
        'puede_ver_red' => $user['puede_ver_red'] ?? 0,
    ]);
    $esJefa = $rol === 'JEFA_OBSTETRAS';
    $codEstabAsignadoLogin = normalizarCodEstab((string)($user['cod_estab'] ?? ''));
    if ($codEstabAsignadoLogin === 'ALL' || hospital_establecimiento($codEstabAsignadoLogin) === null) {
        $codEstabAsignadoLogin = '';
    }

    if ($esAdmin) {
        // El administrador inicia SIEMPRE en alcance de red completa. El
        // selector de la cabecera podrá fijar luego una IPRESS concreta.
        $codEstab = 'ALL';
        $puedeVerRedGuardado = (int)($user['puede_ver_red'] ?? 0);
        $user['puede_ver_red'] = 1;
        if ($puedeVerRedGuardado !== 1) {
            try {
                $pdo->prepare('UPDATE app_usuarios SET puede_ver_red = 1 WHERE dni = :dni LIMIT 1')
                    ->execute([':dni' => $dni]);
                HospitalHuaralDB::olvidarAcceso($dni);
            } catch (Throwable $e) {
                // El flag se fuerza igualmente en la sesión emitida.
            }
        }
    } else {
        $codEstab = normalizarCodEstab((string)($user['cod_estab'] ?? ''));
        if ($codEstab === 'ALL' || hospital_establecimiento($codEstab) === null) {
            $codEstab = HospitalHuaralDB::obtenerEstablecimientoObstetra($dni);
        }
        if ($codEstab === 'ALL' || hospital_establecimiento($codEstab) === null) {
            $codEstab = '000005481';
        }
        $codEstab = str_pad($codEstab, 9, '0', STR_PAD_LEFT);
        if ($codEstab !== (string)($user['cod_estab'] ?? '')) {
            try {
                $pdo->prepare('UPDATE app_usuarios SET cod_estab = :estab WHERE dni = :dni LIMIT 1')
                    ->execute([':estab' => $codEstab, ':dni' => $dni]);
            } catch (Throwable $e) {
                // Se conserva el establecimiento de la sesión.
            }
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
            'cod_estab_asignado' => $codEstabAsignadoLogin,
            'estab_nombre' => $codEstab === 'ALL'
                ? 'TODA LA RED HUARAL-CHANCAY (53 IPRESS)'
                : hospital_nombre_establecimiento($codEstab),
            'alcance_red' => $codEstab === 'ALL',
            'verified2FA' => false,
            'platform' => $platform,
            'isAdmin' => $esAdmin,
            'esSuperAdmin' => hospital_es_super_admin($dni),
            'protegido' => hospital_es_super_admin($dni) || (int)($user['protegido'] ?? 0) === 1,
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
    $nombreCompleto = trim("{$apaterno} {$amaterno}, {$nombre1}");
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
    $solicitado = trim((string)($body['cod_estab'] ?? ''));
    $normalizadoSolicitado = normalizarCodEstab($solicitado);
    if ($normalizadoSolicitado === 'ALL') {
        $codEstab = 'ALL';
        $nombreEstab = 'TODA LA RED HUARAL-CHANCAY (53 IPRESS)';
    } else {
        $codEstab = hospital_codigo_canonico($normalizadoSolicitado);
        if ($codEstab === '') {
            $codEstab = $normalizadoSolicitado;
        }
        if (hospital_establecimiento($codEstab) === null) {
            json_error('El establecimiento seleccionado no pertenece a la Red Huaral-Chancay.', 400);
        }
        $codEstab = str_pad($codEstab, 9, '0', STR_PAD_LEFT);
        $nombreEstab = hospital_nombre_establecimiento($codEstab);
    }
    HospitalHuaralDB::cambiarEstablecimientoSesion((string)$session['token'], $codEstab, (string)$session['dni']);
    HospitalHuaralDB::registrarAuditoria(
        $session['dni'],
        'CAMBIO_ESTABLECIMIENTO',
        'El Administrador de Estadística cambió el alcance activo a ' . $nombreEstab . '.',
        $codEstab,
        $session['platform']
    );
    alertas_cache_invalidate();
    json_out([
        'success' => true,
        'session' => [
            'dni' => $session['dni'],
            'cod_estab' => $codEstab,
            'estab_nombre' => $nombreEstab,
            'alcance_red' => $codEstab === 'ALL',
        ],
    ]);
}

// ---------------------------------------------------------------------------
// 4-B. INVALIDACIÓN EXPLÍCITA DE LA CACHÉ DE ALERTAS
// ---------------------------------------------------------------------------
if ($action === 'invalidar_alertas') {
    $session = require_session();
    alertas_cache_invalidate();
    json_out([
        'success' => true,
        'invalidated_at' => date('c'),
        'by' => (string)$session['dni'],
    ]);
}

// ---------------------------------------------------------------------------
// 4-C. RECUPERACIÓN DE CLAVE SIN TOTP (DNI + PIN/últimos 4 + establecimiento)
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
    if (hospital_es_super_admin($dni)) {
        HospitalHuaralDB::registrarAuditoria($dni, 'INTENTO_MODIFICAR_SUPERADMIN', 'Intento bloqueado de recuperación/restablecimiento de la Cuenta Maestra.', '', $platform);
        json_out([
            'ok' => false,
            'error' => 'ACCESO DENEGADO: Usted no tiene privilegios para modificar datos ni desactivar la cuenta del Super Administrador Principal del Sistema.',
        ], 403);
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
    // El formulario de perfil edita la IPRESS de la CUENTA, no el alcance de la
    // sesión. Un administrador que está viendo "ALL" debe permanecer en red
    // completa aunque guarde sus datos personales.
    $alcanceRedSesion = is_admin_session($session)
        && strtoupper(trim((string)($session['cod_estab'] ?? ''))) === 'ALL';
    $codEstabSesion = $alcanceRedSesion
        ? 'ALL'
        : hospital_codigo_canonico((string)($actual['cod_estab'] ?? $session['cod_estab']));
    if ($codEstabFinal !== '') {
        $sets[] = 'cod_estab = :estab';
        $params[':estab'] = $codEstabFinal;
        if (!$alcanceRedSesion) {
            $codEstabSesion = $codEstabFinal;
        }
    }
    $pdo->prepare('UPDATE app_usuarios SET ' . implode(', ', $sets) . ' WHERE dni = :dni LIMIT 1')->execute($params);
    HospitalHuaralDB::olvidarAcceso($dni);

    if ($codEstabFinal !== '') {
        HospitalHuaralDB::establecerEstablecimientoObstetra($dni, $codEstabFinal);
        if (!$alcanceRedSesion) {
            $pdo->prepare('UPDATE app_sesiones SET cod_estab = :estab WHERE token_hash = :hash AND dni = :dni')
                ->execute([
                    ':estab' => $codEstabFinal,
                    ':hash' => hash('sha256', (string)$session['token']),
                    ':dni' => $dni,
                ]);
        }
    }

    HospitalHuaralDB::registrarAuditoria(
        $dni,
        'PERFIL_ACTUALIZADO',
        'Actualización de datos personales y seguridad' . ($codEstabFinal !== '' ? ' · Establecimiento: ' . hospital_nombre_establecimiento($codEstabFinal) : '') . ($nuevaClave !== '' ? ' (contraseña cambiada)' : '') . ($pin !== '' ? ' (PIN actualizado)' : '') . '.',
        $codEstabSesion,
        (string)$session['platform']
    );
    $session['cod_estab'] = $codEstabSesion;
    $session['estab_nombre'] = $alcanceRedSesion
        ? 'TODA LA RED HUARAL-CHANCAY (53 IPRESS)'
        : hospital_nombre_establecimiento($codEstabSesion);
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
        if (hospital_es_super_admin($dniAcceso)) {
            $acceso['rol'] = 'SUPER_ADMIN';
            $acceso['activo'] = 1;
            $acceso['puede_ver_red'] = 1;
            $acceso['protegido'] = true;
        }
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
            ['codigo' => 'SUPER_ADMIN', 'etiqueta' => 'Super Administrador del Sistema'],
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
    $actorEsSuperAdmin = hospital_es_super_admin((string)$session['dni']);
    $dni = preg_replace('/[^0-9]/', '', (string)($body['dni'] ?? '')) ?? '';
    denegar_superadmin_protegido($session, $dni, 'guardar/editar el acceso');
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
    if (!in_array($rol, ['SUPER_ADMIN', 'ADMIN_ESTADISTICA', 'JEFA_OBSTETRAS', 'OBSTETRA'], true)) {
        json_error('Rol inválido. Use OBSTETRA, JEFA_OBSTETRAS o ADMIN_ESTADISTICA.', 400);
    }
    if ($rol === 'SUPER_ADMIN' && !hospital_es_super_admin($dni)) {
        json_error('El rol SUPER_ADMIN está reservado para la Cuenta Maestra Principal del Sistema.', 403, ['code' => 'SUPERADMIN_RESERVED']);
    }
    if ($rol === 'ADMIN_ESTADISTICA' && !$actorEsSuperAdmin) {
        json_error('Solo el Super Administrador puede asignar el rol de Administrador de Estadística.', 403, ['code' => 'ADMIN_REQUIRED']);
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
    $puedeVerRed = hospital_es_rol_admin_superior($rol) ? 1 : 0;

    $existente = HospitalHuaralDB::accesoUsuario($dni);
    if (!$actorEsSuperAdmin && $dni !== (string)$session['dni'] && es_admin_estadistica_objetivo($existente)) {
        HospitalHuaralDB::registrarAuditoria(
            (string)$session['dni'],
            'INTENTO_MODIFICAR_ADMIN',
            'Intento bloqueado de modificar a otro Administrador de Estadística (DNI ' . $dni . ').',
            (string)$session['cod_estab'],
            (string)$session['platform']
        );
        json_error('Solo el Super Administrador Principal puede modificar los datos de otro Administrador de Estadística.', 403, [
            'code' => 'ADMIN_PEER_DENEGADO',
        ]);
    }
    if (hospital_es_super_admin($dni)) {
        // La Cuenta Maestra nunca puede rebajarse ni desactivarse a sí misma.
        if ($rol !== 'SUPER_ADMIN' || $activo !== 1) {
            HospitalHuaralDB::registrarAuditoria(
                (string)$session['dni'],
                'INTENTO_MODIFICAR_SUPERADMIN',
                'La Cuenta Maestra intentó rebajar su rol o desactivarse a sí misma.',
                (string)$session['cod_estab'],
                (string)$session['platform']
            );
            json_out([
                'ok' => false,
                'error' => 'La Cuenta Maestra del Sistema no puede rebajarse de rol ni desactivarse a sí misma.',
            ], 403);
        }
        $rol = 'SUPER_ADMIN';
        $puedeVerRed = 1;
        $activo = 1;
    }
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
    $actorEsSuperAdmin = hospital_es_super_admin((string)$session['dni']);
    $dni = preg_replace('/[^0-9]/', '', (string)($body['dni'] ?? '')) ?? '';
    $activo = !empty($body['activo']) ? 1 : 0;
    if ($dni === '') {
        json_error('DNI inválido.', 400);
    }
    denegar_superadmin_protegido($session, $dni, 'cambiar el estado del acceso');
    $accesoObjetivo = HospitalHuaralDB::accesoUsuario($dni);
    if (!$actorEsSuperAdmin && $dni !== (string)$session['dni'] && es_admin_estadistica_objetivo($accesoObjetivo)) {
        HospitalHuaralDB::registrarAuditoria(
            (string)$session['dni'],
            'INTENTO_MODIFICAR_ADMIN',
            'Intento bloqueado de cambiar el estado de otro Administrador de Estadística (DNI ' . $dni . ').',
            (string)$session['cod_estab'],
            (string)$session['platform']
        );
        json_error('Solo el Super Administrador Principal puede desactivar o modificar a otro Administrador de Estadística.', 403, [
            'code' => 'ADMIN_PEER_DENEGADO',
        ]);
    }
    if (hospital_es_super_admin($dni) && $activo === 0) {
        HospitalHuaralDB::registrarAuditoria(
            (string)$session['dni'],
            'INTENTO_MODIFICAR_SUPERADMIN',
            'Intento de desactivar la Cuenta Maestra DNI ' . SUPER_ADMIN_DNI . '.',
            (string)$session['cod_estab'],
            (string)$session['platform']
        );
        json_out([
            'ok' => false,
            'error' => 'La Cuenta Maestra Principal del Sistema no puede ser desactivada.',
        ], 403);
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
    denegar_superadmin_protegido($session, $dni, 'restablecer la clave');
    $actorEsSuperAdmin = hospital_es_super_admin((string)$session['dni']);
    $rolObjetivo = strtoupper(trim((string)($acceso['rol'] ?? 'OBSTETRA')));
    if (!$actorEsSuperAdmin && $dni !== (string)$session['dni'] && $rolObjetivo === 'ADMIN_ESTADISTICA') {
        HospitalHuaralDB::registrarAuditoria(
            (string)$session['dni'],
            'INTENTO_MODIFICAR_ADMIN',
            'Intento bloqueado de restablecer la clave de otro Administrador de Estadística (DNI ' . $dni . ').',
            (string)$session['cod_estab'],
            (string)$session['platform']
        );
        json_error('Solo el Super Administrador Principal puede restablecer la clave de otro Administrador de Estadística.', 403, [
            'code' => 'ADMIN_PEER_DENEGADO',
        ]);
    }
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
    $esAdminSesion = is_admin_session($session);
    // El alcance SIEMPRE lo determina la sesión: el administrador inicia en
    // "ALL" (red completa) y el selector de cabecera fija una IPRESS concreta.
    $modoRed = $esAdminSesion && strtoupper(trim((string)($session['cod_estab'] ?? ''))) === 'ALL';
    $obstetraFiltro = preg_replace('/[^0-9A-Za-z]/', '', (string)($_GET['obstetra'] ?? '')) ?? '';
    if ($obstetraFiltro === 'TODOS') {
        $obstetraFiltro = '';
    }

    // RBAC estricto de la pestaña Pacientes:
    //  - OBSTETRA: solo sus propias captaciones (sin bloquear por cod_estab).
    //  - JEFA: todo su establecimiento + captaciones de sus obstetras.
    //  - ADMIN/SUPER_ADMIN: red completa en ALL o la IPRESS seleccionada.
    [$condPacientes, $paramsPacientes] = condicion_alcance_pacientes($pdo, $session, 'p', $obstetraFiltro, 'pac');
    $scopePacientes = $condPacientes !== '' ? ' WHERE ' . $condPacientes . ' ' : '';
    $scopeParamsPacientes = $paramsPacientes;

    // KPI y producción se calculan con el alcance del ESTABLECIMIENTO para
    // todas las roles (misma data que Estadística), sin aislar por obstetra.
    [$condStats, $paramsStats] = condicion_alcance_establecimiento($pdo, $session, 'p', $obstetraFiltro, 'kpi');
    $scopeStats = $condStats !== '' ? ' WHERE ' . $condStats . ' ' : '';
    $scopeParamsStats = $paramsStats;

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

    // Agenda operativa construida desde la fuente única de programación:
    // únicamente pacientes que tocan HOY, MAÑANA o dentro de los PRÓXIMOS 7 DÍAS.
    $alertas = alertas_programaticas_datos($pdo, $session, $catalogo);
    $agenda = [];
    foreach (['hoy', 'manana', 'proximos_7'] as $grupoAlerta) {
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
                'estado_cita' => (int)($filaAlerta['dias_restantes'] ?? 0) === 0
                    ? 'TOCA_HOY'
                    : ((int)($filaAlerta['dias_restantes'] ?? 0) === 1 ? 'TOCA_MANANA' : 'PROXIMO_7_DIAS'),
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

    $scopeProd = $scopeStats;
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
    $stmtProd->execute($scopeParamsStats);
    $produccion = $stmtProd->fetchAll();
    $dnisProd = array_map(static fn ($row) => (string)$row['codpsal'], $produccion);
    $diccionarioProd = nombres_personas_por_dni($pdo, $dnisProd);
    foreach ($produccion as &$prodRow) {
        $cod = (string)$prodRow['codpsal'];
        $prodRow['nombre'] = (string)($diccionarioProd[$cod] ?? ('Obstetra DNI ' . $cod));
    }
    unset($prodRow);

    $auditoria = is_admin_session($session) ? HospitalHuaralDB::ultimaAuditoria(30) : [];
    // Los KPI se calculan con COUNT sobre TODO el padrón del alcance, nunca
    // sobre la lista visual limitada a 500 filas.
    $totalesPacientes = [
        'total' => 0,
        'insatisfechas' => 0,
        'con_metodo' => 0,
        'seguimiento' => 0,
        'atenciones_99208' => 0,
    ];
    try {
        $stmtTotales = $pdo->prepare("
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN p.estado_paciente = 'INSATISFECHA_SIN_METODO' THEN 1 ELSE 0 END) AS insatisfechas,
                   SUM(CASE WHEN p.estado_paciente = 'CAPTADA_CON_METODO' THEN 1 ELSE 0 END) AS con_metodo,
                   SUM(CASE WHEN p.estado_paciente = 'SEGUIMIENTO_DOMICILIARIO' THEN 1 ELSE 0 END) AS seguimiento,
                   SUM(CASE WHEN p.atencion_99208 = 1 THEN 1 ELSE 0 END) AS atenciones_99208
            FROM pacientes_sin_metodo p
            {$scopeStats}
        ");
        $stmtTotales->execute($scopeParamsStats);
        $totalesPacientes = array_merge($totalesPacientes, $stmtTotales->fetch() ?: []);
    } catch (Throwable $e) {
        error_log('[PlanificaHIS] overview totales: ' . $e->getMessage());
    }
    $stats = [
        'totalCaptadas' => (int)($totalesPacientes['total'] ?? 0),
        'insatisfechasSinMetodo' => (int)($totalesPacientes['insatisfechas'] ?? 0),
        'captadasConMetodo' => (int)($totalesPacientes['con_metodo'] ?? 0),
        'seguimientoDomiciliario' => (int)($totalesPacientes['seguimiento'] ?? 0),
        'citasAmpollaHoyManana' => (int)($alertas['hoy'] ?? 0) + (int)($alertas['manana'] ?? 0),
        'alertasProximos7Dias' => (int)($alertas['proximos_7'] ?? 0),
        'alertasHisPorCaptar' => (int)($alertas['total'] ?? 0),
        'atenciones99208' => (int)($totalesPacientes['atenciones_99208'] ?? 0),
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
            'estab_nombre' => $modoRed
                ? 'TODA LA RED HUARAL-CHANCAY (53 IPRESS)'
                : $session['estab_nombre'],
            'alcance_red' => $modoRed,
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
    static $cache = [];
    $codigo = trim((string)$codigo);
    $fallback = trim((string)$fallback);
    $cacheKey = $codigo . '|' . $fallback;
    if (isset($cache[$cacheKey])) {
        return $cache[$cacheKey];
    }
    $variantes = hospital_codigos_busqueda_establecimiento($codigo);
    // El catálogo oficial manda: se prueba el código recibido y sus variantes
    // (IPRESS, interno de 4 dígitos, sin ceros) antes de consultar establec.
    foreach ($variantes as $variante) {
        $est = hospital_establecimiento($variante);
        if ($est !== null) {
            $nombre = trim((string)($est['DESC_ESTAB'] ?? ''));
            if ($nombre !== '') {
                return $cache[$cacheKey] = $nombre;
            }
        }
    }

    if ($fallback !== '' && $fallback !== $codigo) {
        return $cache[$cacheKey] = $fallback;
    }

    if ($variantes) {
        $placeholders = implode(',', array_fill(0, count($variantes), '?'));
        try {
            $stmt = $pdo->prepare("SELECT DESC_ESTAB FROM establec WHERE COD_ESTAB IN ({$placeholders}) LIMIT 1");
            $stmt->execute($variantes);
            $nombre = trim((string)($stmt->fetchColumn() ?: ''));
            if ($nombre !== '') {
                return $cache[$cacheKey] = $nombre;
            }
        } catch (Throwable $e) {
            // La tabla establec puede no existir en una instalación mínima.
        }
    }

    return $cache[$cacheKey] = ($fallback !== '' ? $fallback : ($codigo !== '' ? $codigo : 'SIN ESTABLECIMIENTO'));
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
 * Caché ligera de alertas programáticas (TTL 90 s).
 * Evita que 15 obstetras del mismo establecimiento golpeen TiDB Cloud al
 * mismo tiempo: la primera petición consulta y las demás leen el JSON local.
 */
function alertas_cache_path(string $key): string
{
    return rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR)
        . DIRECTORY_SEPARATOR . 'planificahis_alertas_' . $key . '.json';
}

function alertas_cache_get(string $key): ?array
{
    $path = alertas_cache_path($key);
    if (!is_file($path)) {
        return null;
    }
    $mtime = @filemtime($path);
    if ($mtime === false || (time() - $mtime) > 90) {
        @unlink($path);
        return null;
    }
    $raw = @file_get_contents($path);
    if ($raw === false || $raw === '') {
        return null;
    }
    $data = json_decode($raw, true);
    return is_array($data) ? $data : null;
}

function alertas_cache_set(string $key, array $data): void
{
    $path = alertas_cache_path($key);
    $json = json_encode($data, JSON_UNESCAPED_UNICODE);
    if ($json === false) {
        return;
    }
    @file_put_contents($path, $json, LOCK_EX);
}

/** Invalida todas las cachés de alertas al guardar una paciente o un método. */
function alertas_cache_invalidate(): void
{
    $patron = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR)
        . DIRECTORY_SEPARATOR . 'planificahis_alertas_*.json';
    foreach (glob($patron) ?: [] as $archivo) {
        @unlink($archivo);
    }
}

/**
 * FUENTE ÚNICA DE VERDAD DE PROGRAMACIÓN (alertas, agenda, padrón y reportes).
 *
 * Calcula, para el rango de fechas de PRÓXIMO CONTROL indicado, un mapa
 * DNI => paciente con su método principal vigente. Reglas:
 *
 *  1) Descubrimiento SARGable: se consulta cada ciclo por separado con la
 *     ventana exacta de fechas de aplicación (próximo - ciclo). Para una
 *     ventana de 7 días cada consulta recorre solo 8 días de his_dl, sin
 *     escanear años de historial ni pacientes vencidas.
 *  2) El método principal de una atención es el de mayor ciclo; si una
 *     paciente tiene varios DX en la misma fecha (método + consejería), se
 *     consolida en UNA sola fila por DNI.
 *  3) La atención más reciente de la paciente siempre prevalece: si tiene una
 *     atención posterior que aún no vence, no se reporta una atención antigua.
 *  4) El establecimiento se filtra con h.COD_ESTAB IN (...) usando las
 *     variantes indexables del catálogo (9 dígitos, IPRESS y sin ceros).
 *     NUNCA se aplican LPAD/TRIM/RIGHT sobre columnas de his_dl en WHERE/JOIN.
 *
 * @param array<string, array<string, mixed>> $catalogo
 * @param array<int, string> $codigosFiltro códigos oficiales o variantes HIS
 * @return array<string, array<string, mixed>>
 */
function programacion_candidatos_rango(
    PDO $pdo,
    array $session,
    array $catalogo,
    string $desdeProximo,
    string $hastaProximo,
    array $codigosFiltro = []
): array {
    $desdeDt = DateTimeImmutable::createFromFormat('!Y-m-d', trim($desdeProximo));
    $hastaDt = DateTimeImmutable::createFromFormat('!Y-m-d', trim($hastaProximo));
    if (!$desdeDt instanceof DateTimeImmutable || !$hastaDt instanceof DateTimeImmutable) {
        return [];
    }
    if ($desdeDt->format('Y-m-d') !== trim($desdeProximo) || $hastaDt->format('Y-m-d') !== trim($hastaProximo)) {
        return [];
    }
    if ($desdeDt > $hastaDt) {
        [$desdeDt, $hastaDt] = [$hastaDt, $desdeDt];
    }

    $codigosConsulta = codigos_consulta_metodos($catalogo, $codigosFiltro);
    if (!$codigosConsulta) {
        return [];
    }

    $gruposCiclo = [];
    $maxCiclo = 0;
    foreach ($codigosConsulta as $codigo) {
        $meta = resolver_metodo_catalogo($catalogo, $codigo);
        if ($meta === null) {
            continue;
        }
        $dias = max(1, (int)($meta['dias_ciclo'] ?? 30));
        $gruposCiclo[$dias][] = (string)$codigo;
        $maxCiclo = max($maxCiclo, $dias);
    }
    if (!$gruposCiclo) {
        return [];
    }
    ksort($gruposCiclo);

    $esAdmin = is_admin_session($session);
    $modoRed = $esAdmin && normalizarCodEstab((string)($session['cod_estab'] ?? '')) === 'ALL';
    $codigosEstab = $modoRed ? [] : codigos_establecimiento_consulta($pdo, $session);
    $scope = '';
    $paramsScope = [];
    if ($codigosEstab) {
        $scope = ' AND h.COD_ESTAB IN (' . implode(',', array_fill(0, count($codigosEstab), '?')) . ') ';
        $paramsScope = $codigosEstab;
    }

    // Índice compuesto correcto según el alcance. Si hay IPRESS, el índice
    // (COD_ESTAB, ANO, MES, DIA) resuelve todo en milisegundos.
    if ($codigosEstab && indice_existe($pdo, 'his_dl', 'idx_his_dl_estab_ano_mes_dia')) {
        $hint = ' FORCE INDEX(idx_his_dl_estab_ano_mes_dia)';
    } elseif (indice_existe($pdo, 'his_dl', 'idx_his_dl_ano_mes_dia')) {
        $hint = ' FORCE INDEX(idx_his_dl_ano_mes_dia)';
    } else {
        $hint = '';
    }

    // 1) Descubrimiento de DNIs candidatos. Cada ciclo usa su ventana exacta;
    // todos los ciclos viajan en UN solo UNION ALL para minimizar round trips
    // contra la base remota (6 consultas -> 1).
    $partesCandidatos = [];
    $paramsCandidatos = [];
    foreach ($gruposCiclo as $diasCiclo => $listaCodigos) {
        $desdeAplicacion = $desdeDt->modify('-' . (int)$diasCiclo . ' days')->format('Y-m-d');
        $hastaAplicacion = $hastaDt->modify('-' . (int)$diasCiclo . ' days')->format('Y-m-d');
        $paramsRango = [];
        $condicionRango = sql_condicion_rango_ymd('h', $desdeAplicacion, $hastaAplicacion, $paramsRango);
        $anioMin = (int)substr($desdeAplicacion, 0, 4);
        $anioMax = (int)substr($hastaAplicacion, 0, 4);
        $marcas = implode(',', array_fill(0, count($listaCodigos), '?'));
        $partesCandidatos[] = "
            SELECT h.DNI AS dni
            FROM his_dl h{$hint}
            STRAIGHT_JOIN his_dl_dt dt ON dt.ID = h.ID
            WHERE h.ANO BETWEEN ? AND ?
              AND dt.DX IN ({$marcas})
              AND {$condicionRango}
              {$scope}
        ";
        $paramsCandidatos = array_merge(
            $paramsCandidatos,
            [$anioMin, $anioMax],
            $listaCodigos,
            $paramsRango,
            $paramsScope
        );
    }
    $candidatos = [];
    if ($partesCandidatos) {
        $sqlCandidatos = 'SELECT DISTINCT dni FROM (' . implode(' UNION ALL ', $partesCandidatos) . ') candidatos';
        $stmtCandidatos = $pdo->prepare($sqlCandidatos);
        $stmtCandidatos->execute($paramsCandidatos);
        foreach ($stmtCandidatos->fetchAll(PDO::FETCH_COLUMN, 0) as $dniCandidato) {
            $dniCandidato = trim((string)$dniCandidato);
            if ($dniCandidato !== '') {
                $candidatos[$dniCandidato] = true;
            }
        }
    }
    if (!$candidatos) {
        return [];
    }

    // 2) Para esos DNIs se trae su historial reciente de métodos y se elige la
    // atención más reciente + el método de mayor ciclo de esa misma fecha.
    $anioMinDetalle = (int)$desdeDt->modify('-' . $maxCiclo . ' days')->format('Y');
    // La última atención válida se evalúa "a la fecha": nunca usa atenciones
    // posteriores al día consultado (ni al día de hoy, para no mezclar datos
    // futuros digitados por error).
    $hoyDetalle = new DateTimeImmutable('today');
    $limiteDetalle = $hastaDt < $hoyDetalle ? $hastaDt : $hoyDetalle;
    $anioMaxDetalle = (int)$limiteDetalle->format('Y');
    if ($anioMinDetalle > $anioMaxDetalle) {
        $anioMinDetalle = $anioMaxDetalle;
    }
    $limiteYmdDetalle = (int)$limiteDetalle->format('Ymd');
    $marcasTodos = implode(',', array_fill(0, count($codigosConsulta), '?'));
    // La segunda pasada se limita SOLO a los DNIs candidatos (no recorre el
    // historial completo) y usa el índice por DNI + fecha.
    if (indice_existe($pdo, 'his_dl', 'idx_his_dl_dni_ano_mes_dia')) {
        $hintDetalle = ' FORCE INDEX(idx_his_dl_dni_ano_mes_dia)';
    } elseif (indice_existe($pdo, 'his_dl', 'idx_his_dl_dni_fecha')) {
        $hintDetalle = ' FORCE INDEX(idx_his_dl_dni_fecha)';
    } else {
        $hintDetalle = '';
    }
    $detalle = [];
    foreach (array_chunk(array_keys($candidatos), 500) as $loteDnis) {
        $marcasDni = implode(',', array_fill(0, count($loteDnis), '?'));
        $sql = "
            SELECT h.DNI AS dni, h.ID AS id_his, h.COD_ESTAB AS cod_estab,
                   TRIM(h.Apellido_p) AS apellido_paterno,
                   TRIM(h.Apellido_m) AS apellido_materno,
                   TRIM(COALESCE(NULLIF(h.Dnombres, ''), h.Pnombre)) AS nombres,
                   h.EDAD AS edad, h.HCLFAM AS historia_clinica,
                   h.FICHAFAM AS ficha_familiar, h.CODPSAL AS obstetra_dni,
                   h.DIA, h.MES, h.ANO, h.fecha_reg,
                   dt.DX AS codigo_his, dt.id_dosis AS dosis, dt.fecha_reg AS fecha_dx
            FROM his_dl h{$hintDetalle}
            STRAIGHT_JOIN his_dl_dt dt ON dt.ID = h.ID
            WHERE h.DNI IN ({$marcasDni})
              AND h.ANO BETWEEN ? AND ?
              AND (h.ANO * 10000 + h.MES * 100 + h.DIA) <= ?
              AND dt.DX IN ({$marcasTodos})
              {$scope}
            ORDER BY h.DNI ASC, h.ANO DESC, h.MES DESC, h.DIA DESC, h.ID DESC
        ";
        $params = array_merge(
            $loteDnis,
            [$anioMinDetalle, $anioMaxDetalle, $limiteYmdDetalle],
            $codigosConsulta,
            $paramsScope
        );
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        foreach ($stmt->fetchAll() as $row) {
            $dni = trim((string)($row['dni'] ?? ''));
            $codigoHis = trim((string)($row['codigo_his'] ?? ''));
            if ($dni === '' || $codigoHis === '') {
                continue;
            }
            $meta = resolver_metodo_catalogo($catalogo, $codigoHis);
            if ($meta === null || (int)($meta['dias_ciclo'] ?? 0) <= 0) {
                continue;
            }
            $fecha = fecha_aplicacion_his($row);
            if ($fecha === '') {
                continue;
            }
            $dias = (int)$meta['dias_ciclo'];
            $score = $fecha . '|' . str_pad((string)$dias, 4, '0', STR_PAD_LEFT)
                . '|' . str_pad((string)(int)($row['id_his'] ?? 0), 12, '0', STR_PAD_LEFT);
            if (isset($detalle[$dni]) && strcmp($score, (string)$detalle[$dni]['_score']) <= 0) {
                continue;
            }
            $detalle[$dni] = [
                '_score' => $score,
                'row' => $row,
                'meta' => $meta,
                'dias' => $dias,
                'fecha' => $fecha,
                'codigo_his' => $codigoHis,
            ];
        }
    }

    $resultado = [];
    foreach ($detalle as $dni => $sel) {
        try {
            $proximo = (new DateTimeImmutable($sel['fecha']))->modify('+' . (int)$sel['dias'] . ' days');
        } catch (Throwable $e) {
            continue;
        }
        $resultado[(string)$dni] = [
            'dni' => (string)$dni,
            'row' => $sel['row'],
            'meta' => $sel['meta'],
            'codigo' => (string)($sel['meta']['codigo_dx'] ?? $sel['codigo_his']),
            'codigo_his' => (string)$sel['codigo_his'],
            'dias_ciclo' => (int)$sel['dias'],
            'fecha_aplicacion' => (string)$sel['fecha'],
            'fecha_proximo' => $proximo->format('Y-m-d'),
        ];
    }
    return $resultado;
}

/**
 * Alertas proactivas de seguimiento programático: pacientes que les toca HOY,
 * MAÑANA o dentro de los PRÓXIMOS 7 DÍAS. Usa la misma fuente única de verdad
 * que la Programación calculada y el padrón, de modo que HOY siempre coincide
 * exactamente con “Toca fecha” del reporte (0 desfases).
 *
 * @param array<string, array<string, mixed>>|null $catalogo
 * @return array<string, mixed>
 */
function alertas_programaticas_datos(PDO $pdo, array $session, ?array $catalogo = null, int $limiteLista = 1000): array
{
    $catalogo = $catalogo ?: catalogo_metodos_planificacion($pdo);
    $hoy = new DateTimeImmutable('today');
    $hasta7 = $hoy->modify('+7 days');
    $vacio = [
        'manana' => 0,
        'hoy' => 0,
        'proximos_7' => 0,
        'total' => 0,
        'listas' => ['manana' => [], 'hoy' => [], 'proximos_7' => []],
    ];
    $codigosConsulta = codigos_consulta_metodos($catalogo);
    if (!$codigosConsulta) {
        return $vacio;
    }

    $rolAlertas = HospitalHuaralDB::rolUsuario((string)($session['dni'] ?? ''));
    $esAdminAlertas = is_admin_session($session);
    // Programación y alertas NO se filtran por CODPSAL para ningún rol. La
    // obstetra y la jefatura ven toda la programación de su IPRESS; el
    // administrador ve la red (ALL) o la IPRESS seleccionada en la cabecera.
    $modoRedAlertas = $esAdminAlertas
        && normalizarCodEstab((string)($session['cod_estab'] ?? '')) === 'ALL';
    $codigosEstabAlertas = $modoRedAlertas ? [] : codigos_establecimiento_consulta($pdo, $session);

    $cacheKey = hash('sha256', implode('|', [
        'alertas-v6',
        (string)($session['dni'] ?? ''),
        (string)($session['cod_estab'] ?? ''),
        (string)$rolAlertas,
        $modoRedAlertas ? 'red' : 'est',
        implode(',', $codigosEstabAlertas),
        implode(',', $codigosConsulta),
        (string)$limiteLista,
        $hoy->format('Y-m-d'),
    ]));
    $cacheado = alertas_cache_get($cacheKey);
    if ($cacheado !== null) {
        return $cacheado;
    }

    try {
        $candidatos = programacion_candidatos_rango(
            $pdo,
            $session,
            $catalogo,
            $hoy->format('Y-m-d'),
            $hasta7->format('Y-m-d')
        );
    } catch (Throwable $e) {
        error_log('[PlanificaHIS] alertas_programaticas_datos: ' . $e->getMessage());
        return $vacio;
    }

    $totales = ['manana' => 0, 'hoy' => 0, 'proximos_7' => 0];
    $porGrupo = ['manana' => [], 'hoy' => [], 'proximos_7' => []];
    foreach ($candidatos as $dni => $sel) {
        try {
            $proximo = new DateTimeImmutable((string)$sel['fecha_proximo']);
        } catch (Throwable $e) {
            continue;
        }
        $diasRestantes = (int)$hoy->diff($proximo)->format('%r%a');
        if ($diasRestantes < 0 || $diasRestantes > 7) {
            continue;
        }
        $grupo = $diasRestantes === 0 ? 'hoy' : ($diasRestantes === 1 ? 'manana' : 'proximos_7');
        $totales[$grupo]++;
        $porGrupo[$grupo][$dni] = [
            'sel' => $sel,
            'dias' => $diasRestantes,
            'grupo' => $grupo,
        ];
    }

    if (!$totales['hoy'] && !$totales['manana'] && !$totales['proximos_7']) {
        alertas_cache_set($cacheKey, $vacio);
        return $vacio;
    }

    // Solo se construyen tarjetas completas hasta el límite por grupo; los
    // totales reales ya quedaron contados con la fuente única de verdad.
    $seleccionados = [];
    foreach ($porGrupo as $listaGrupo) {
        uasort($listaGrupo, static function (array $a, array $b): int {
            $cmp = (int)$a['dias'] <=> (int)$b['dias'];
            return $cmp !== 0 ? $cmp : strcmp((string)($a['sel']['dni'] ?? ''), (string)($b['sel']['dni'] ?? ''));
        });
        foreach (array_slice($listaGrupo, 0, max(1, $limiteLista), true) as $dniGrupo => $metaGrupo) {
            $seleccionados[$dniGrupo] = $metaGrupo;
        }
    }

    $dnis = array_keys($seleccionados);
    $contactos = contactos_pacientes_por_dni($pdo, $dnis);
    $dnisObstetras = array_map(static fn ($metaSel) => (string)($metaSel['sel']['row']['obstetra_dni'] ?? ''), $seleccionados);
    $nombresObstetras = nombres_personas_por_dni($pdo, $dnisObstetras);
    $listas = ['manana' => [], 'hoy' => [], 'proximos_7' => []];

    foreach ($seleccionados as $dni => $metaSel) {
        $sel = $metaSel['sel'];
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
        $diasRestantes = (int)$metaSel['dias'];
        $prioridad = $diasRestantes === 0
            ? 'ALTA (HOY)'
            : ($diasRestantes === 1 ? 'ALTA (MAÑANA)' : 'MEDIA');
        $fila = [
            'dni' => $dni,
            'paciente_nombre' => $pacienteNombre,
            'edad' => $edad,
            'historia_clinica' => (string)($row['historia_clinica'] ?? ''),
            'cod_estab' => $codEstab,
            'establecimiento' => resolver_nombre_establecimiento($pdo, $codEstab),
            'codigo_metodo' => (string)$sel['codigo'],
            'codigo_his' => (string)$sel['codigo_his'],
            'nombre_metodo' => (string)($meta['nombre_metodo'] ?? $sel['codigo']),
            'fecha_aplicacion' => fecha_para_mostrar($sel['fecha_aplicacion']),
            'fecha_aplicacion_iso' => $sel['fecha_aplicacion'],
            'dias_ciclo' => (int)$sel['dias_ciclo'],
            'fecha_proximo_metodo' => fecha_para_mostrar($sel['fecha_proximo']),
            'fecha_proximo_metodo_iso' => $sel['fecha_proximo'],
            'dias_restantes' => $diasRestantes,
            'estado_programacion' => $diasRestantes === 0 ? 'TOCA_EN_FECHA' : 'PROXIMO_7_DIAS',
            'prioridad_llamada' => $prioridad,
            'celular' => (string)($cap['celular'] ?? ''),
            'direccion' => (string)($cap['direccion'] ?? ''),
            'distrito' => (string)($cap['distrito'] ?? ''),
            'sector' => (string)($cap['sector'] ?? ''),
            'obstetra_dni' => $codObstetra,
            'nombre_obstetra' => (string)($nombresObstetras[$codObstetra] ?? ('OBST. ' . $codObstetra)),
        ];
        $listas[$metaSel['grupo']][] = $fila;
    }

    foreach ($listas as &$lista) {
        usort($lista, static function (array $a, array $b): int {
            $cmp = (int)$a['dias_restantes'] <=> (int)$b['dias_restantes'];
            return $cmp !== 0 ? $cmp : strcmp((string)$a['paciente_nombre'], (string)$b['paciente_nombre']);
        });
        $lista = array_slice($lista, 0, max(1, $limiteLista));
    }
    unset($lista);

    $resultado = [
        'manana' => (int)$totales['manana'],
        'hoy' => (int)$totales['hoy'],
        'proximos_7' => (int)$totales['proximos_7'],
        'total' => (int)$totales['hoy'] + (int)$totales['manana'] + (int)$totales['proximos_7'],
        'listas' => $listas,
    ];
    alertas_cache_set($cacheKey, $resultado);
    return $resultado;
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
 * Obtiene la ÚLTIMA atención de Planificación Familiar por DNI hasta una fecha
 * tope, en dos pasos rápidos:
 *   1) índice (DNI, ANO, MES, DIA) → MAX(YYYYMMDD) por DNI (solo índice).
 *   2) búsqueda exacta de las filas completas de esas fechas por DNI.
 * Evita traer todo el historial de cada paciente y mantiene el cruce en < 2 s.
 *
 * @param array<int, string> $dnis
 * @param array<int, string> $codigos
 * @param array<int, string> $columnasSelect columnas ya escapadas del SELECT
 * @return array<int, array<string, mixed>>
 */
function ultimas_atenciones_metodo_hasta(
    PDO $pdo,
    array $dnis,
    array $codigos,
    string $desdeIso,
    string $hastaIso,
    string $columnasSelect
): array {
    $dnis = array_values(array_unique(array_filter(array_map(
        static fn ($dni): string => preg_replace('/[^0-9A-Za-z]/', '', (string)$dni) ?? '',
        $dnis
    ), static fn (string $dni): bool => $dni !== '')));
    $codigos = array_values(array_unique(array_filter(array_map('strval', $codigos), static fn ($c) => trim($c) !== '')));
    if (!$dnis || !$codigos) {
        return [];
    }
    $desde = ymd_partes_fecha($desdeIso);
    $hasta = ymd_partes_fecha($hastaIso);
    if ($desde === null || $hasta === null) {
        return [];
    }
    $marcasDx = implode(',', array_fill(0, count($codigos), '?'));
    $resultado = [];
    foreach (array_chunk($dnis, 500) as $lote) {
        $marcasDni = implode(',', array_fill(0, count($lote), '?'));
        $paramsRango = [];
        $condicionRango = sql_condicion_rango_ymd('h', $desdeIso, $hastaIso, $paramsRango);
        $sqlUltima = "
            SELECT h.DNI AS dni,
                   MAX(h.ANO * 10000 + h.MES * 100 + h.DIA) AS ymd
            FROM his_dl h
            INNER JOIN his_dl_dt dt ON dt.ID = h.ID
            WHERE h.DNI IN ({$marcasDni})
              AND h.ANO BETWEEN ? AND ?
              AND dt.DX IN ({$marcasDx})
              AND {$condicionRango}
            GROUP BY h.DNI
        ";
        $paramsUltima = array_merge($lote, [$desde[0], $hasta[0]], $codigos, $paramsRango);
        try {
            $stmtUltima = $pdo->prepare($sqlUltima);
            $stmtUltima->execute($paramsUltima);
            $ultimas = $stmtUltima->fetchAll();
        } catch (Throwable $e) {
            error_log('[PlanificaHIS] ultimas_atenciones_metodo_hasta (max): ' . $e->getMessage());
            continue;
        }
        if (!$ultimas) {
            continue;
        }
        $tuplas = [];
        $paramsTuplas = [];
        foreach ($ultimas as $filaUltima) {
            $ymd = (int)($filaUltima['ymd'] ?? 0);
            if ($ymd <= 0) {
                continue;
            }
            $tuplas[] = '(?, ?, ?, ?)';
            $paramsTuplas[] = (string)$filaUltima['dni'];
            $paramsTuplas[] = intdiv($ymd, 10000);
            $paramsTuplas[] = intdiv($ymd - intdiv($ymd, 10000) * 10000, 100);
            $paramsTuplas[] = $ymd % 100;
        }
        if (!$tuplas) {
            continue;
        }
        $sqlFilas = "
            SELECT {$columnasSelect}
            FROM his_dl h
            INNER JOIN his_dl_dt dt ON dt.ID = h.ID
            WHERE (h.DNI, h.ANO, h.MES, h.DIA) IN (" . implode(',', $tuplas) . ")
              AND dt.DX IN ({$marcasDx})
        ";
        try {
            $stmtFilas = $pdo->prepare($sqlFilas);
            $stmtFilas->execute(array_merge($paramsTuplas, $codigos));
            foreach ($stmtFilas->fetchAll() as $fila) {
                $resultado[] = $fila;
            }
        } catch (Throwable $e) {
            error_log('[PlanificaHIS] ultimas_atenciones_metodo_hasta (filas): ' . $e->getMessage());
        }
    }
    return $resultado;
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
    $historialPorAtencion = [];
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
        if ($metaDx === null || (int)($metaDx['dias_ciclo'] ?? 0) <= 0) {
            continue;
        }
        $idAtencion = trim((string)($row['ID'] ?? ''));
        $claveHistorial = $idAtencion !== '' ? $idAtencion : ($fecha . '|' . $dx);
        $diasHistorial = max(0, (int)($metaDx['dias_ciclo'] ?? 0));
        if (
            isset($historialPorAtencion[$claveHistorial])
            && $diasHistorial <= (int)$historialPorAtencion[$claveHistorial]['dias_ciclo']
        ) {
            continue;
        }
        $codEstabHistorial = trim((string)($row['COD_ESTAB'] ?? ''));
        $codpsalHistorial = trim((string)($row['CODPSAL'] ?? ''));
        $historialPorAtencion[$claveHistorial] = [
            'id_his' => $idAtencion,
            'id_dosis' => (string)($row['id_dosis'] ?? ''),
            'codigo' => (string)($metaDx['codigo_dx'] ?? $dx),
            'codigo_his' => $dx,
            'nombre' => (string)($metaDx['nombre_metodo'] ?? $dx),
            'dias_ciclo' => $diasHistorial,
            'fecha_iso' => $fecha,
            'fecha' => fecha_para_mostrar($fecha),
            'cod_estab' => $codEstabHistorial,
            'establecimiento' => $codEstabHistorial !== '' ? resolver_nombre_establecimiento($pdo, $codEstabHistorial) : '',
            'codpsal' => $codpsalHistorial,
            'obstetra_nombre' => '',
            '_score' => $fecha . '|' . str_pad((string)$diasHistorial, 4, '0', STR_PAD_LEFT),
        ];
    }

    // El historial ya viene de la atención más reciente a la más antigua.
    // Se conserva una entrada por atención y hasta 10 métodos registrados.
    uasort($historialPorAtencion, static function (array $a, array $b): int {
        return strcmp((string)$b['_score'], (string)$a['_score']);
    });
    $historialMetodos = array_slice(array_values($historialPorAtencion), 0, 10);
    foreach ($historialMetodos as &$itemHistorial) {
        unset($itemHistorial['_score']);
    }
    unset($itemHistorial);

    $dnisHistorial = array_values(array_unique(array_filter(array_map(
        static fn (array $item): string => (string)($item['codpsal'] ?? ''),
        $historialMetodos
    ), static fn (string $v): bool => trim($v) !== '')));
    $nombresHistorial = $dnisHistorial ? nombres_personas_por_dni($pdo, $dnisHistorial) : [];
    foreach ($historialMetodos as &$itemHistorial) {
        $codpsalItem = (string)($itemHistorial['codpsal'] ?? '');
        $itemHistorial['obstetra_nombre'] = $codpsalItem !== ''
            ? (string)($nombresHistorial[$codpsalItem] ?? ('OBST. ' . $codpsalItem))
            : '';
    }
    unset($itemHistorial);

    $metodoActualHistorial = $historialMetodos[0] ?? null;
    $codigoHis = $metodoActualHistorial !== null ? (string)$metodoActualHistorial['codigo_his'] : '';
    $metaUltimo = $metodoActualHistorial !== null
        ? resolver_metodo_catalogo($catalogo, $codigoHis)
        : null;
    $codigo = $metaUltimo !== null ? (string)$metaUltimo['codigo_dx'] : $codigoHis;
    $diasCiclo = $metaUltimo !== null ? max(0, (int)($metaUltimo['dias_ciclo'] ?? 0)) : 0;
    $fechaAplicacionIso = $metodoActualHistorial !== null ? (string)$metodoActualHistorial['fecha_iso'] : '';
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

    // Cambio de método: se compara el método actual con el método distinto
    // inmediatamente anterior del historial (las renovaciones del mismo método
    // no cuentan como cambio).
    $metodoAnterior = null;
    $codigosDistintos = [];
    foreach ($historialMetodos as $indiceHistorial => $itemHistorialComparar) {
        $codigoComparar = (string)($itemHistorialComparar['codigo'] ?? '');
        if ($codigoComparar === '') {
            continue;
        }
        if (!in_array($codigoComparar, $codigosDistintos, true)) {
            $codigosDistintos[] = $codigoComparar;
        }
        if ($metodoAnterior === null && $codigoComparar !== $codigo && $codigo !== '') {
            $metodoAnterior = $itemHistorialComparar;
            $metodoAnterior['_indice'] = $indiceHistorial;
        }
    }
    $cambioMetodoDetectado = $metodoAnterior !== null;
    if ($metodoAnterior !== null) {
        unset($metodoAnterior['_indice']);
    }
    $metodosDistintosRegistrados = count($codigosDistintos);

    $estabReferencia = '';
    if ($metodoActualHistorial !== null) {
        $estabReferencia = trim((string)($metodoActualHistorial['cod_estab'] ?? ''));
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
    $obstetraActualDni = $metodoActualHistorial !== null ? (string)($metodoActualHistorial['codpsal'] ?? '') : '';
    $obstetraActualNombre = $metodoActualHistorial !== null ? (string)($metodoActualHistorial['obstetra_nombre'] ?? '') : '';
    $establecimientoActualNombre = $metodoActualHistorial !== null
        ? (string)($metodoActualHistorial['establecimiento'] ?? '')
        : $nombreOrigen;

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
    if ($cambioMetodoDetectado && $metodoAnterior !== null) {
        $recomendacion .= ' Se detectó CAMBIO DE MÉTODO: antes ' . (string)$metodoAnterior['nombre']
            . ' (' . (string)$metodoAnterior['fecha'] . '), ahora ' . $nombreMetodo . '.';
    }

    $metodoActual = [
        'codigo' => $codigo,
        'codigo_his' => $codigoHis,
        'nombre' => $nombreMetodo,
        'fecha_aplicacion_iso' => $fechaAplicacionIso,
        'fecha_aplicacion' => $fechaAplicacionMostrar,
        'dias_ciclo' => $diasCiclo,
        'fecha_proximo_iso' => $fechaProximoIso,
        'fecha_proximo' => $fechaProximoMostrar,
        'dias_restantes' => $diasParaProximo,
        'dias_vencidos' => $diasVencidos,
        'estado' => $estado,
        'id_dosis' => $metodoActualHistorial !== null ? (string)($metodoActualHistorial['id_dosis'] ?? '') : '',
        'obstetra_dni' => $obstetraActualDni,
        'obstetra_nombre' => $obstetraActualNombre,
        'cod_estab' => $estabReferencia,
        'establecimiento' => $establecimientoActualNombre,
    ];

    return [
        'tieneMetodoRegistrado' => $codigo !== '',
        'codigoMetodo' => $codigo,
        'codigoHis' => $codigoHis,
        'nombreMetodo' => $nombreMetodo,
        'dosis' => $metodoActual['id_dosis'],
        'fechaUltimaAplicacion' => $fechaAplicacionMostrar,
        'fechaUltimaAplicacionIso' => $fechaAplicacionIso,
        'diasCiclo' => $diasCiclo,
        'fechaProximoMetodo' => $fechaProximoMostrar,
        'fechaProximoMetodoIso' => $fechaProximoIso,
        'diasParaProximo' => $diasParaProximo,
        'estadoProgramacion' => $estado,
        'obstetraDni' => $obstetraActualDni,
        'obstetraNombre' => $obstetraActualNombre,
        'establecimientoNombre' => $establecimientoActualNombre,
        'metodoActual' => $metodoActual,
        'cambioMetodoDetectado' => $cambioMetodoDetectado,
        'esNuevoMetodo' => $cambioMetodoDetectado,
        'metodoAnterior' => $metodoAnterior,
        'historialMetodos' => $historialMetodos,
        'metodosDistintosRegistrados' => $metodosDistintosRegistrados,
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
    $codigosMetodo = codigos_consulta_metodos($catalogo);
    // Consejería/orientación en planificación familiar. Se incluyen los códigos
    // base y, mediante prefijo 99208.%, los subcódigos de orientación que el HIS
    // histórico haya registrado. La clasificación final se hace con el catálogo:
    // si el código resuelve a un método es ENTREGA; si no, es CONSEJERÍA.
    $codigosConsejeria = ['99208', '99208.00', '9920800', '99402.04', '9940204'];
    $codigos = array_values(array_unique(array_merge($codigosMetodo, $codigosConsejeria)));
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
        WHERE h.DNI = ?
          AND (dt.DX IN ({$placeholders}) OR dt.DX LIKE '99208.%')
        ORDER BY h.ANO DESC, h.MES DESC, h.DIA DESC
        LIMIT 30
    ";
    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute(array_merge([$dni], $codigos));
        $filas = $stmt->fetchAll();
    } catch (Throwable $e) {
        try {
            $stmt = $pdo->prepare($sql);
            $stmt->execute(array_merge([$dni], $codigos));
            $filas = $stmt->fetchAll();
        } catch (Throwable $e2) {
            return [];
        }
    }

    foreach ($filas as &$fila) {
        $codigoDx = trim((string)($fila['DX'] ?? ''));
        $meta = resolver_metodo_catalogo($catalogo, $codigoDx);
        $esMetodo = $meta !== null;
        $esConsejeria = !$esMetodo && (
            in_array($codigoDx, $codigosConsejeria, true)
            || str_starts_with($codigoDx, '99208.')
        );
        $fila['tipo_atencion'] = $esMetodo ? 'ENTREGA_METODO' : ($esConsejeria ? 'CONSEJERIA' : 'OTRO');
        $fila['es_metodo'] = $esMetodo;
        $fila['es_consejeria'] = $esConsejeria;
        $fila['metodo_codigo'] = $esMetodo ? (string)($meta['codigo_dx'] ?? '') : '';
        $fila['metodo_nombre'] = $esMetodo ? (string)($meta['nombre_metodo'] ?? '') : '';
    }
    unset($fila);
    return $filas;
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
        HospitalHuaralDB::registrarAuditoria($session['dni'], 'LOOKUP_RATE_LIMITED', 'Límite de 30 consultas de documento por minuto excedido. Posible scraping bloqueado.', $session['cod_estab'], $session['platform']);
        json_error('Límite de 30 consultas de documento por minuto alcanzado. Espere y vuelva a intentar.', 429, [
            'retryAfter' => $limit['retryAfter'],
        ]);
    }
    HospitalHuaralDB::rateLimitHit($bucket, 60);

    $documentoRaw = (string)($_GET['dni'] ?? $_GET['documento'] ?? '');
    $tipoSolicitado = (string)($_GET['tipo_doc'] ?? $_GET['tipo_documento'] ?? '');
    $validacionDocumento = validar_documento_paciente($documentoRaw, $tipoSolicitado);
    if (!$validacionDocumento['ok']) {
        json_error(
            $validacionDocumento['error'] . ' Seleccione el tipo de documento correcto (DNI, CE, Pasaporte, PTP o CNV/SIS).',
            400,
            ['code' => 'DOCUMENTO_INVALIDO', 'tipo_doc' => $validacionDocumento['tipo']]
        );
    }
    $dni = $validacionDocumento['documento'];
    $tipoDoc = $validacionDocumento['tipo'];

    $codEstab = establecimiento_registro_sesion($session);
    $codEstabSolicitado = strtoupper(trim((string)($_GET['cod_estab'] ?? '')));
    if (is_admin_session($session) && $codEstabSolicitado !== '' && $codEstabSolicitado !== 'ALL') {
        $canonicoSolicitado = hospital_codigo_canonico($codEstabSolicitado);
        if (hospital_establecimiento($canonicoSolicitado) !== null) {
            $codEstab = str_pad($canonicoSolicitado, 9, '0', STR_PAD_LEFT);
        }
    }
    $est = hospital_establecimiento($codEstab) ?: [];

    // 7.1 Historia general (la más reciente)
    $hisRecord = null;
    try {
        $stmt = $pdo->prepare("
            SELECT h.ID, h.DNI, h.COD_ESTAB, h.COD_SERVSA, h.CODPSAL, h.COD_DOC,
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
            'tipo_atencion' => (string)($row['tipo_atencion'] ?? 'OTRO'),
            'es_metodo' => (bool)($row['es_metodo'] ?? false),
            'es_consejeria' => (bool)($row['es_consejeria'] ?? false),
            'metodo_codigo' => (string)($row['metodo_codigo'] ?? ''),
            'metodo_nombre' => (string)($row['metodo_nombre'] ?? ''),
        ];
    }
    $historialConsejeria = array_values(array_filter(
        $historial99208,
        static fn (array $item): bool => (bool)($item['es_consejeria'] ?? false)
    ));
    $historialEntregaMetodo = array_values(array_filter(
        $historial99208,
        static fn (array $item): bool => (bool)($item['es_metodo'] ?? false)
    ));
    $tiene99208 = count($historial99208) > 0;
    $tieneConsejeria99208 = count($historialConsejeria) > 0;
    $tieneEntregaMetodo99208 = count($historialEntregaMetodo) > 0;
    $primer99208 = $historial99208[0] ?? null;
    $primerConsejeria = $historialConsejeria[0] ?? null;
    $primerEntregaMetodo = $historialEntregaMetodo[0] ?? null;
    $mensaje99208 = $tiene99208
        ? sprintf(
            'La paciente con DNI %s registra atenciones de Planificación Familiar en la Red Huaral-Chancay: %s consejería(s) y %s entrega(s)/administración(es) de método.',
            $dni,
            count($historialConsejeria),
            count($historialEntregaMetodo)
        )
        : sprintf('La paciente con DNI %s no registra atención con el código 99208 en la Red Huaral-Chancay.', $dni);
    $mensajeConsejeria = $tieneConsejeria99208
        ? sprintf(
            'CONSEJERÍA / ORIENTACIÓN 99208: última atención el %s en %s (DX %s).',
            $primerConsejeria['fecha'],
            $primerConsejeria['establecimiento'],
            $primerConsejeria['dx']
        )
        : sprintf('La paciente con DNI %s no registra consejería/orientación 99208.', $dni);
    $mensajeEntregaMetodo = $tieneEntregaMetodo99208
        ? sprintf(
            'ADMINISTRACIÓN / ENTREGA DE MÉTODO: última atención el %s en %s (%s, DX %s).',
            $primerEntregaMetodo['fecha'],
            $primerEntregaMetodo['establecimiento'],
            $primerEntregaMetodo['metodo_nombre'] !== '' ? $primerEntregaMetodo['metodo_nombre'] : 'método registrado',
            $primerEntregaMetodo['dx']
        )
        : sprintf('La paciente con DNI %s no registra entrega/administración de método en el catálogo oficial.', $dni);

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
    $captacionMismoEstablecimiento = false;
    $nombreEstabCaptacion = '';
    if ($existing) {
        $captacionMismoEstablecimiento = hospital_codigo_canonico((string)($existing['cod_estab'] ?? '')) === $codEstab;
        $nombreEstabCaptacion = hospital_nombre_establecimiento((string)($existing['cod_estab'] ?? ''));
        $existing['celular'] = HospitalHuaralDB::decryptPII((string)$existing['celular']);
        $existing['correo'] = HospitalHuaralDB::decryptPII((string)$existing['correo']);
        $existing['direccion'] = HospitalHuaralDB::decryptPII((string)$existing['direccion']);
        $tipoDocExistente = tipo_documento_normalizado((string)($existing['tipo_doc'] ?? $tipoDoc)) ?: $tipoDoc;
        $existing['tipo_doc'] = $tipoDocExistente;
        $existing['tipo_doc_etiqueta'] = etiqueta_tipo_documento($tipoDocExistente);
        $existing['estab_nombre'] = $nombreEstabCaptacion;
        $existing['estado_etiqueta'] = str_replace('_', ' ', (string)($existing['estado_paciente'] ?? ''));
        $existing['mismo_establecimiento'] = $captacionMismoEstablecimiento;
        unset($existing['encrypted_raw']);
    }
    $registroPrevio = $existing ? [
        'ya_registrada' => true,
        'mismo_establecimiento' => $captacionMismoEstablecimiento,
        'cod_estab' => (string)($existing['cod_estab'] ?? ''),
        'establecimiento' => (string)($existing['estab_nombre'] ?? hospital_nombre_establecimiento((string)($existing['cod_estab'] ?? ''))),
        'fecha_registro' => (string)($existing['fecha_registro'] ?? ''),
        'estado' => (string)($existing['estado_paciente'] ?? ''),
        'estado_etiqueta' => (string)($existing['estado_etiqueta'] ?? ''),
        'obstetra_dni' => (string)($existing['codpsal_obstetra'] ?? ''),
    ] : [
        'ya_registrada' => false,
        'mismo_establecimiento' => false,
        'cod_estab' => '',
        'establecimiento' => '',
        'fecha_registro' => '',
        'estado' => '',
        'estado_etiqueta' => '',
        'obstetra_dni' => '',
    ];

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
        $tipoDocHis = $tipoDoc;
        if (isset($hisRecord['COD_DOC']) && (string)$hisRecord['COD_DOC'] !== '') {
            $tipoDocHis = tipo_documento_normalizado((string)$hisRecord['COD_DOC']) ?: $tipoDoc;
        }
        $precargaDesdeHis = [
            'apellido_paterno' => (string)($hisRecord['Apellido_p'] ?? ''),
            'apellido_materno' => (string)($hisRecord['Apellido_m'] ?? ''),
            'nombres' => (string)($hisRecord['Dnombres'] ?? ($hisRecord['Pnombre'] ?? '')),
            'edad' => (int)($hisRecord['EDAD'] ?? 0),
            'dni' => (string)($hisRecord['DNI'] ?? $dni),
            'tipo_doc' => $tipoDocHis,
            'tipo_doc_etiqueta' => etiqueta_tipo_documento($tipoDocHis),
        ];
    }
    $hisMismoEstablecimiento = $hisRecord
        ? hospital_codigo_canonico((string)($hisRecord['COD_ESTAB'] ?? '')) === $codEstab
        : false;
    $pacienteEncontradaRed = (bool)$hisRecord || $registroPrevio['ya_registrada'];
    $pacienteEnMismoEstablecimiento = $hisMismoEstablecimiento || $captacionMismoEstablecimiento;
    $pacienteEnOtroEstablecimiento = $pacienteEncontradaRed && !$pacienteEnMismoEstablecimiento;
    $estabUbicacionCodigo = '';
    $estabUbicacionNombre = '';
    if ($hisMismoEstablecimiento || $captacionMismoEstablecimiento) {
        $estabUbicacionCodigo = $codEstab;
        $estabUbicacionNombre = $nombreEstab;
    } elseif ($hisRecord) {
        $estabUbicacionCodigo = (string)($hisRecord['COD_ESTAB'] ?? '');
        $estabUbicacionNombre = resolver_nombre_establecimiento($pdo, $estabUbicacionCodigo);
    } elseif ($existing) {
        $estabUbicacionCodigo = (string)($existing['cod_estab'] ?? '');
        $estabUbicacionNombre = $nombreEstabCaptacion;
    }
    if (!$pacienteEncontradaRed) {
        $mensajeUbicacionPaciente = 'La paciente no registra atenciones previas en la Red Huaral-Chancay.';
    } elseif ($pacienteEnMismoEstablecimiento) {
        $mensajeUbicacionPaciente = 'La paciente SÍ registra atenciones en ESTE establecimiento (' . $nombreEstab . ').';
    } else {
        $mensajeUbicacionPaciente = 'La paciente registra atenciones en OTRO establecimiento de la Red: '
            . ($estabUbicacionNombre !== '' ? $estabUbicacionNombre : 'establecimiento no identificado') . '.';
    }

    $mensajeRegistroPrevio = $registroPrevio['ya_registrada']
        ? sprintf(
            'La paciente YA ESTÁ REGISTRADA en la app en %s: %s, fecha %s, estado %s.',
            $registroPrevio['mismo_establecimiento'] ? 'ESTE establecimiento' : 'OTRO establecimiento',
            $registroPrevio['establecimiento'] !== '' ? $registroPrevio['establecimiento'] : 'establecimiento no registrado',
            $registroPrevio['fecha_registro'] !== '' ? $registroPrevio['fecha_registro'] : 'sin fecha',
            $registroPrevio['estado_etiqueta'] !== '' ? $registroPrevio['estado_etiqueta'] : 'sin estado'
        )
        : 'La paciente no tiene una captación previa registrada en la app.';

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
        'foundInApp' => $registroPrevio['ya_registrada'],
        'documento' => [
            'numero' => $dni,
            'tipo_doc' => $tipoDoc,
            'tipo_doc_etiqueta' => etiqueta_tipo_documento($tipoDoc),
        ],
        'pacienteYaRegistrada' => $registroPrevio['ya_registrada'],
        'registroPrevio' => $registroPrevio,
        'mensajeRegistroPrevio' => $mensajeRegistroPrevio,
        'ubicacionPaciente' => [
            'encontrada' => $pacienteEncontradaRed,
            'mismo_establecimiento' => $pacienteEnMismoEstablecimiento,
            'otro_establecimiento' => $pacienteEnOtroEstablecimiento,
            'cod_estab' => $estabUbicacionCodigo,
            'establecimiento' => $estabUbicacionNombre,
            'mensaje' => $mensajeUbicacionPaciente,
        ],
        'mensajeUbicacionPaciente' => $mensajeUbicacionPaciente,
        'foundInEstablecimiento' => $hisMismoEstablecimiento,
        'foundInOtherEstablishment' => $pacienteEnOtroEstablecimiento,
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
            'tieneConsejeria' => $tieneConsejeria99208,
            'tieneEntregaMetodo' => $tieneEntregaMetodo99208,
            'mensajeOficial99208' => $mensaje99208,
            'mensajeConsejeria' => $mensajeConsejeria,
            'mensajeEntregaMetodo' => $mensajeEntregaMetodo,
            'historial99208' => $historial99208,
            'historialConsejeria' => $historialConsejeria,
            'historialMetodos' => $historialEntregaMetodo,
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
    // Solo se admiten la fecha exacta y la ventana accionable de 7 días.
    // Cualquier modo histórico/vencidas de clientes antiguos se normaliza a
    // fecha exacta para no disparar escaneos masivos sobre his_dl.
    if (!in_array($rangoModo, ['exacto', 'ventana_7d'], true)) {
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
    // 7-B.2 FUENTE ÚNICA DE VERDAD: exactamente la misma función que alimenta
    // las alertas superiores, la agenda y el padrón. Así “HOY” del dashboard y
    // “Toca fecha” de la programación devuelven siempre el mismo número.
    $esAdminReporte = is_admin_session($session);
    $rolReporte = rol_sesion($session);
    $esObstetraReporte = !$esAdminReporte && $rolReporte !== 'JEFA_OBSTETRAS';
    $esJefaReporte = $rolReporte === 'JEFA_OBSTETRAS';
    $modoRedReporte = $esAdminReporte
        && normalizarCodEstab((string)($session['cod_estab'] ?? '')) === 'ALL';
    // Programación: obstetra y jefatura ven TODA la programación de su
    // establecimiento, SIN filtro CODPSAL. El administrador ve la red (ALL) o
    // la IPRESS de su sesión.
    $alcance = $modoRedReporte ? 'red' : 'establecimiento';
    $ambitoReporte = $modoRedReporte ? 'red' : 'establecimiento';
    $codigosEstabProgramacion = $modoRedReporte
        ? []
        : codigos_establecimiento_consulta($pdo, $session);
    $reporteCtx = [
        'rol' => $rolReporte,
        'es_obstetra' => $esObstetraReporte,
        'es_jefa' => $esJefaReporte,
        'alcance_red' => $modoRedReporte,
        'dni_obstetra' => '',
        'codigos_estab' => $codigosEstabProgramacion,
    ];

    $fechaBaseIso = $fechaBase->format('Y-m-d');
    $hastaProgramacion = $rangoModo === 'ventana_7d'
        ? $fechaBase->modify('+7 days')
        : $fechaBase;
    $hastaProgramacionIso = $hastaProgramacion->format('Y-m-d');

    try {
        $candidatos = programacion_candidatos_rango(
            $pdo,
            $session,
            $catalogo,
            $fechaBaseIso,
            $hastaProgramacionIso,
            $codigosFiltro
        );
    } catch (Throwable $e) {
        error_log('[PlanificaHIS] reporte_programacion query failure: ' . $e->getMessage());
        json_error('No se pudo calcular la programación. Verifique los índices clínicos del HIS e intente nuevamente.', 503, [
            'code' => 'REPORTE_QUERY_FAILED',
        ]);
    }

    $hoy = new DateTimeImmutable('today');
    $hoyIso = $hoy->format('Y-m-d');
    $mananaIso = $hoy->modify('+1 day')->format('Y-m-d');
    $dnis = [];
    $candidatosFiltrados = [];
    foreach ($candidatos as $dniKey => $sel) {
        $fechaProximo = (string)$sel['fecha_proximo'];
        if ($fechaProximo < $fechaBaseIso || $fechaProximo > $hastaProgramacionIso) {
            continue;
        }
        $diasRestantes = (int)$hoy->diff(new DateTimeImmutable($fechaProximo))->format('%r%a');
        if ($fechaProximo === $fechaBaseIso) {
            $estado = 'TOCA_EN_FECHA';
        } elseif ($diasRestantes >= 0 && $diasRestantes <= 7) {
            $estado = 'PROXIMO_7_DIAS';
        } else {
            $estado = 'AL_DIA';
        }
        $sel['dias_restantes'] = $diasRestantes;
        $sel['estado'] = $estado;
        $candidatosFiltrados[$dniKey] = $sel;
        $dnis[] = $dniKey;
    }

    // 7-B.3 Cruce por DNI con pacientes_sin_metodo para adjuntar contacto y
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
    foreach ($candidatosFiltrados as $dniKey => $sel) {
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
            'codigo_metodo' => (string)$sel['codigo'],
            'codigo_his' => (string)$sel['codigo_his'],
            'nombre_metodo' => (string)($sel['meta']['nombre_metodo'] ?? $sel['codigo']),
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

    // Resumen accionable: sin “vencidas” ni escaneos históricos. “Toca fecha”
    // cuenta exactamente las pacientes cuya fecha de próximo control es la
    // fecha objetivo; para HOY coincide 1:1 con la tarjeta superior.
    $resumen = [
        'total' => count($filas),
        'toca_en_fecha' => 0,
        'manana' => 0,
        'proximo_7_dias' => 0,
        'al_dia' => 0,
    ];
    foreach ($filas as $fila) {
        $fechaProximoFila = (string)$fila['fecha_proximo_metodo_iso'];
        $diasFila = (int)$fila['dias_restantes'];
        if ($fechaProximoFila === $fechaBaseIso) {
            $resumen['toca_en_fecha']++;
        }
        if ($fechaBaseIso <= $hoyIso && $fechaProximoFila === $mananaIso) {
            $resumen['manana']++;
        }
        if ($diasFila >= 2 && $diasFila <= 7) {
            $resumen['proximo_7_dias']++;
        }
        if ($diasFila > 7) {
            $resumen['al_dia']++;
        }
    }

    $establecimientoActual = [
        'codigo' => (string)$session['cod_estab'],
        'nombre' => (string)$session['estab_nombre'],
        'distrito' => '',
    ];
    $estInfoActual = hospital_establecimiento((string)$session['cod_estab']);
    $establecimientoActual['distrito'] = (string)($estInfoActual['DISTRITO'] ?? '');

    $obstetraNombreReporte = '';
    if ($modoRedReporte) {
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
        'obstetra_dni' => '',
        'obstetra_nombre' => $obstetraNombreReporte,
        'codigo_metodo' => $codigoMetodoRaw !== '' ? $codigoMetodoRaw : 'TODOS',
        'establecimiento' => $establecimientoActual,
        'resumen' => $resumen,
        'catalogo' => array_values($catalogo),
        'filas' => $filas,
        'metadata' => [
            'generado_en' => date('c'),
            'ventana_desde' => $fechaBaseIso,
            'ventana_hasta' => $hastaProgramacionIso,
            'fuente_catalogo' => 'app_catalogo_metodos',
            'fuente_unica' => 'programacion_candidatos_rango',
            'emisor' => [
                'dni' => (string)$session['dni'],
                'nombre' => HospitalHuaralDB::nombrePersona((string)$session['dni'], $pdo),
                'rol' => HospitalHuaralDB::rolEtiqueta($reporteCtx['rol']),
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
    $grupos = in_array($grupoFiltro, ['manana', 'hoy', 'proximos_7'], true)
        ? [$grupoFiltro]
        : ['hoy', 'manana', 'proximos_7'];
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
    $modoRedPadron = is_admin_session($session)
        && strtoupper(trim((string)($session['cod_estab'] ?? ''))) === 'ALL';
    $obstetraPadron = preg_replace('/[^0-9A-Za-z]/', '', (string)($_GET['obstetra'] ?? '')) ?? '';
    if ($obstetraPadron === 'TODOS') {
        $obstetraPadron = '';
    }
    $obstetraNombrePadron = $obstetraPadron !== ''
        ? HospitalHuaralDB::nombrePersona($obstetraPadron, $pdo)
        : ((string)($perfil['rol'] ?? '') === 'OBSTETRA'
            ? (string)($perfil['nombreCompleto'] ?? '')
            : ($modoRedPadron ? 'TODAS LAS OBSTETRAS DE LA RED' : 'TODAS LAS OBSTETRAS DEL ESTABLECIMIENTO'));
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
            'proximos_7' => (int)$alertas['proximos_7'],
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
function reporte_codigos_establecimiento(array $session, string $alcance = ''): array
{
    if (is_admin_session($session) && strtoupper(trim((string)($session['cod_estab'] ?? ''))) === 'ALL') {
        return [];
    }
    return codigos_establecimiento_sesion($session);
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
        return ['estado' => 'VENCIDA', 'etiqueta' => 'Control pendiente / captación inmediata', 'dias_restantes' => $dias, 'prioridad' => 0];
    }
    if ($dias <= 7) {
        return ['estado' => 'PROXIMA', 'etiqueta' => 'Le toca dentro de 7 días', 'dias_restantes' => $dias, 'prioridad' => 1];
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
    $esAdminCampo = is_admin_session($session);
    $modoRedCampo = $esAdminCampo
        && strtoupper(trim((string)($session['cod_estab'] ?? ''))) === 'ALL';
    $reporteCtxCampo = resolver_alcance_reporte(
        $session,
        (string)($input['obstetra'] ?? ''),
        $modoRedCampo ? 'red' : 'establecimiento'
    );
    $soloMisCaptacionesCampo = $reporteCtxCampo['es_obstetra'];
    $alcance = $modoRedCampo ? 'red' : 'establecimiento';
    $obstetra = $reporteCtxCampo['dni_obstetra'];

    $where = ['p.fecha_registro >= :desde', 'p.fecha_registro < :hasta_exclusivo'];
    $params = [':desde' => $desde, ':hasta_exclusivo' => $hastaExclusivo];
    [$condAlcanceCampo, $paramsAlcanceCampo] = condicion_alcance_pacientes($pdo, $session, 'p', $obstetra, 'campo');
    if ($condAlcanceCampo !== '') {
        $where[] = '(' . $condAlcanceCampo . ')';
        $params = array_merge($params, $paramsAlcanceCampo);
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
    $q = trim((string)($input['q'] ?? ''));
    if ($q !== '') {
        $where[] = '(p.dni LIKE :q1 OR p.apellido_paterno LIKE :q2 OR p.apellido_materno LIKE :q3 OR p.nombres LIKE :q4)';
        $like = '%' . str_replace(['%', '_'], ['\%', '\_'], $q) . '%';
        $params[':q1'] = $like;
        $params[':q2'] = $like;
        $params[':q3'] = $like;
        $params[':q4'] = $like;
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
        [$condSector, $paramsSector] = condicion_alcance_pacientes($pdo, $session, 'p', $obstetra, 'sector');
        if ($condSector !== '') {
            $whereSector[] = '(' . $condSector . ')';
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
        [$condObs, $paramsObs] = condicion_alcance_pacientes($pdo, $session, 'p', $obstetra, 'obs');
        $stmtObs = $pdo->prepare("
            SELECT p.codpsal_obstetra, COUNT(*) AS total
            FROM pacientes_sin_metodo p
            " . ($condObs !== '' ? ' WHERE (' . $condObs . ')' : '') . "
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
        // El último método se busca en TODA la Red por DNI: la paciente pudo
        // renovar en otra IPRESS y aun así debe mostrarse su método vigente.
        $ultimas = reporte_ultimas_atenciones_metodo($pdo, $dnisPagina, $catalogo);
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
            'ambito' => $soloMisCaptacionesCampo ? 'mis_captaciones' : 'establecimiento',
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
        'obstetra_dni' => $soloMisCaptacionesCampo ? (string)$session['dni'] : (($obstetra !== '' && $obstetra !== 'TODOS') ? $obstetra : ''),
        'obstetra_nombre' => $soloMisCaptacionesCampo
            ? HospitalHuaralDB::nombrePersona((string)$session['dni'], $pdo)
            : (($obstetra !== '' && $obstetra !== 'TODOS')
                ? HospitalHuaralDB::nombrePersona($obstetra, $pdo)
                : ($modoRedCampo
                    ? 'TODAS LAS OBSTETRAS DE LA RED'
                    : 'TODAS LAS OBSTETRAS DEL ESTABLECIMIENTO')),
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
    $esAdminMetodos = is_admin_session($session);
    $modoRedMetodos = $esAdminMetodos
        && strtoupper(trim((string)($session['cod_estab'] ?? ''))) === 'ALL';
    $reporteCtxMetodos = resolver_alcance_reporte(
        $session,
        (string)($input['obstetra'] ?? ''),
        $modoRedMetodos ? 'red' : 'establecimiento'
    );
    $soloMisCaptacionesMetodos = $reporteCtxMetodos['es_obstetra'];
    $alcance = $modoRedMetodos ? 'red' : 'establecimiento';
    $codigosEstab = $modoRedMetodos ? [] : codigos_establecimiento_sesion($session);
    $obstetraMetodos = $reporteCtxMetodos['dni_obstetra'];
    $catalogo = catalogo_metodos_planificacion($pdo);

    $where = ['p.fecha_registro >= :desde', 'p.fecha_registro < :hasta_exclusivo'];
    $params = [':desde' => $desde, ':hasta_exclusivo' => $hastaExclusivo];
    [$condAlcanceMetodos, $paramsAlcanceMetodos] = condicion_alcance_pacientes($pdo, $session, 'p', $obstetraMetodos, 'metodos');
    if ($condAlcanceMetodos !== '') {
        $where[] = '(' . $condAlcanceMetodos . ')';
        $params = array_merge($params, $paramsAlcanceMetodos);
    }
    $sector = strtoupper(trim((string)($input['sector'] ?? '')));
    if ($sector !== '' && $sector !== 'TODOS') {
        $where[] = 'p.sector = :sector';
        $params[':sector'] = $sector;
    }
    $whereSql = implode(' AND ', $where);

    // Base acotada: máximo 800 pacientes del periodo/establecimiento (5000 en
    // exportaciones completas) para mantener fluidez en celulares de gama media.
    $limiteBase = $perPage > 200 ? 5000 : 800;
    $stmt = $pdo->prepare("
        SELECT p.*
        FROM pacientes_sin_metodo p
        WHERE {$whereSql}
        ORDER BY p.fecha_registro DESC, p.id DESC
        LIMIT {$limiteBase}
    ");
    $stmt->execute($params);
    $base = $stmt->fetchAll();
    $fuenteBase = 'captacion';
    $ultimasFallbackHis = [];

    // Si el padrón de captación tiene pocos o ningún registro para el rango,
    // el reporte NO debe salir en cero: se completa con las atenciones reales
    // del HIS del establecimiento para el mismo periodo.
    if (count($base) < 10 && ($sector === '' || $sector === 'TODOS')) {
        $codigosDxFallback = codigos_consulta_metodos($catalogo);
        if ($codigosDxFallback) {
            $dnisYaBase = [];
            foreach ($base as $filaBaseExistente) {
                $dnisYaBase[(string)$filaBaseExistente['dni']] = true;
            }
            $paramsFallbackHis = [];
            $rangoFallbackHis = sql_condicion_rango_ymd('h', $desde, $hasta, $paramsFallbackHis);
            $marcasDxFallback = implode(',', array_fill(0, count($codigosDxFallback), '?'));
            $condAlcanceFallback = '';
            $paramsAlcanceFallback = [];
            if ($soloMisCaptacionesMetodos) {
                $variantesObsFallback = variantes_codpsal_dni((string)$session['dni']);
                $condAlcanceFallback = ' AND h.CODPSAL IN (' . implode(',', array_fill(0, count($variantesObsFallback), '?')) . ')';
                $paramsAlcanceFallback = $variantesObsFallback;
            } elseif ($obstetraMetodos !== '') {
                $variantesObsFallback = variantes_codpsal_dni($obstetraMetodos);
                $condAlcanceFallback = ' AND h.CODPSAL IN (' . implode(',', array_fill(0, count($variantesObsFallback), '?')) . ')';
                $paramsAlcanceFallback = $variantesObsFallback;
            } elseif (!$modoRedMetodos) {
                $orFallback = [];
                $paramsOrFallback = [];
                if ($codigosEstab) {
                    $orFallback[] = 'h.COD_ESTAB IN (' . implode(',', array_fill(0, count($codigosEstab), '?')) . ')';
                    $paramsOrFallback = array_merge($paramsOrFallback, $codigosEstab);
                }
                if (rol_sesion($session) === 'JEFA_OBSTETRAS') {
                    $dnisAsignadasFallback = dnis_obstetras_establecimiento($pdo, $codigosEstab);
                    if ($dnisAsignadasFallback) {
                        $orFallback[] = 'h.CODPSAL IN (' . implode(',', array_fill(0, count($dnisAsignadasFallback), '?')) . ')';
                        $paramsOrFallback = array_merge($paramsOrFallback, $dnisAsignadasFallback);
                    }
                }
                if ($orFallback) {
                    $condAlcanceFallback = ' AND (' . implode(' OR ', $orFallback) . ')';
                    $paramsAlcanceFallback = $paramsOrFallback;
                }
            }
            $sqlFallbackHis = "
                SELECT h.ID, h.DNI, h.COD_ESTAB, h.CODPSAL, h.EDAD, h.HCLFAM,
                       TRIM(h.Apellido_p) AS apellido_paterno,
                       TRIM(h.Apellido_m) AS apellido_materno,
                       TRIM(COALESCE(NULLIF(h.Dnombres, ''), h.Pnombre)) AS nombres,
                       h.ANO, h.MES, h.DIA, h.fecha_reg,
                       dt.DX, dt.fecha_reg AS fecha_dx
                FROM his_dl h
                INNER JOIN his_dl_dt dt ON dt.ID = h.ID
                WHERE h.ANO BETWEEN ? AND ?
                  AND {$rangoFallbackHis}
                  AND dt.DX IN ({$marcasDxFallback})
                  {$condAlcanceFallback}
                ORDER BY h.DNI ASC, h.ANO DESC, h.MES DESC, h.DIA DESC, h.ID DESC
                LIMIT 20000
            ";
            $paramsFallbackHis = array_merge(
                [(int)substr($desde, 0, 4), (int)substr($hasta, 0, 4)],
                $paramsFallbackHis,
                $codigosDxFallback,
                $paramsAlcanceFallback
            );
            try {
                $stmtFallbackHis = $pdo->prepare($sqlFallbackHis);
                $stmtFallbackHis->execute($paramsFallbackHis);
                $mejoresFallbackHis = [];
                foreach ($stmtFallbackHis->fetchAll() as $filaHisFallback) {
                    $dniHisFallback = trim((string)($filaHisFallback['DNI'] ?? $filaHisFallback['dni'] ?? ''));
                    if ($dniHisFallback === '' || isset($dnisYaBase[$dniHisFallback])) {
                        continue;
                    }
                    $codigoHisFallback = trim((string)($filaHisFallback['DX'] ?? ''));
                    $metaHisFallback = resolver_metodo_catalogo($catalogo, $codigoHisFallback);
                    if ($metaHisFallback === null) {
                        continue;
                    }
                    $fechaHisFallback = fecha_aplicacion_his($filaHisFallback);
                    if ($fechaHisFallback === '') {
                        continue;
                    }
                    $diasHisFallback = max(0, (int)($metaHisFallback['dias_ciclo'] ?? 0));
                    $scoreHisFallback = $fechaHisFallback . '|' . str_pad((string)$diasHisFallback, 4, '0', STR_PAD_LEFT)
                        . '|' . str_pad((string)(int)($filaHisFallback['ID'] ?? 0), 12, '0', STR_PAD_LEFT);
                    if (
                        isset($mejoresFallbackHis[$dniHisFallback])
                        && strcmp($scoreHisFallback, (string)$mejoresFallbackHis[$dniHisFallback]['_score']) <= 0
                    ) {
                        continue;
                    }
                    $mejoresFallbackHis[$dniHisFallback] = [
                        '_score' => $scoreHisFallback,
                        'row' => $filaHisFallback,
                        'meta' => $metaHisFallback,
                        'fecha' => $fechaHisFallback,
                        'dias' => $diasHisFallback,
                    ];
                }
                $nuevosFallbackHis = array_slice($mejoresFallbackHis, 0, $limiteBase, true);
                foreach ($nuevosFallbackHis as $dniHisNuevo => $seleccionHisNueva) {
                    $rowHisNuevo = $seleccionHisNueva['row'];
                    $base[] = [
                        'id' => 0,
                        'dni' => (string)$dniHisNuevo,
                        'apellido_paterno' => (string)($rowHisNuevo['apellido_paterno'] ?? ''),
                        'apellido_materno' => (string)($rowHisNuevo['apellido_materno'] ?? ''),
                        'nombres' => (string)($rowHisNuevo['nombres'] ?? ''),
                        'edad' => (int)($rowHisNuevo['EDAD'] ?? $rowHisNuevo['edad'] ?? 0),
                        'celular' => '',
                        'direccion' => '',
                        'distrito' => '',
                        'sector' => '',
                        'estado_paciente' => 'CAPTADA_CON_METODO',
                        'codpsal_obstetra' => (string)($rowHisNuevo['CODPSAL'] ?? ''),
                        'cod_estab' => (string)($rowHisNuevo['COD_ESTAB'] ?? ''),
                        'atencion_99208' => 1,
                        'fecha_registro' => (string)($rowHisNuevo['fecha_reg'] ?? ''),
                    ];
                    $proximaHisNueva = $seleccionHisNueva['dias'] > 0
                        ? (new DateTimeImmutable($seleccionHisNueva['fecha']))->modify('+' . $seleccionHisNueva['dias'] . ' days')->format('Y-m-d')
                        : null;
                    $ultimasFallbackHis[(string)$dniHisNuevo] = [
                        'codigo_metodo' => (string)($seleccionHisNueva['meta']['codigo_dx'] ?? ''),
                        'codigo_his' => (string)($rowHisNuevo['DX'] ?? ''),
                        'nombre_metodo' => (string)($seleccionHisNueva['meta']['nombre_metodo'] ?? ''),
                        'dias_ciclo' => (int)$seleccionHisNueva['dias'],
                        'fecha_ultima_atencion' => (string)$seleccionHisNueva['fecha'],
                        'fecha_proxima_cita' => $proximaHisNueva,
                        'cod_estab' => (string)($rowHisNuevo['COD_ESTAB'] ?? ''),
                    ];
                }
                if ($nuevosFallbackHis) {
                    $fuenteBase = 'his_dl';
                }
            } catch (Throwable $e) {
                error_log('[PlanificaHIS] reporte_metodos fallback his_dl: ' . $e->getMessage());
            }
        }
    }

    $dnis = array_map(static fn ($row) => (string)$row['dni'], $base);
    $dnisObs = array_map(static fn ($row) => (string)$row['codpsal_obstetra'], $base);
    $dicObs = nombres_personas_por_dni($pdo, $dnisObs);
    // Búsqueda en toda la Red por DNI (sin restringir al establecimiento del padrón).
    $ultimas = reporte_ultimas_atenciones_metodo($pdo, $dnis, $catalogo);
    if ($ultimasFallbackHis) {
        $ultimas = array_merge($ultimas, $ultimasFallbackHis);
    }

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
        $whereSectorMetodos = ["p.sector <> ''"];
        [$condSectorMetodos, $paramsSectorMetodos] = condicion_alcance_pacientes($pdo, $session, 'p', $obstetraMetodos, 'sector_m');
        if ($condSectorMetodos !== '') {
            $whereSectorMetodos[] = '(' . $condSectorMetodos . ')';
        }
        $stmtSect = $pdo->prepare("SELECT DISTINCT p.sector FROM pacientes_sin_metodo p WHERE " . implode(' AND ', $whereSectorMetodos) . " ORDER BY p.sector ASC LIMIT 500");
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
            'obstetra' => $obstetraMetodos !== '' ? $obstetraMetodos : 'TODOS',
            'alcance' => $alcance,
            'ambito' => $soloMisCaptacionesMetodos ? 'mis_captaciones' : 'establecimiento',
        ],
        'fuente' => $fuenteBase,
        'catalogo' => array_values($catalogo),
        'resumen' => [
            'vigente' => (int)($resumen['vigente'] ?? 0),
            'proxima' => (int)($resumen['proxima'] ?? 0),
            'proximos_7_dias' => (int)($resumen['proxima'] ?? 0),
            'sin_metodo' => (int)($resumen['sin_metodo'] ?? 0),
            'total' => (int)($resumen['total'] ?? 0),
        ],
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

function reporte_emisor_datos(array $session, PDO $pdo, string $establecimiento = ''): array
{
    $rol = trim((string)($session['rol_etiqueta'] ?? ''));
    if ($rol === '') {
        $rol = HospitalHuaralDB::rolEtiqueta((string)($session['rol'] ?? 'OBSTETRA'));
    }
    return [
        'nombre' => HospitalHuaralDB::nombrePersona((string)($session['dni'] ?? ''), $pdo),
        'rol' => $rol,
        'dni' => (string)($session['dni'] ?? ''),
        'establecimiento' => $establecimiento !== ''
            ? $establecimiento
            : (string)($session['estab_nombre'] ?? ''),
    ];
}

/**
 * Excel oficial enriquecido (.xls HTML/XML) con los DOS logos institucionales
 * incrustados en Base64: DIRESA Lima (izquierda) y Hospital SJB Huaral
 * (derecha). Conserva ceros a la izquierda con mso-number-format:"\@",
 * incluye resumen estadístico, filtros y pie de firma/emisor.
 *
 * @param array<int, string> $headers
 * @param array<int, array<int, string|int|float|null>> $rows
 * @param array<int, string> $metaLineas
 * @param array<int, string> $resumenLineas
 * @param array{nombre?: string, rol?: string, dni?: string, establecimiento?: string} $emisorDatos
 */
function reporte_excel_enriquecido(
    string $filename,
    string $titulo,
    string $subtitulo,
    array $metaLineas,
    array $headers,
    array $rows,
    array $codigosTexto = [],
    array $resumenLineas = [],
    array $emisorDatos = []
): void {
    if (headers_sent()) {
        return;
    }
    $filename = preg_replace('/[^A-Za-z0-9_\-\.]/', '_', $filename);
    header('Content-Type: application/vnd.ms-excel; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');

    $logoDiresa = '';
    $rutaDiresa = __DIR__ . '/public/logo-diresa-lima.jpg';
    if (is_file($rutaDiresa)) {
        $logoDiresa = 'data:image/jpeg;base64,' . base64_encode((string)file_get_contents($rutaDiresa));
    }
    $logoHospital = '';
    $rutaHospital = __DIR__ . '/public/logo.png';
    if (is_file($rutaHospital)) {
        $logoHospital = 'data:image/png;base64,' . base64_encode((string)file_get_contents($rutaHospital));
    }

    $e = static fn ($v): string => htmlspecialchars((string)($v ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $totalCols = max(1, count($headers));
    $metaHtml = '';
    foreach ($metaLineas as $linea) {
        $metaHtml .= '<tr><td colspan="' . $totalCols . '" style="font-size:9pt;color:#334155;border:1px solid #cbd5e1;padding:3px 6px;background:#f8fafc">' . $e($linea) . '</td></tr>';
    }
    $filasHtml = '';
    foreach ($rows as $row) {
        $filasHtml .= '<tr>';
        foreach (array_values($row) as $i => $valor) {
            $texto = (string)($valor ?? '');
            $estilo = 'border:1px solid #94a3b8;padding:3px 5px;font-size:8.5pt;vertical-align:top;';
            if (in_array($i, $codigosTexto, true)) {
                $estilo .= "mso-number-format:'\\@';";
            }
            $filasHtml .= '<td style="' . $estilo . '">' . $e($texto) . '</td>';
        }
        $filasHtml .= '</tr>';
    }
    $resumenHtml = '';
    foreach ($resumenLineas as $linea) {
        $resumenHtml .= '<tr><td colspan="' . $totalCols . '" style="border:1px solid #94a3b8;background:#f1f5f9;font-size:9pt;font-weight:bold;color:#334155;padding:3px 6px">' . $e($linea) . '</td></tr>';
    }
    $emisorNombre = trim((string)($emisorDatos['nombre'] ?? ''));
    $emisorRol = trim((string)($emisorDatos['rol'] ?? ''));
    $emisorDni = trim((string)($emisorDatos['dni'] ?? ''));
    $emisorEstablecimiento = trim((string)($emisorDatos['establecimiento'] ?? ''));
    if ($emisorNombre === '') {
        $emisorNombre = 'Responsable del Reporte';
    }
    $ahora = date('d/m/Y H:i:s');

    echo "\xEF\xBB\xBF";
    echo '<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">'
        . '<head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />'
        . '<meta name="ProgId" content="Excel.Sheet" />'
        . '<style>'
        . 'table{border-collapse:collapse;font-family:Arial,sans-serif}'
        . '.inst{font-size:9pt;font-weight:bold;color:#7f1d1d;text-align:center;line-height:1.35}'
        . '.inst2{font-size:9pt;font-weight:bold;color:#075985;text-align:center;line-height:1.35}'
        . '.titulo{font-size:14pt;font-weight:bold;color:#0f172a;text-align:center;background:#f8fafc}'
        . '.sub{font-size:9pt;font-weight:bold;color:#075985;text-align:center}'
        . '.th{border:1px solid #64748b;background:#0082C8;color:#ffffff;font-weight:bold;font-size:9pt;padding:5px 6px;text-align:center}'
        . '</style></head><body>'
        . '<table><tr>'
        . '<td width="240" align="center" valign="middle">' . ($logoDiresa !== '' ? '<img src="' . $logoDiresa . '" width="220" height="75" alt="DIRESA Lima" />' : '') . '</td>'
        . '<td align="center" valign="middle"><div class="titulo">' . $e($titulo) . '</div><div class="sub">' . $e($subtitulo) . '</div></td>'
        . '<td width="110" align="center" valign="middle">' . ($logoHospital !== '' ? '<img src="' . $logoHospital . '" width="80" height="85" alt="Hospital San Juan Bautista Huaral" />' : '') . '</td>'
        . '</tr></table>'
        . '<table style="width:100%">' . $metaHtml . '</table><br/>'
        . '<table style="width:100%"><thead><tr>';
    foreach ($headers as $header) {
        echo '<th class="th">' . $e($header) . '</th>';
    }
    echo '</tr></thead><tbody>' . $filasHtml
        . '<tr><td colspan="' . $totalCols . '" style="border:1px solid #94a3b8;background:#fef3c7;color:#78350f;font-weight:bold;text-align:center">Total de registros: ' . count($rows) . '</td></tr>'
        . $resumenHtml
        . '</tbody></table><br/>'
        . '<table style="width:100%;margin-top:30px"><tr><td align="center">'
        . '<table style="width:320px;border-collapse:collapse">'
        . '<tr><td style="border-top:1.5px solid #0f172a;padding-top:6px;text-align:center;font-size:9.5pt;font-weight:bold;color:#0f172a">' . $e($emisorNombre) . '</td></tr>'
        . '<tr><td style="text-align:center;font-size:9.5pt;font-weight:bold;color:#075985">' . $e($emisorRol) . ' · DNI ' . $e($emisorDni) . '</td></tr>'
        . '<tr><td style="text-align:center;font-size:8.5pt;color:#475569">' . $e($emisorEstablecimiento) . '</td></tr>'
        . '<tr><td style="text-align:center;font-size:8pt;color:#64748b">Firma y Sello del Responsable del Reporte</td></tr>'
        . '</table></td></tr></table>'
        . '<table style="width:100%"><tr><td style="font-size:8pt;color:#64748b;text-align:center">Generado el ' . $e($ahora) . '</td></tr></table>'
        . '</body></html>';
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
    alertas_cache_invalidate();
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
            reporte_excel_enriquecido(
                'productividad_campo_' . $sello . '.xls',
                'REPORTE 02 · PRODUCTIVIDAD DIARIA POR OBSTETRA',
                'Salidas a campo, sectores visitados y pacientes captadas por día',
                [
                    'Establecimiento: ' . (string)($datos['establecimiento']['nombre'] ?? $session['estab_nombre']),
                    'Periodo: ' . (string)($datos['filtros']['fecha_desde'] ?? '') . ' al ' . (string)($datos['filtros']['fecha_hasta'] ?? ''),
                    'Obstetra: ' . (string)($datos['obstetra_nombre'] ?? 'TODAS LAS OBSTETRAS'),
                    'Emisor: ' . HospitalHuaralDB::nombrePersona((string)$session['dni'], $pdo) . ' · DNI ' . (string)$session['dni'] . ' · ' . (string)$session['platform'],
                    'Generado: ' . date('d/m/Y H:i:s'),
                ],
                [
                    'Fecha de salida', 'DNI Obstetra', 'Nombre Obstetra', 'Sectores visitados',
                    'Pacientes registradas', 'Primera hora de registro', 'Última hora de registro',
                ],
                $rows,
                [1],
                ['Total de salidas registradas: ' . count($rows)],
                reporte_emisor_datos($session, $pdo, (string)($datos['establecimiento']['nombre'] ?? $session['estab_nombre']))
            );
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
        reporte_excel_enriquecido(
            'pacientes_campo_' . $sello . '.xls',
            'REPORTE 01 · CAPTACIÓN DE CAMPO / BARRIDO',
            'Captación domiciliaria y barrido de Planificación Familiar',
            [
                'Establecimiento: ' . (string)($datos['establecimiento']['nombre'] ?? $session['estab_nombre']),
                'Periodo: ' . (string)($datos['filtros']['fecha_desde'] ?? '') . ' al ' . (string)($datos['filtros']['fecha_hasta'] ?? ''),
                'Obstetra: ' . (string)($datos['obstetra_nombre'] ?? 'TODAS LAS OBSTETRAS'),
                'Filtros: ' . json_encode($datos['filtros'] ?? [], JSON_UNESCAPED_UNICODE),
                'Emisor: ' . HospitalHuaralDB::nombrePersona((string)$session['dni'], $pdo) . ' · DNI ' . (string)$session['dni'] . ' · ' . (string)$session['platform'],
                'Generado: ' . date('d/m/Y H:i:s'),
            ],
            [
                'Fecha y hora de registro', 'Sector', 'DNI Paciente', 'Apellido Paterno', 'Apellido Materno',
                'Nombres', 'Edad', 'Celular', 'Dirección', 'Distrito', 'Estado de la Paciente',
                'Validación 99208', 'Último Método', 'Próxima Cita', 'DNI Obstetra',
                'Obstetra que registró', 'Código Establecimiento', 'Establecimiento',
            ],
            $rows,
            [2, 14, 16],
            [
                'Total de pacientes registradas: ' . (int)($datos['resumen']['total_pacientes'] ?? count($rows)),
                'Satisfechas con método: ' . (int)($datos['resumen']['satisfechas'] ?? 0),
                'Insatisfechas sin método: ' . (int)($datos['resumen']['insatisfechas'] ?? 0),
                'Con consejería 99208: ' . (int)($datos['resumen']['con_99208'] ?? 0),
                'Pendientes / seguimiento: ' . (int)($datos['resumen']['pendientes'] ?? 0),
            ],
            reporte_emisor_datos($session, $pdo, (string)($datos['establecimiento']['nombre'] ?? $session['estab_nombre']))
        );
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
    reporte_excel_enriquecido(
        'reporte_por_metodo_' . date('Ymd_His') . '.xls',
        'REPORTE 03 · INDICADORES POR MÉTODO ANTICONCEPTIVO',
        'Programación y estado de la última atención de Planificación Familiar',
        [
            'Establecimiento: ' . (string)($datos['establecimiento']['nombre'] ?? $session['estab_nombre']),
            'Periodo: ' . (string)($datos['filtros']['fecha_desde'] ?? '') . ' al ' . (string)($datos['filtros']['fecha_hasta'] ?? ''),
            'Filtros: ' . json_encode($datos['filtros'] ?? [], JSON_UNESCAPED_UNICODE),
            'Emisor: ' . HospitalHuaralDB::nombrePersona((string)$session['dni'], $pdo) . ' · DNI ' . (string)$session['dni'] . ' · ' . (string)$session['platform'],
            'Generado: ' . date('d/m/Y H:i:s'),
        ],
        [
            'DNI Paciente', 'Paciente', 'Edad', 'Celular', 'Sector', 'Código Método',
            'Método', 'Días de ciclo', 'Fecha última atención', 'Fecha programada siguiente atención',
            'Estado del indicador', 'DNI Obstetra', 'Obstetra', 'Código Establecimiento', 'Establecimiento',
        ],
        $rows,
        [0, 11, 13],
        [
            'Total de pacientes: ' . (int)($datos['resumen']['total'] ?? count($rows)),
            'Vigentes: ' . (int)($datos['resumen']['vigente'] ?? 0),
            'Próximas: ' . (int)($datos['resumen']['proxima'] ?? 0),
            'Vencidas: ' . (int)($datos['resumen']['vencida'] ?? 0),
            'Sin método: ' . (int)($datos['resumen']['sin_metodo'] ?? 0),
        ],
        reporte_emisor_datos($session, $pdo, (string)($datos['establecimiento']['nombre'] ?? $session['estab_nombre']))
    );
}


if ($action === 'save_paciente') {
    $session = require_session();
    $paseUps = !empty($body['pase_ups']);

    $tipoDocInput = (string)($body['tipo_doc'] ?? $body['tipo_documento'] ?? 'DNI');
    $validacionDocumentoPaciente = validar_documento_paciente((string)($body['dni'] ?? $body['documento'] ?? ''), $tipoDocInput);
    if (!$validacionDocumentoPaciente['ok']) {
        json_error($validacionDocumentoPaciente['error'], 400, [
            'code' => 'DOCUMENTO_INVALIDO',
            'tipo_doc' => $validacionDocumentoPaciente['tipo'],
        ]);
    }
    $dni = $validacionDocumentoPaciente['documento'];
    $tipoDoc = $validacionDocumentoPaciente['tipo'];
    $apPaterno = strtoupper(HospitalHuaralDB::sanitizeText($body['apellido_paterno'] ?? '', 50));
    $apMaterno = strtoupper(HospitalHuaralDB::sanitizeText($body['apellido_materno'] ?? '', 50));
    $nombres = strtoupper(HospitalHuaralDB::sanitizeText($body['nombres'] ?? '', 80));
    $edad = (int)($body['edad'] ?? 0);
    $celular = HospitalHuaralDB::sanitizeText($body['celular'] ?? '', 15);
    $correo = strtolower(HospitalHuaralDB::sanitizeText($body['correo'] ?? '', 150));
    $distrito = strtoupper(HospitalHuaralDB::sanitizeText($body['distrito'] ?? '', 80));
    $direccion = HospitalHuaralDB::sanitizeText($body['direccion'] ?? '', 200);
    $sector = strtoupper(HospitalHuaralDB::sanitizeText($body['sector'] ?? '', 50));
    // El estado SOLO cambia si la obstetra lo envía explícitamente. Un guardado
    // normal (pase UPS, edición de celular/dirección) nunca debe sobrescribir
    // el estado clínico ya registrado.
    $estadoExplicito = array_key_exists('estado_paciente', $body)
        && trim((string)($body['estado_paciente'] ?? '')) !== '';
    $estadoSolicitado = $estadoExplicito
        ? strtoupper(HospitalHuaralDB::sanitizeText((string)$body['estado_paciente'], 30))
        : '';
    $estadoDefault = $paseUps ? 'CAPTADA_CON_METODO' : 'INSATISFECHA_SIN_METODO';
    $estadosValidos = ['INSATISFECHA_SIN_METODO', 'CAPTADA_CON_METODO', 'SEGUIMIENTO_DOMICILIARIO', 'CONSEJERIA_REALIZADA', 'RECHAZA_METODO'];
    if ($estadoExplicito && !in_array($estadoSolicitado, $estadosValidos, true)) {
        json_error('El estado clínico enviado no es válido.', 400, ['code' => 'ESTADO_INVALIDO']);
    }
    $estadoInsert = $estadoExplicito ? $estadoSolicitado : null;
    $estadoUpdate = $estadoExplicito ? $estadoSolicitado : $estadoDefault;
    $estadoPresente = $estadoExplicito ? 1 : 0;
    // La captación SIEMPRE se registra en una IPRESS real. Si un administrador
    // está viendo la red completa ("ALL"), se usa la IPRESS asignada a su
    // cuenta; nunca se escribe "ALL" en pacientes_sin_metodo.
    $codEstab = establecimiento_registro_sesion($session);
    $atencion99208Solicitada = !empty($body['atencion_99208']) ? 1 : 0;

    if (strlen($dni) < 6 || strlen($dni) > 15) {
        json_error('El número de documento de la paciente no tiene una longitud válida (6 a 15 caracteres).', 400);
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
            $sector = $sector ?: preg_replace('/[^0-9]/', '', (string)$existente['sector']) ?? '';
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
            $sector = $sector ?: '0';
        }
    }

    if ($distrito === '') {
        $distrito = 'HUARAL';
    }
    if ($paseUps && trim($sector) === '') {
        // El pase directo puede no traer sector; se usa 0 (sin sector) para
        // mantener la regla estricta de solo dígitos.
        $sector = '0';
    }

    // Sector estrictamente numérico (se permiten ceros a la izquierda: 01, 1, 2).
    $sector = trim($sector);
    if ($sector === '' || !preg_match('/^[0-9]+$/', $sector)) {
        json_error('El campo Sector solo permite números (ejemplo: 01, 1, 2). No se permiten letras ni símbolos.', 422, [
            'code' => 'SECTOR_NO_NUMERICO',
        ]);
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
            (dni, tipo_doc, apellido_paterno, apellido_materno, nombres, edad, celular, correo, distrito, direccion, sector, estado_paciente, codpsal_obstetra, cod_estab, atencion_99208)
        VALUES
            (:dni, :tipo_doc, :ap_p, :ap_m, :nom, :edad, :cel, :cor, :dist, :dir, :sec,
             COALESCE(:est_insert, :est_default), :obst, :estab, :a99208)
        ON DUPLICATE KEY UPDATE
            tipo_doc = VALUES(tipo_doc),
            apellido_paterno = VALUES(apellido_paterno),
            apellido_materno = VALUES(apellido_materno),
            nombres = VALUES(nombres),
            edad = VALUES(edad),
            celular = VALUES(celular),
            correo = VALUES(correo),
            distrito = VALUES(distrito),
            direccion = VALUES(direccion),
            sector = VALUES(sector),
            estado_paciente = IF(:est_presente = 1, :est_update, estado_paciente),
            codpsal_obstetra = VALUES(codpsal_obstetra),
            cod_estab = VALUES(cod_estab),
            atencion_99208 = GREATEST(atencion_99208, VALUES(atencion_99208))
    ");
    $stmt->execute([
        ':dni' => $dni,
        ':tipo_doc' => $tipoDoc,
        ':ap_p' => $apPaterno,
        ':ap_m' => $apMaterno,
        ':nom' => $nombres,
        ':edad' => $edad,
        ':cel' => HospitalHuaralDB::encryptPII($celular),
        ':cor' => HospitalHuaralDB::encryptPII($correo),
        ':dist' => $distrito,
        ':dir' => HospitalHuaralDB::encryptPII($direccion),
        ':sec' => $sector,
        ':est_insert' => $estadoInsert,
        ':est_default' => $estadoDefault,
        ':est_presente' => $estadoPresente,
        ':est_update' => $estadoUpdate,
        ':obst' => $session['dni'],
        ':estab' => $codEstab,
        ':a99208' => $atencion99208,
    ]);

    alertas_cache_invalidate();
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
    $stmtRegistro = $pdo->prepare('SELECT id, dni, cod_estab, codpsal_obstetra, estado_paciente FROM pacientes_sin_metodo WHERE id = :id LIMIT 1');
    $stmtRegistro->execute([':id' => $id]);
    $registroEstado = $stmtRegistro->fetch() ?: null;
    if (!$registroEstado) {
        json_error('No se encontró el registro solicitado.', 404);
    }

    if (!is_admin_session($session)) {
        $codigosEstabUsuario = codigos_establecimiento_sesion($session);
        $codEstabRegistro = trim((string)($registroEstado['cod_estab'] ?? ''));
        $mismoEstablecimiento = $codEstabRegistro !== '' && (
            in_array($codEstabRegistro, $codigosEstabUsuario, true)
            || hospital_codigo_canonico($codEstabRegistro) === hospital_codigo_canonico((string)$session['cod_estab'])
        );
        $esObstetraRegistradora = trim((string)($registroEstado['codpsal_obstetra'] ?? '')) === trim((string)$session['dni']);
        if (!$mismoEstablecimiento && !$esObstetraRegistradora) {
            HospitalHuaralDB::registrarAuditoria(
                (string)$session['dni'],
                'PACIENTE_STATUS_DENEGADO',
                'Intento de cambiar estado del registro #' . $id . ' (DNI ' . (string)$registroEstado['dni'] . ') fuera de su establecimiento o captación.',
                (string)$session['cod_estab'],
                (string)$session['platform']
            );
            json_error('No tiene permiso para modificar este registro: pertenece a otro establecimiento y no fue captado por usted.', 403, ['code' => 'ESTABLECIMIENTO_NO_AUTORIZADO']);
        }
    }

    // Edición de datos de contacto (celular / dirección / sector) desde el
    // listado de pacientes. Son opcionales: si no llegan, no se tocan.
    $sets = ['estado_paciente = :estado'];
    $params = [':estado' => $estado, ':id' => $id];
    $cambiosContacto = [];
    if (array_key_exists('celular', $body)) {
        $sets[] = 'celular = :celular';
        $params[':celular'] = HospitalHuaralDB::encryptPII(HospitalHuaralDB::sanitizeText($body['celular'] ?? '', 15));
        $cambiosContacto[] = 'celular';
    }
    if (array_key_exists('direccion', $body)) {
        $sets[] = 'direccion = :direccion';
        $params[':direccion'] = HospitalHuaralDB::encryptPII(HospitalHuaralDB::sanitizeText($body['direccion'] ?? '', 200));
        $cambiosContacto[] = 'dirección';
    }
    if (array_key_exists('sector', $body)) {
        $sectorUpdate = trim((string)($body['sector'] ?? ''));
        if ($sectorUpdate === '' || !preg_match('/^[0-9]+$/', $sectorUpdate)) {
            json_error('El campo Sector solo permite números (ejemplo: 01, 1, 2). No se permiten letras ni símbolos.', 422, [
                'code' => 'SECTOR_NO_NUMERICO',
            ]);
        }
        $sets[] = 'sector = :sector';
        $params[':sector'] = $sectorUpdate;
        $cambiosContacto[] = 'sector';
    }
    $stmt = $pdo->prepare('UPDATE pacientes_sin_metodo SET ' . implode(', ', $sets) . ' WHERE id = :id LIMIT 1');
    $stmt->execute($params);
    if ($stmt->rowCount() === 0 && (string)$registroEstado['estado_paciente'] !== $estado && !$cambiosContacto) {
        json_error('No se pudo actualizar el estado del registro.', 409);
    }
    alertas_cache_invalidate();
    HospitalHuaralDB::registrarAuditoria(
        (string)$session['dni'],
        'PACIENTE_STATUS_CHANGE',
        'Cambio de estado del registro #' . $id . ' (DNI ' . (string)$registroEstado['dni'] . ') de ' . (string)$registroEstado['estado_paciente'] . ' a ' . $estado . ' en ' . hospital_nombre_establecimiento((string)($registroEstado['cod_estab'] ?? '')) . '.'
            . ($cambiosContacto ? ' Datos de contacto actualizados: ' . implode(', ', $cambiosContacto) . '.' : ''),
        (string)$session['cod_estab'],
        (string)$session['platform']
    );
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
    $codEstabEquipo = '';
    if (is_admin_session($session)) {
        $solicitadoEquipo = hospital_codigo_canonico((string)($_GET['cod_estab'] ?? ''));
        if (hospital_establecimiento($solicitadoEquipo) !== null) {
            $codEstabEquipo = $solicitadoEquipo;
        }
    } elseif (strtoupper(trim((string)($session['cod_estab'] ?? ''))) !== 'ALL') {
        $canonicoEquipo = hospital_codigo_canonico((string)$session['cod_estab']);
        if (hospital_establecimiento($canonicoEquipo) !== null) {
            $codEstabEquipo = $canonicoEquipo;
        }
    }
    if ($codEstabEquipo === '') {
        // Nunca consultar con cod_estab = 'ALL': se usa la IPRESS asignada a la
        // cuenta cuando el administrador está en alcance de red completa.
        $codEstabEquipo = establecimiento_registro_sesion($session);
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
