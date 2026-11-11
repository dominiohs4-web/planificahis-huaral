<?php
/**
 * db.php — Núcleo de datos y seguridad clínica
 * Hospital San Juan Bautista Huaral / Red de Salud Huaral-Chancay
 * Motor: MariaDB 10.4.x (XAMPP / Navicat / Nube)
 *
 * REGLAS DE ORO:
 *  - NO altera ni elimina columnas de las tablas originales del hospital.
 *  - Solo crea/actualiza tablas propias de la app (`pacientes_sin_metodo`,
 *    `auditoria_seguridad_app` y tablas de seguridad `app_*`).
 *  - PDO con sentencias preparadas NATIVAS (EMULATE_PREPARES = false).
 *  - AES-256-GCM para celular, correo y dirección domiciliaria.
 *  - Tokens HMAC-SHA256, TOTP RFC 6238, rate limiting y cadena de auditoría SHA-256.
 */
declare(strict_types=1);

/**
 * DNI de la Cuenta Maestra del Sistema. Es inmutable por diseño: ni siquiera
 * el propio titular puede desactivarla ni rebajar su rol.
 */
if (!defined('SUPER_ADMIN_DNI')) {
    define('SUPER_ADMIN_DNI', '75100725');
}

require_once __DIR__ . '/catalogo_establecimientos.php';

/**
 * Catálogo oficial de los 14 métodos de Planificación Familiar del HIS/MINSA.
 *
 * Cada método conserva su código oficial (con punto) y las variantes que el
 * HIS histórico guarda en `his_dl_dt.DX` (sin punto, con .00 o con ceros).
 * Las variantes se usan SIEMPRE dentro de `dt.DX IN (...)`, nunca con funciones
 * sobre la columna, para conservar el índice B-Tree de la tabla de 5 GB.
 *
 * @return array<string, array<string, mixed>>
 */
function hospital_catalogo_metodos_oficial(): array
{
    return [
        '99208.02' => [
            'codigo_dx' => '99208.02', 'nombre_metodo' => 'Preservativo o condón masculino',
            'dias_ciclo' => 90, 'requiere_cita' => 1, 'activo' => 1, 'orden' => 1,
            'alias' => ['9920802', '99208.2'],
        ],
        '99208.06' => [
            'codigo_dx' => '99208.06', 'nombre_metodo' => 'Preservativo o condón femenino',
            'dias_ciclo' => 90, 'requiere_cita' => 1, 'activo' => 1, 'orden' => 2,
            'alias' => ['9920806', '99208.6'],
        ],
        '99208.13' => [
            'codigo_dx' => '99208.13', 'nombre_metodo' => 'Hormonal combinado oral (Píldora)',
            'dias_ciclo' => 120, 'requiere_cita' => 1, 'activo' => 1, 'orden' => 3,
            'alias' => ['9920813', '99208.03', '9920803'],
        ],
        '99208.04' => [
            'codigo_dx' => '99208.04', 'nombre_metodo' => 'Hormonal combinado inyectable mensual',
            'dias_ciclo' => 30, 'requiere_cita' => 1, 'activo' => 1, 'orden' => 4,
            'alias' => ['9920804', '99208.4'],
        ],
        '99208.05' => [
            'codigo_dx' => '99208.05', 'nombre_metodo' => 'Hormonal de solo progestágenos inyectable trimestral',
            'dias_ciclo' => 90, 'requiere_cita' => 1, 'activo' => 1, 'orden' => 5,
            'alias' => ['9920805', '99208.5'],
        ],
        '11975.00' => [
            'codigo_dx' => '11975.00', 'nombre_metodo' => 'Implante subdérmico',
            'dias_ciclo' => 90, 'requiere_cita' => 1, 'activo' => 1, 'orden' => 6,
            'alias' => ['11975', '1197500', '11981', '11981.00', '11982', '11983'],
        ],
        '58300.00' => [
            'codigo_dx' => '58300.00', 'nombre_metodo' => 'DIU (T de cobre)',
            'dias_ciclo' => 30, 'requiere_cita' => 1, 'activo' => 1, 'orden' => 7,
            'alias' => ['58300', '5830000'],
        ],
        '58300.01' => [
            'codigo_dx' => '58300.01', 'nombre_metodo' => 'DIU LNG (Liberador de Levonorgestrel)',
            'dias_ciclo' => 30, 'requiere_cita' => 1, 'activo' => 1, 'orden' => 8,
            'alias' => ['5830001', '58300.1'],
        ],
        '58600.00' => [
            'codigo_dx' => '58600.00', 'nombre_metodo' => 'Bloqueo Tubárico Bilateral (BTB)',
            'dias_ciclo' => 365, 'requiere_cita' => 1, 'activo' => 1, 'orden' => 9,
            'alias' => ['58600', '5860000', '58605', '58611', '58615'],
        ],
        '55250.00' => [
            'codigo_dx' => '55250.00', 'nombre_metodo' => 'Vasectomía',
            'dias_ciclo' => 365, 'requiere_cita' => 1, 'activo' => 1, 'orden' => 10,
            'alias' => ['55250', '5525000'],
        ],
        '99208.07' => [
            'codigo_dx' => '99208.07', 'nombre_metodo' => 'Método de lactancia materna exclusiva y amenorrea (MELA)',
            'dias_ciclo' => 180, 'requiere_cita' => 1, 'activo' => 1, 'orden' => 11,
            'alias' => ['9920807', '99208.7'],
        ],
        '99208.09' => [
            'codigo_dx' => '99208.09', 'nombre_metodo' => 'Billings o del moco cervical',
            'dias_ciclo' => 60, 'requiere_cita' => 1, 'activo' => 1, 'orden' => 12,
            'alias' => ['9920809', '99208.9'],
        ],
        '99208.08' => [
            'codigo_dx' => '99208.08', 'nombre_metodo' => 'Ritmo o de la Regla',
            'dias_ciclo' => 60, 'requiere_cita' => 1, 'activo' => 1, 'orden' => 13,
            'alias' => ['9920808', '99208.8'],
        ],
        '99208.10' => [
            'codigo_dx' => '99208.10', 'nombre_metodo' => 'Método de los días fijos o método del collar',
            'dias_ciclo' => 60, 'requiere_cita' => 1, 'activo' => 1, 'orden' => 14,
            'alias' => ['9920810'],
        ],
    ];
}

/**
 * DNIs con acceso pre-activado. Se reconocen aunque todavía no existan en
 * `his_mstrpers` ni en la tabla `usuario`.
 *
 * @return array<string, array{rol: string, nombre: string}>
 */
function hospital_dnis_preactivados(): array
{
    return [
        '75100725' => [
            'rol' => 'SUPER_ADMIN',
            'nombre' => 'LUIS FERNANDO INOÑAN SANTISTEBAN',
        ],
        '43246820' => [
            'rol' => 'JEFA_OBSTETRAS',
            'nombre' => 'DIANA ALEJANDRINA ANICETO AGUEDO',
        ],
    ];
}

/** ¿El documento corresponde a la Cuenta Maestra del Sistema? */
function hospital_es_super_admin(?string $dni): bool
{
    return preg_replace('/[^0-9A-Za-z]/', '', (string)$dni) === SUPER_ADMIN_DNI;
}

/**
 * Jerarquía oficial de roles. Un número mayor implica más privilegios.
 */
function hospital_nivel_rol(?string $rol): int
{
    return match (strtoupper(trim((string)$rol))) {
        'SUPER_ADMIN' => 100,
        'ADMIN_ESTADISTICA' => 50,
        'JEFA_OBSTETRAS' => 30,
        'OBSTETRA' => 10,
        default => 0,
    };
}

/** ¿El rol es administrador superior (SUPER_ADMIN o ADMIN_ESTADISTICA)? */
function hospital_es_rol_admin_superior(?string $rol): bool
{
    return hospital_nivel_rol($rol) >= hospital_nivel_rol('ADMIN_ESTADISTICA');
}

/**
 * Helper único de administración superior: SUPER_ADMIN, cualquier
 * ADMIN_ESTADISTICA, la Cuenta Maestra 75100725 o cualquier usuario marcado
 * explícitamente con `puede_ver_red = 1`.
 *
 * @param array<string, mixed>|string|null $usuario
 */
function esAdminSuperior($usuario): bool
{
    if (is_array($usuario)) {
        $rol = strtoupper(trim((string)($usuario['rol'] ?? '')));
        $dni = trim((string)($usuario['dni'] ?? $usuario['CODPSAL'] ?? ''));
        $puedeVerRed = !empty($usuario['puede_ver_red']) || !empty($usuario['puedeVerRed']);
        return ($dni !== '' && hospital_es_super_admin($dni))
            || $rol === 'SUPER_ADMIN'
            || $rol === 'ADMIN_ESTADISTICA'
            || $puedeVerRed;
    }
    $rol = strtoupper(trim((string)$usuario));
    return $rol === 'SUPER_ADMIN' || $rol === 'ADMIN_ESTADISTICA';
}

/**
 * Normaliza un código de establecimiento para filtros clínicos.
 *
 * REGLA CRÍTICA: los centinelas "ALL", "TODOS", "RED", vacío y null SIEMPRE
 * significan red completa y NUNCA deben convertirse en "000000ALL" ni en un
 * código de 9 dígitos. Un código real se devuelve canónico con 9 dígitos.
 */
function normalizarCodEstab(?string $codEstab): string
{
    $raw = strtoupper(trim((string)$codEstab));
    if ($raw === '' || $raw === 'ALL' || $raw === 'TODOS' || $raw === 'RED') {
        return 'ALL';
    }

    $canonico = hospital_codigo_canonico($raw);
    if (hospital_establecimiento($canonico) !== null) {
        return str_pad(trim($canonico), 9, '0', STR_PAD_LEFT);
    }

    $digitos = preg_replace('/[^0-9]/', '', $raw) ?? '';
    if ($digitos !== '') {
        return str_pad($digitos, 9, '0', STR_PAD_LEFT);
    }

    return $raw;
}

/**
 * Columnas reales de una tabla del HIS (mapa MAYÚSCULAS => nombre original).
 *
 * @return array<string, string>
 */
function hospital_columnas_tabla(PDO $pdo, string $tabla): array
{
    static $cache = [];
    if (!preg_match('/^[A-Za-z0-9_]+$/', $tabla)) {
        return [];
    }
    if (array_key_exists($tabla, $cache)) {
        return $cache[$tabla];
    }
    $columnas = [];
    try {
        $filas = $pdo->query("SHOW COLUMNS FROM `{$tabla}`")->fetchAll(PDO::FETCH_ASSOC);
        foreach ($filas as $fila) {
            $original = (string)($fila['Field'] ?? '');
            if ($original !== '') {
                $columnas[strtoupper($original)] = $original;
            }
        }
    } catch (Throwable $e) {
        $columnas = [];
    }
    $cache[$tabla] = $columnas;
    return $columnas;
}

/**
 * Resuelve TODOS los códigos equivalentes de un establecimiento cruzando las
 * tablas históricas de la Red (app_catalogo_establecimientos, establec,
 * maestro_sys_establecimiento, maestro_sys_establec) por código y por nombre.
 *
 * Incluye las variantes de formato usadas por el HIS: 9 dígitos, 8 dígitos,
 * sin ceros a la izquierda y código corto. Para "ALL" devuelve [] (sin filtro).
 *
 * @return array<int, string>
 */
function obtenerCodigosEstablecimientoEquivalentes(PDO $pdo, string $codEstab): array
{
    static $cache = [];
    $codEstab = trim($codEstab);
    $normalizado = normalizarCodEstab($codEstab);
    if ($normalizado === 'ALL') {
        return [];
    }

    $cacheKey = $normalizado . '|' . spl_object_id($pdo);
    if (array_key_exists($cacheKey, $cache)) {
        return $cache[$cacheKey];
    }

    /** @var array<string, string> $resultado */
    $resultado = [];
    /** @var array<string, string> $nombres */
    $nombres = [];

    $agregar = static function ($valor) use (&$resultado): void {
        $valor = trim((string)$valor);
        if ($valor === '' || strtoupper($valor) === 'ALL' || strtoupper($valor) === 'TODOS') {
            return;
        }
        $resultado[$valor] = $valor;
        if (preg_match('/^[0-9]+$/', $valor)) {
            $digitos = ltrim($valor, '0');
            if ($digitos === '') {
                $digitos = '0';
            }
            foreach ([
                str_pad($digitos, 9, '0', STR_PAD_LEFT),
                str_pad($digitos, 8, '0', STR_PAD_LEFT),
                $digitos,
            ] as $variante) {
                if ($variante !== '') {
                    $resultado[$variante] = $variante;
                }
            }
        }
    };

    $agregarNombre = static function ($valor) use (&$nombres): void {
        $valor = trim((string)$valor);
        if ($valor !== '') {
            $nombres[strtoupper($valor)] = $valor;
        }
    };

    $est = hospital_establecimiento($normalizado) ?: hospital_establecimiento($codEstab);
    $agregar($codEstab);
    $agregar($normalizado);
    if ($est !== null) {
        $agregar($est['COD_ESTAB'] ?? '');
        $agregar($est['COD_IPRESS'] ?? '');
        $agregar($est['COD_IPRESS_ALT'] ?? '');
        $agregarNombre($est['DESC_ESTAB'] ?? '');
    }

    // El catálogo local resuelve el código canónico y el IPRESS real. Las
    // tablas históricas se consultan debajo solo por código exacto y nombre
    // validado, para no mezclar establecimientos vecinos del mismo distrito.
    if ($est !== null) {
        $agregar($est['COD_ESTAB'] ?? '');
        $agregar($est['COD_IPRESS'] ?? '');
        $agregar($est['COD_IPRESS_ALT'] ?? '');
        $agregarNombre($est['DESC_ESTAB'] ?? '');
    }

    // Variantes legibles del nombre oficial para el cruce por nombre. NO se
    // parte el nombre en fragmentos genéricos ("SAN JUAN BAUTISTA"), porque
    // eso mezclaría establecimientos de otras regiones con el mismo nombre.
    $nombreOficial = trim((string)($est['DESC_ESTAB'] ?? ''));
    if ($nombreOficial !== '') {
        $sinPrefijo = preg_replace(
            '/^(HOSPITAL DE APOYO|HOSPITAL|CENTRO DE SALUD|C\.S\.|PUESTO DE SALUD|P\.S\.)\s+/i',
            '',
            $nombreOficial
        );
        if (is_string($sinPrefijo) && trim($sinPrefijo) !== '') {
            $agregarNombre($sinPrefijo);
        }
    }
    $nombreOficialMayus = strtoupper($nombreOficial);
    $distritoOficial = strtoupper(trim((string)($est['DISTRITO'] ?? '')));

    $tablas = [
        [
            'app_catalogo_establecimientos',
            ['COD_ESTAB', 'COD_IPRESS', 'IPRESS_CORTO'],
            ['NOMBRE_ESTABLECIMIENTO', 'NOMBRE', 'DESC_ESTAB'],
            ['COD_ESTAB', 'COD_IPRESS', 'IPRESS_CORTO'],
        ],
        [
            'maestro_sys_establecimiento',
            ['COD_ESTABLECIMIENTO', 'CODIGO_UNICO', 'ID_ESTABLECIMIENTO'],
            ['NOMBRE_ESTABLECIMIENTO', 'NOMBRE', 'DESC_ESTAB', 'DESCRIPCION'],
            ['COD_ESTABLECIMIENTO'],
        ],
        [
            'maestro_sys_establec',
            ['COD_ESTAB', 'COD_2000', 'ID_ESTAB'],
            ['DESC_ESTAB', 'NOMBRE_ESTABLECIMIENTO', 'NOMBRE', 'DESCRIPCION'],
            ['COD_ESTAB', 'COD_2000'],
        ],
        [
            'establec',
            ['COD_ESTAB', 'COD_2000', 'UGIPRESS'],
            ['DESC_ESTAB', 'NOMBRE_ESTABLECIMIENTO', 'NOMBRE', 'DESCRIPCION'],
            ['COD_ESTAB', 'COD_2000', 'UGIPRESS'],
        ],
    ];

    foreach ($tablas as [$tabla, $columnasCodigo, $columnasNombre, $columnasSalida]) {
        $columnasReales = hospital_columnas_tabla($pdo, $tabla);
        if (!$columnasReales) {
            continue;
        }

        $candidatos = array_values($resultado);
        $nombresBuscar = array_values($nombres);
        $condiciones = [];
        $params = [];

        foreach ($columnasCodigo as $columna) {
            if (!isset($columnasReales[$columna]) || !$candidatos) {
                continue;
            }
            $real = $columnasReales[$columna];
            $condiciones[] = '`' . $real . '` IN (' . implode(',', array_fill(0, count($candidatos), '?')) . ')';
            $params = array_merge($params, $candidatos);
        }
        foreach ($columnasNombre as $columna) {
            if (!isset($columnasReales[$columna]) || !$nombresBuscar) {
                continue;
            }
            $real = $columnasReales[$columna];
            $marcasNombre = implode(',', array_fill(0, count($nombresBuscar), '?'));
            $condiciones[] = 'UPPER(TRIM(`' . $real . '`)) IN (' . $marcasNombre . ')';
            foreach ($nombresBuscar as $nombreBuscar) {
                $params[] = strtoupper($nombreBuscar);
            }
        }

        if (!$condiciones) {
            continue;
        }

        try {
            $sql = 'SELECT * FROM `' . $tabla . '` WHERE (' . implode(' OR ', $condiciones) . ') LIMIT 300';
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            foreach ($stmt->fetchAll() as $fila) {
                // Código y geo de la fila histórica para validar que realmente
                // corresponde al mismo establecimiento y no a una colisión de
                // código con otra región (p. ej. Ucayali vs. Huaral).
                $nombreFila = '';
                foreach ($columnasNombre as $columnaNombre) {
                    if (!isset($columnasReales[$columnaNombre])) {
                        continue;
                    }
                    $nombreFila = strtoupper(trim((string)($fila[$columnasReales[$columnaNombre]] ?? '')));
                    if ($nombreFila !== '') {
                        break;
                    }
                }

                $mismoNombre = $nombreFila !== '' && (
                    isset($nombres[$nombreFila])
                    || ($nombreOficialMayus !== '' && (
                        strpos($nombreFila, $nombreOficialMayus) !== false
                        || strpos($nombreOficialMayus, $nombreFila) !== false
                    ))
                    || ($distritoOficial !== '' && preg_match(
                        '/(^|[^A-Z])' . preg_quote($distritoOficial, '/') . '([^A-Z]|$)/',
                        $nombreFila
                    ) === 1)
                );
                // Sin nombre oficial no hay con qué validar: se acepta la fila
                // localizada por código exacto.
                $filaSinNombre = $nombreFila === '' || $est === null;
                if (!$mismoNombre && !$filaSinNombre) {
                    continue;
                }

                foreach (array_merge($columnasSalida, $columnasNombre) as $columna) {
                    if (!isset($columnasReales[$columna])) {
                        continue;
                    }
                    $valor = $fila[$columnasReales[$columna]] ?? null;
                    if ($valor === null || is_array($valor) || is_object($valor)) {
                        continue;
                    }
                    if (in_array($columna, $columnasNombre, true)) {
                        $agregarNombre($valor);
                    } else {
                        $agregar($valor);
                    }
                }
            }
        } catch (Throwable $e) {
            // Tabla/columna histórica no disponible: se conservan las variantes.
        }
    }

    $cache[$cacheKey] = array_values(array_unique(array_filter(
        $resultado,
        static fn ($valor): bool => trim((string)$valor) !== ''
    )));
    return $cache[$cacheKey];
}

final class HospitalHuaralDB
{
    /** Sesión persistente de 7 días exactos (60 * 60 * 24 * 7). */
    public const SESSION_TTL = 604800;
    public const SESSION_COOKIE = 'planificahis_session';

    private static ?PDO $pdo = null;
    private static bool $connectionVerified = false;
    /** @var array<string, array<string, mixed>|null> */
    private static array $accesosCache = [];

    private static function isProductionEnvironment(): bool
    {
        static $production = null;
        if ($production === null) {
            $appEnv = strtolower(trim((string)getenv('APP_ENV')));
            $render = strtolower(trim((string)getenv('RENDER')));
            $production = $appEnv === 'production'
                || in_array($render, ['1', 'true', 'yes'], true);
        }
        return $production;
    }

    /**
     * Resuelve un secreto clínico SIN romper la disponibilidad del aplicativo.
     *
     * Orden de búsqueda:
     *   1. Variable propia ($name): HUARAL_AES_SECRET / HUARAL_SESSION_SECRET.
     *   2. Variable legacy ($legacyName): ENCRYPTION_SECRET.
     *   3. Derivación determinística SHA-256 de 64 caracteres (nunca una
     *      excepción fatal). Así un contenedor de Render sin secretos
     *      configurados jamás devuelve "API Error 500" en el login.
     *
     * La derivación usa el nombre del secreto, el host de base de datos y el
     * usuario; es estable entre reinicios y despliegues de la misma instancia.
     */
    private static function configuredSecret(string $name, string $legacyName, string $developmentDefault): string
    {
        $value = getenv($name);
        if (!is_string($value) || trim($value) === '') {
            $value = getenv($legacyName);
        }
        $value = is_string($value) ? trim($value) : '';
        if ($value === '') {
            if (self::isProductionEnvironment()) {
                $derived = hash(
                    'sha256',
                    'planificahis-huaral-prod-' . $name . '-' .
                    (getenv('DB_HOST') ?: 'local') . '-' .
                    (getenv('DB_USER') ?: 'app')
                );
                error_log(
                    '[PlanificaHIS] ADVERTENCIA: ' . $name . ' / ' . $legacyName .
                    ' no están definidas. Se usa una clave determinística derivada. ' .
                    'Configure los secretos en Render > Environment para un despliegue óptimo.'
                );
                return $derived;
            }
            return $developmentDefault;
        }
        if (self::isProductionEnvironment() && strlen($value) < 32) {
            // No se lanza excepción: se fortalece el material débil con SHA-256
            // (64 caracteres) para no tumbar el login de las obstetras.
            error_log(
                '[PlanificaHIS] ADVERTENCIA: ' . $name . ' tiene menos de 32 caracteres. ' .
                'Se deriva una clave SHA-256 de 64 caracteres.'
            );
            return hash('sha256', $name . '|' . $value);
        }
        return $value;
    }

    /** Clave maestra para el cifrado AES-256-GCM (HUARAL_AES_SECRET / ENCRYPTION_SECRET). */
    public static function masterSecret(): string
    {
        return self::configuredSecret(
            'HUARAL_AES_SECRET',
            'ENCRYPTION_SECRET',
            'hospital-san-juan-bautista-huaral-aes256-key-2026'
        );
    }

    public static function sessionSecret(): string
    {
        return self::configuredSecret(
            'HUARAL_SESSION_SECRET',
            'ENCRYPTION_SECRET',
            'hospital-san-juan-bautista-huaral-aes256-key-2026'
        );
    }

    /** AES-256 key idéntica a la de Node: SHA-256(raw) de la clave maestra. */
    private static function aesKey(): string
    {
        return hash('sha256', self::masterSecret(), true);
    }

    public static function getConnection(): PDO
    {
        if (self::$pdo instanceof PDO && self::$connectionVerified) {
            return self::$pdo;
        }
        if (self::$pdo instanceof PDO) {
            try {
                self::$pdo->query('SELECT 1')->fetchColumn();
                self::$connectionVerified = true;
                return self::$pdo;
            } catch (Throwable $e) {
                // El servidor remoto puede cerrar sockets inactivos: se
                // descarta la conexión muerta y se abre una nueva en el mismo
                // request.
                error_log('[PlanificaHIS] Conexión MySQL reciclada: ' . $e->getMessage());
                self::$pdo = null;
                self::$connectionVerified = false;
            }
        }

        // Infraestructura dedicada en DigitalOcean (MySQL 8.0).
        $host = '206.189.225.149';
        $port = '3306';
        $dbname = 'app';
        $user = 'admin_planifica';
        $pass = '75100725L@uis';

        $dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset=utf8mb4";
        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            // BLOQUEO REAL DE SQLi: el driver no interpola parámetros.
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_STRINGIFY_FETCHES => false,
            // Conexión persistente para reducir el handshake TCP/TLS entre
            // Render y el Droplet. getConnection() valida el socket con
            // SELECT 1 y lo recicla si el servidor cerró la conexión.
            PDO::ATTR_PERSISTENT => true,
            // Corta la conexión a los 5 s para evitar que la API se quede
            // colgada ante un micro-corte del Droplet.
            PDO::ATTR_TIMEOUT => 5,
            // Charset y collation binaria: consistencia con las tablas.
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_bin",
        ];

        // El Droplet puede exponer MySQL con TLS. Se activa con DB_SSL=1; si
        // existe DB_SSL_CA legible se usa como CA explícita.
        if (getenv('DB_SSL') === '1') {
            if (defined('PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT')) {
                $options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = false;
            }
            if (
                defined('PDO::MYSQL_ATTR_SSL_CA')
                && getenv('DB_SSL_CA')
                && is_readable((string)getenv('DB_SSL_CA'))
            ) {
                $options[PDO::MYSQL_ATTR_SSL_CA] = (string)getenv('DB_SSL_CA');
            }
        }

        $conectar = static function () use ($dsn, $user, $pass, $options): PDO {
            return new PDO($dsn, $user, $pass, $options);
        };

        try {
            self::$pdo = $conectar();
            // Verificación activa: si el socket estaba en el pool pero ya no
            // responde, se reconecta de inmediato.
            self::$pdo->query('SELECT 1')->fetchColumn();
        } catch (Throwable $e) {
            error_log('[PlanificaHIS] Reintentando conexión MySQL: ' . $e->getMessage());
            self::$pdo = $conectar();
            self::$pdo->query('SELECT 1')->fetchColumn();
        }
        self::$connectionVerified = true;

        // Contra un servidor remoto, cada ALTER ... ADD COLUMN IF NOT EXISTS
        // repetido en cada request HTTP añade latencia. El esquema se crea una sola vez
        // (semáforo en /tmp) salvo que DB_AUTO_MIGRATE=1.
        $autoMigrate = getenv('DB_AUTO_MIGRATE') === '1';
        $schemaLock = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR)
            . DIRECTORY_SEPARATOR . 'planificahis_schema_v8_'
            . substr(hash('sha256', $host . '|' . $dbname), 0, 12) . '.lock';
        if ($autoMigrate || !is_file($schemaLock)) {
            try {
                self::bootstrapSchema(self::$pdo);
                if (!$autoMigrate) {
                    @file_put_contents($schemaLock, date('c'), LOCK_EX);
                }
            } catch (Throwable $e) {
                error_log('[PlanificaHIS] bootstrapSchema failure: ' . $e->getMessage());
                if ($autoMigrate) {
                    throw $e;
                }
            }
        }
        return self::$pdo;
    }

    private static function bootstrapSchema(PDO $pdo): void
    {
        // Tabla de captación (propia de la app, NO del HIS original).
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS `pacientes_sin_metodo` (
              `id` int NOT NULL AUTO_INCREMENT,
              `dni` varchar(15) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
              `apellido_paterno` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
              `apellido_materno` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
              `nombres` varchar(80) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
              `edad` int NOT NULL,
              `celular` varchar(512) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
              `correo` varchar(512) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
              `distrito` varchar(80) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
              `direccion` varchar(512) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
              `sector` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
              `tipo_doc` varchar(15) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL DEFAULT 'DNI' COMMENT 'DNI, CE, PASAPORTE, PTP, CNV',
              `estado_paciente` varchar(30) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT 'INSATISFECHA_SIN_METODO',
              `codpsal_obstetra` varchar(11) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT 'DNI de la obstetra que capta',
              `cod_estab` varchar(9) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
              `atencion_99208` tinyint(1) NOT NULL DEFAULT 0,
              `fecha_registro` timestamp NOT NULL DEFAULT current_timestamp(),
              PRIMARY KEY (`id`) USING BTREE,
              UNIQUE INDEX `uk_dni_paciente`(`dni` ASC) USING BTREE,
              INDEX `idx_obstetra`(`codpsal_obstetra` ASC) USING BTREE,
              INDEX `idx_estab`(`cod_estab` ASC) USING BTREE
            ) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;
        ");

        // Catálogo propio de métodos anticonceptivos y ciclos clínicos.
        // Permite calcular la fecha del próximo método sin tocar las tablas del HIS.
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS `app_catalogo_metodos` (
              `codigo_dx` varchar(15) NOT NULL,
              `nombre_metodo` varchar(120) NOT NULL,
              `alias_codigos` varchar(255) NOT NULL DEFAULT '',
              `dias_ciclo` int NOT NULL DEFAULT 30,
              `requiere_cita` tinyint(1) DEFAULT 1,
              `activo` tinyint(1) DEFAULT 1,
              `orden` int NOT NULL DEFAULT 0,
              PRIMARY KEY (`codigo_dx`)
            ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
        ");
        // Compatibilidad con instalaciones anteriores al catálogo oficial.
        foreach ([
            "ALTER TABLE `app_catalogo_metodos` ADD COLUMN IF NOT EXISTS `alias_codigos` varchar(255) NOT NULL DEFAULT '' AFTER `nombre_metodo`",
            "ALTER TABLE `app_catalogo_metodos` ADD COLUMN IF NOT EXISTS `orden` int NOT NULL DEFAULT 0 AFTER `activo`",
        ] as $ddlCatalogo) {
            try {
                $pdo->exec($ddlCatalogo);
            } catch (Throwable $e) {
                // El motor ya tiene la columna o no soporta IF NOT EXISTS.
            }
        }
        // Metadatos internos de la app (versión de catálogo, marcas de migración).
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS `app_config` (
              `clave` varchar(100) NOT NULL,
              `valor` varchar(255) NOT NULL DEFAULT '',
              `actualizado` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
              PRIMARY KEY (`clave`)
            ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
        ");
        self::ensureCatalogoOficial($pdo);

        // Tabla única e independiente de usuarios de la app. Es la ÚNICA fuente
        // de autenticación, roles y recuperación de clave. Nunca se sincroniza
        // al HIS local y jamás escribe en la tabla original `usuario`.
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS `app_usuarios` (
              `id` int NOT NULL AUTO_INCREMENT,
              `dni` varchar(15) NOT NULL,
              `nombres` varchar(120) NOT NULL DEFAULT '',
              `apellido_paterno` varchar(80) NOT NULL DEFAULT '',
              `apellido_materno` varchar(80) NOT NULL DEFAULT '',
              `nombre_completo` varchar(190) NOT NULL DEFAULT '',
              `email` varchar(190) NOT NULL DEFAULT '',
              `celular` varchar(20) NOT NULL DEFAULT '',
              `clave_hash` varchar(255) NOT NULL DEFAULT '',
              `pin_recuperacion` varchar(64) NOT NULL DEFAULT '',
              `rol` varchar(30) NOT NULL DEFAULT 'OBSTETRA',
              `cod_estab` varchar(9) NOT NULL DEFAULT '000005481',
              `puede_ver_red` tinyint(1) NOT NULL DEFAULT 0,
              `protegido` tinyint(1) NOT NULL DEFAULT 0,
              `activo` tinyint(1) NOT NULL DEFAULT 1,
              `creado_por` varchar(40) NOT NULL DEFAULT '',
              `ultimo_login` timestamp NULL DEFAULT NULL,
              `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
              `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
              PRIMARY KEY (`id`),
              UNIQUE KEY `uk_app_usuarios_dni` (`dni`),
              INDEX `idx_app_usuarios_rol` (`rol`),
              INDEX `idx_app_usuarios_estab` (`cod_estab`),
              INDEX `idx_app_usuarios_activo` (`activo`)
            ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
        ");

        // Migración desde la tabla antigua de accesos (si existiera) y limpieza:
        // a partir de esta versión solo existe `app_usuarios`.
        try {
            $stmtLegacy = $pdo->query("
                SELECT COUNT(*) FROM information_schema.TABLES
                WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'app_usuarios_accesos'
            ");
            if ((int)$stmtLegacy->fetchColumn() > 0) {
                // INSERT IGNORE evita el error de columna ambigua que produce
                // `ON DUPLICATE KEY UPDATE nombre_completo = ...` en MariaDB
                // cuando origen y destino comparten nombres de columna. Los
                // usuarios ya existentes en app_usuarios nunca se sobreescriben.
                $pdo->exec("
                    INSERT IGNORE INTO `app_usuarios`
                        (`dni`, `nombre_completo`, `rol`, `cod_estab`, `activo`,
                         `pin_recuperacion`, `celular`, `email`, `puede_ver_red`, `creado_por`)
                    SELECT `dni`, `nombre_completo`, `rol`, `cod_estab`, `activo`,
                           LEFT(`pin_hash`, 64), `celular`, `email`,
                           IF(`rol` = 'ADMIN_ESTADISTICA', 1, 0), 'MIGRACION'
                    FROM `app_usuarios_accesos`
                ");
            }
            $pdo->exec('DROP TABLE IF EXISTS `app_usuarios_accesos`');
        } catch (Throwable $e) {
            error_log('[PlanificaHIS] migracion app_usuarios: ' . $e->getMessage());
        }

        try {
            $stmtUsuario = $pdo->prepare("
                INSERT INTO `app_usuarios`
                    (`dni`, `nombre_completo`, `rol`, `cod_estab`, `activo`, `puede_ver_red`, `creado_por`)
                VALUES (:dni, :nombre, :rol, :estab, 1, :red, 'BOOTSTRAP')
                ON DUPLICATE KEY UPDATE
                    nombre_completo = IF(nombre_completo = '', VALUES(nombre_completo), nombre_completo)
            ");
            foreach (hospital_dnis_preactivados() as $dniPre => $metaPre) {
                $stmtUsuario->execute([
                    ':dni' => $dniPre,
                    ':nombre' => $metaPre['nombre'],
                    ':rol' => $metaPre['rol'],
                    ':estab' => '000005481',
                    ':red' => hospital_es_rol_admin_superior($metaPre['rol']) ? 1 : 0,
                ]);
            }
            // La Cuenta Maestra es inmutable: siempre SUPER_ADMIN, activa y
            // marcada como protegida, incluso si una migración previa la alteró.
            $pdo->prepare("
                UPDATE `app_usuarios`
                SET `rol` = 'SUPER_ADMIN', `protegido` = 1, `activo` = 1, `puede_ver_red` = 1
                WHERE `dni` = :dni
            ")->execute([':dni' => SUPER_ADMIN_DNI]);
        } catch (Throwable $e) {
            // Si la tabla no admite el upsert se conserva el acceso por DNI.
        }

        // Tabla de auditoría con cadena inmutable SHA-256.
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS `auditoria_seguridad_app` (
              `id` bigint NOT NULL AUTO_INCREMENT,
              `fecha_hora` timestamp NOT NULL DEFAULT current_timestamp(),
              `actor_dni` varchar(15) NOT NULL,
              `actor_estab` varchar(9) NOT NULL DEFAULT '',
              `accion` varchar(60) NOT NULL,
              `detalle` varchar(255) NOT NULL,
              `ip` varchar(45) NOT NULL,
              `plataforma` varchar(30) NOT NULL DEFAULT 'Web Desktop',
              `prev_hash` char(64) NOT NULL DEFAULT '',
              `hash_sha256` char(64) NOT NULL,
              PRIMARY KEY (`id`),
              INDEX `idx_actor`(`actor_dni`),
              INDEX `idx_accion`(`accion`),
              INDEX `idx_fecha`(`fecha_hora`)
            ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
        ");

        // Compatibilidad con instalaciones previas (MariaDB 10.4 soporta IF NOT EXISTS).
        // Los MODIFY garantizan que el texto cifrado AES-256-GCM nunca se trunque:
        // enc:gcm:<24 hex IV>:<32 hex tag>:<ciphertext hex> exige VARCHAR(512).
        foreach ([
            "ALTER TABLE `pacientes_sin_metodo` ADD COLUMN IF NOT EXISTS `tipo_doc` varchar(15) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL DEFAULT 'DNI' AFTER `dni`",
            "ALTER TABLE `pacientes_sin_metodo` ADD COLUMN IF NOT EXISTS `cod_estab` varchar(9) NULL DEFAULT NULL AFTER `codpsal_obstetra`",
            "ALTER TABLE `pacientes_sin_metodo` ADD COLUMN IF NOT EXISTS `atencion_99208` tinyint(1) NOT NULL DEFAULT 0 AFTER `cod_estab`",
            "ALTER TABLE `auditoria_seguridad_app` ADD COLUMN IF NOT EXISTS `actor_estab` varchar(9) NOT NULL DEFAULT '' AFTER `actor_dni`",
            "ALTER TABLE `auditoria_seguridad_app` ADD COLUMN IF NOT EXISTS `plataforma` varchar(30) NOT NULL DEFAULT 'Web Desktop' AFTER `ip`",
            "ALTER TABLE `auditoria_seguridad_app` ADD COLUMN IF NOT EXISTS `prev_hash` char(64) NOT NULL DEFAULT '' AFTER `plataforma`",
            "ALTER TABLE `app_usuarios` ADD COLUMN IF NOT EXISTS `protegido` tinyint(1) NOT NULL DEFAULT 0 AFTER `puede_ver_red`",
            "ALTER TABLE `pacientes_sin_metodo` MODIFY COLUMN `celular` varchar(512) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL",
            "ALTER TABLE `pacientes_sin_metodo` MODIFY COLUMN `correo` varchar(512) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL",
            "ALTER TABLE `pacientes_sin_metodo` MODIFY COLUMN `direccion` varchar(512) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL",
            "ALTER TABLE `auditoria_seguridad_app` MODIFY COLUMN `id` bigint NOT NULL AUTO_INCREMENT",
        ] as $ddl) {
            try {
                $pdo->exec($ddl);
            } catch (Throwable $e) {
                // Si el motor no soporta IF NOT EXISTS se ignora: la tabla base ya existe.
            }
        }

        // Índices de los reportes web (tabla propia de la app). Se intentan una
        // sola vez; si ya existen, el motor devuelve error y se ignora.
        foreach ([
            'idx_reporte_fecha_estab' => "CREATE INDEX `idx_reporte_fecha_estab` ON `pacientes_sin_metodo` (`fecha_registro`, `cod_estab`)",
            'idx_reporte_estado_fecha' => "CREATE INDEX `idx_reporte_estado_fecha` ON `pacientes_sin_metodo` (`estado_paciente`, `fecha_registro`)",
            'idx_reporte_sector' => "CREATE INDEX `idx_reporte_sector` ON `pacientes_sin_metodo` (`sector`)",
            // Índices compuestos SARGables de los reportes clínicos. En una
            // instalación nueva se crean aquí; en la base histórica de 5 GB
            // conviene aplicarlos con optimizar_indices_5gb.sql en ventana de mantenimiento.
            'idx_his_dl_ano_mes_dia' => "CREATE INDEX `idx_his_dl_ano_mes_dia` ON `his_dl` (`ANO`, `MES`, `DIA`)",
            'idx_his_dl_estab_ano_mes_dia' => "CREATE INDEX `idx_his_dl_estab_ano_mes_dia` ON `his_dl` (`COD_ESTAB`, `ANO`, `MES`, `DIA`)",
            'idx_his_dl_codpsal_ano_mes_dia' => "CREATE INDEX `idx_his_dl_codpsal_ano_mes_dia` ON `his_dl` (`CODPSAL`, `ANO`, `MES`, `DIA`)",
            'idx_his_dl_dni_ano_mes_dia' => "CREATE INDEX `idx_his_dl_dni_ano_mes_dia` ON `his_dl` (`DNI`, `ANO`, `MES`, `DIA`)",
            'idx_his_dl_dt_dx_id' => "CREATE INDEX `idx_his_dl_dt_dx_id` ON `his_dl_dt` (`DX`, `ID`)",
            'idx_his_dl_dt_id_dx' => "CREATE INDEX `idx_his_dl_dt_id_dx` ON `his_dl_dt` (`ID`, `DX`)",
            'idx_his_dl_id_dni_fecha' => "CREATE INDEX `idx_his_dl_id_dni_fecha` ON `his_dl` (`ID`, `DNI`, `ANO`, `MES`, `DIA`)",
        ] as $ddlIndice) {
            try {
                $pdo->exec($ddlIndice);
            } catch (Throwable $e) {
                // El índice ya existe o el motor no permite crearlo en línea.
            }
        }

        // Tablas propias de seguridad (nunca se sincronizan al HIS local).
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS `app_obstetra_establecimiento` (
              `dni` varchar(11) NOT NULL,
              `cod_estab` varchar(9) NOT NULL,
              `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
              PRIMARY KEY (`dni`),
              INDEX `idx_cod_estab`(`cod_estab`)
            ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
        ");
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS `app_totp_secretos` (
              `dni` varchar(11) NOT NULL,
              `secret_base32` varchar(64) NOT NULL,
              `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
              PRIMARY KEY (`dni`)
            ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
        ");
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS `app_2fa_challenges` (
              `challenge_id` char(64) NOT NULL,
              `dni` varchar(11) NOT NULL,
              `cod_estab` varchar(9) NOT NULL,
              `plataforma` varchar(30) NOT NULL DEFAULT 'Web Desktop',
              `expires_at` bigint NOT NULL,
              `used` tinyint(1) NOT NULL DEFAULT 0,
              `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
              PRIMARY KEY (`challenge_id`),
              INDEX `idx_expira`(`expires_at`)
            ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
        ");
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS `app_sesiones` (
              `token_hash` char(64) NOT NULL,
              `dni` varchar(11) NOT NULL,
              `cod_estab` varchar(9) NOT NULL,
              `plataforma` varchar(30) NOT NULL DEFAULT 'Web Desktop',
              `created_at` bigint NOT NULL,
              `last_activity` bigint NOT NULL,
              `expires_at` bigint NOT NULL,
              `revoked` tinyint(1) NOT NULL DEFAULT 0,
              PRIMARY KEY (`token_hash`),
              INDEX `idx_dni`(`dni`),
              INDEX `idx_expira`(`expires_at`)
            ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
        ");
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS `app_rate_limits` (
              `bucket` varchar(190) NOT NULL,
              `hits` int NOT NULL DEFAULT 0,
              `reset_at` bigint NOT NULL,
              PRIMARY KEY (`bucket`),
              INDEX `idx_reset`(`reset_at`)
            ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
        ");
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS `app_sync_runs` (
              `id` bigint NOT NULL AUTO_INCREMENT,
              `actor_dni` varchar(15) NOT NULL,
              `modo` varchar(20) NOT NULL,
              `tablas` varchar(255) NOT NULL,
              `filas` int NOT NULL DEFAULT 0,
              `fecha_hora` timestamp NOT NULL DEFAULT current_timestamp(),
              PRIMARY KEY (`id`)
            ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
        ");
    }

    // ========================================================================
    // CATÁLOGO OFICIAL DE 14 MÉTODOS Y RBAC POR DNI
    // ========================================================================
    /**
     * Siembra/actualiza los 14 métodos oficiales una sola vez por versión de
     * catálogo. Al subir CATALOGO_VERSION se reescriben códigos, nombres,
     * alias y ciclos oficiales (necesario para corregir datos ya sembrados en
     * producción); después se respetan las ediciones manuales de Estadística
     * hasta la siguiente versión.
     */
    public static function ensureCatalogoOficial(PDO $pdo): void
    {
        static $verificado = false;
        if ($verificado) {
            return;
        }
        $verificado = true;
        $catalogoVersion = 'oficial_2026_11_v7';
        try {
            try {
                $pdo->exec("
                    CREATE TABLE IF NOT EXISTS `app_config` (
                      `clave` varchar(100) NOT NULL,
                      `valor` varchar(255) NOT NULL DEFAULT '',
                      `actualizado` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
                      PRIMARY KEY (`clave`)
                    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4
                ");
            } catch (Throwable $e) {
                // La tabla pudo crearse en bootstrapSchema.
            }
            $stmtVersion = $pdo->prepare("SELECT valor FROM app_config WHERE clave = 'catalogo_metodos_version' LIMIT 1");
            $stmtVersion->execute();
            if ((string)$stmtVersion->fetchColumn() === $catalogoVersion) {
                return;
            }

            $oficial = hospital_catalogo_metodos_oficial();
            $upsert = $pdo->prepare("
                INSERT INTO app_catalogo_metodos
                    (codigo_dx, nombre_metodo, alias_codigos, dias_ciclo, requiere_cita, activo, orden)
                VALUES
                    (:codigo, :nombre, :alias, :dias, :cita, :activo, :orden)
                ON DUPLICATE KEY UPDATE
                    nombre_metodo = VALUES(nombre_metodo),
                    alias_codigos = VALUES(alias_codigos),
                    dias_ciclo = VALUES(dias_ciclo),
                    requiere_cita = VALUES(requiere_cita),
                    activo = VALUES(activo),
                    orden = VALUES(orden)
            ");
            foreach ($oficial as $meta) {
                $upsert->execute([
                    ':codigo' => (string)$meta['codigo_dx'],
                    ':nombre' => (string)$meta['nombre_metodo'],
                    ':alias' => implode(',', (array)($meta['alias'] ?? [])),
                    ':dias' => (int)$meta['dias_ciclo'],
                    ':cita' => (int)$meta['requiere_cita'],
                    ':activo' => (int)$meta['activo'],
                    ':orden' => (int)$meta['orden'],
                ]);
            }
            $stmtMarca = $pdo->prepare("
                INSERT INTO app_config (clave, valor) VALUES ('catalogo_metodos_version', :version)
                ON DUPLICATE KEY UPDATE valor = VALUES(valor)
            ");
            $stmtMarca->execute([':version' => $catalogoVersion]);
        } catch (Throwable $e) {
            error_log('[PlanificaHIS] ensureCatalogoOficial: ' . $e->getMessage());
        }
    }

    /** @return array<string, mixed>|null */
    public static function dniPreactivado(string $dni): ?array
    {
        $dni = preg_replace('/[^0-9A-Za-z]/', '', $dni) ?? '';
        $mapa = hospital_dnis_preactivados();
        return $mapa[$dni] ?? null;
    }

    /** @return array<string, mixed>|null */
    public static function accesoUsuario(string $dni): ?array
    {
        $dni = preg_replace('/[^0-9A-Za-z]/', '', $dni) ?? '';
        if ($dni === '') {
            return null;
        }
        if (array_key_exists($dni, self::$accesosCache)) {
            return self::$accesosCache[$dni];
        }
        try {
            $stmt = self::getConnection()->prepare('SELECT * FROM app_usuarios WHERE dni = :dni LIMIT 1');
            $stmt->execute([':dni' => $dni]);
            $row = $stmt->fetch();
            self::$accesosCache[$dni] = $row ?: null;
        } catch (Throwable $e) {
            self::$accesosCache[$dni] = null;
        }
        return self::$accesosCache[$dni];
    }

    public static function olvidarAcceso(string $dni): void
    {
        $dni = preg_replace('/[^0-9A-Za-z]/', '', $dni) ?? '';
        if ($dni !== '') {
            unset(self::$accesosCache[$dni]);
        }
    }

    /**
     * Rol efectivo. El DNI de la Cuenta Maestra SIEMPRE es SUPER_ADMIN y la
     * tabla no puede rebajarlo; en el resto, la tabla manda y si no hay fila
     * se reconocen los accesos pre-activados.
     */
    public static function rolUsuario(string $dni): string
    {
        if (hospital_es_super_admin($dni)) {
            return 'SUPER_ADMIN';
        }
        $acceso = self::accesoUsuario($dni);
        if ($acceso !== null) {
            $rol = strtoupper(trim((string)($acceso['rol'] ?? '')));
            return $rol !== '' ? $rol : 'OBSTETRA';
        }
        $pre = self::dniPreactivado($dni);
        return $pre !== null ? (string)$pre['rol'] : 'OBSTETRA';
    }

    public static function accesoActivo(string $dni): bool
    {
        if (hospital_es_super_admin($dni)) {
            return true;
        }
        $acceso = self::accesoUsuario($dni);
        if ($acceso === null) {
            // Una sesión histórica sin fila no se bloquea aquí; el login y la
            // recuperación exigen una fila real en app_usuarios.
            return true;
        }
        return (int)($acceso['activo'] ?? 1) === 1;
    }

    /**
     * Solo los administradores superiores (SUPER_ADMIN / ADMIN_ESTADISTICA)
     * tienen alcance de red. La Jefatura de Obstetras queda estrictamente
     * limitada a su establecimiento.
     */
    public static function esRolRed(string $rol): bool
    {
        return hospital_es_rol_admin_superior($rol);
    }

    public static function puedeGestionarAccesos(string $rol): bool
    {
        return hospital_es_rol_admin_superior($rol);
    }

    public static function puedeResetearObstetra(string $rol): bool
    {
        return in_array(
            strtoupper(trim($rol)),
            ['SUPER_ADMIN', 'ADMIN_ESTADISTICA', 'JEFA_OBSTETRAS'],
            true
        );
    }

    public static function rolEtiqueta(string $rol): string
    {
        return match (strtoupper(trim($rol))) {
            'SUPER_ADMIN' => 'Super Administrador del Sistema',
            'ADMIN_ESTADISTICA' => 'Administrador de Estadística',
            'JEFA_OBSTETRAS' => 'Jefa de Obstetras',
            default => 'Obstetra',
        };
    }

    /** Nombre institucional con prioridad app_usuarios → HIS (`mstrpers`). */
    public static function nombrePersona(string $dni, ?PDO $pdo = null): string
    {
        $dni = preg_replace('/[^0-9A-Za-z]/', '', $dni) ?? '';
        if ($dni === '') {
            return '';
        }
        $acceso = self::accesoUsuario($dni);
        if ($acceso !== null) {
            $nombreCompleto = trim((string)($acceso['nombre_completo'] ?? ''));
            if ($nombreCompleto !== '') {
                return $nombreCompleto;
            }
            $partes = trim(
                (string)($acceso['apellido_paterno'] ?? '') . ' ' .
                (string)($acceso['apellido_materno'] ?? '') . ' ' .
                (string)($acceso['nombres'] ?? '')
            );
            if ($partes !== '') {
                return $partes;
            }
        }
        $pre = self::dniPreactivado($dni);
        if ($pre !== null) {
            return (string)$pre['nombre'];
        }
        try {
            $pdo = $pdo ?: self::getConnection();
            foreach (['mstrpers', 'his_mstrpers'] as $tabla) {
                try {
                    $stmt = $pdo->prepare("SELECT NOMBRE FROM {$tabla} WHERE CODPSAL = :dni LIMIT 1");
                    $stmt->execute([':dni' => $dni]);
                    $nombre = trim((string)($stmt->fetchColumn() ?: ''));
                    if ($nombre !== '') {
                        return $nombre;
                    }
                } catch (Throwable $e) {
                    // La tabla puede no existir en una instalación mínima.
                }
            }
        } catch (Throwable $e) {
            // Sin nombre se devuelve vacío para que el llamador use su fallback.
        }
        return '';
    }

    // ========================================================================
    // CIFRADO AUTENTICADO AES-256-GCM (IV 96 bits + AuthTag 128 bits)
    // Formato: enc:gcm:<iv_hex>:<tag_hex>:<ciphertext_hex>
    // ========================================================================
    public static function encryptPII(?string $plaintext): string
    {
        $plaintext = (string)$plaintext;
        if ($plaintext === '') {
            return '';
        }
        if (str_starts_with($plaintext, 'enc:gcm:')) {
            return $plaintext;
        }
        $iv = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            self::aesKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            16
        );
        if ($ciphertext === false) {
            throw new RuntimeException('No se pudo cifrar el dato clínico.');
        }
        return 'enc:gcm:' . bin2hex($iv) . ':' . bin2hex($tag) . ':' . bin2hex($ciphertext);
    }

    public static function decryptPII(?string $stored): string
    {
        $stored = (string)$stored;
        if ($stored === '' || !str_starts_with($stored, 'enc:gcm:')) {
            return $stored;
        }
        $parts = explode(':', $stored);
        if (count($parts) !== 5) {
            return '[FORMATO_CIFRADO_INVALIDO]';
        }
        $iv = hex2bin($parts[2]);
        $tag = hex2bin($parts[3]);
        $ciphertext = hex2bin($parts[4]);
        if ($iv === false || $tag === false || $ciphertext === false) {
            return '[DATO_PROTEGIDO]';
        }
        $decrypted = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            self::aesKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        return $decrypted !== false ? $decrypted : '[DATO_PROTEGIDO_TAG_INVALIDO]';
    }

    /** Alias de compatibilidad con código anterior. */
    public static function decryptField(?string $stored): string
    {
        return self::decryptPII($stored);
    }

    // ========================================================================
    // TOTP RFC 6238 (HMAC-SHA1, 6 dígitos, ventana de 30 s)
    // ========================================================================
    private static function base32Decode(string $base32): string
    {
        $map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $base32 = strtoupper(preg_replace('/[^A-Z2-7]/i', '', $base32) ?? '');
        $bits = '';
        foreach (str_split($base32) as $char) {
            $pos = strpos($map, $char);
            if ($pos === false) {
                continue;
            }
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
        $binary = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $binary .= chr((int)bindec($byte));
            }
        }
        return $binary;
    }

    public static function base32Encode(string $binary): string
    {
        $map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = '';
        foreach (str_split($binary) as $char) {
            $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $out .= $map[(int)bindec($chunk)];
        }
        return $out;
    }

    public static function generateTOTP(string $secretBase32, int $windowOffset = 0): array
    {
        $step = 30;
        $now = time();
        $counter = intdiv($now, $step) + $windowOffset;
        $remaining = $step - ($now % $step);
        $key = self::base32Decode($secretBase32);
        if ($key === '') {
            // Compatibilidad con secretos antiguos no Base32 (solo demo).
            $key = $secretBase32;
        }
        $counterBytes = pack('N2', 0, $counter);
        $hmac = hash_hmac('sha1', $counterBytes, $key, true);
        $offset = ord($hmac[strlen($hmac) - 1]) & 0x0f;
        $binary = ((ord($hmac[$offset]) & 0x7f) << 24)
            | ((ord($hmac[$offset + 1]) & 0xff) << 16)
            | ((ord($hmac[$offset + 2]) & 0xff) << 8)
            | (ord($hmac[$offset + 3]) & 0xff);
        $code = str_pad((string)($binary % 1000000), 6, '0', STR_PAD_LEFT);
        return ['code' => $code, 'remainingSeconds' => $remaining];
    }

    public static function verifyTOTP(string $secretBase32, string $inputCode): bool
    {
        $code = trim($inputCode);
        if (!preg_match('/^\d{6}$/', $code)) {
            return false;
        }
        foreach ([-1, 0, 1] as $offset) {
            if (hash_equals(self::generateTOTP($secretBase32, $offset)['code'], $code)) {
                return true;
            }
        }
        return false;
    }

    public static function obtenerSecretoTotp(string $dni): string
    {
        $pdo = self::getConnection();
        $stmt = $pdo->prepare('SELECT secret_base32 FROM app_totp_secretos WHERE dni = :dni LIMIT 1');
        $stmt->execute([':dni' => $dni]);
        $secret = $stmt->fetchColumn();
        if (is_string($secret) && $secret !== '') {
            return $secret;
        }
        // Secreto aleatorio de 160 bits codificado en Base32 (RFC 4226/6238).
        $secret = self::base32Encode(random_bytes(20));
        $stmt = $pdo->prepare('INSERT INTO app_totp_secretos (dni, secret_base32) VALUES (:dni, :secret)');
        $stmt->execute([':dni' => $dni, ':secret' => $secret]);
        return $secret;
    }

    // ========================================================================
    // SESIONES OPACAS 64 HEX + HASH SHA-256 + TOKEN POR PETICIÓN
    // ========================================================================
    /**
     * Normaliza el establecimiento de una sesión: "ALL" para el alcance de red
     * del administrador o el código IPRESS canónico de 9 dígitos.
     */
    public static function normalizarEstablecimientoSesion(?string $codEstab): string
    {
        $codEstab = trim((string)$codEstab);
        if ($codEstab === '') {
            return '000005481';
        }
        $normalizado = normalizarCodEstab($codEstab);
        if ($normalizado === 'ALL') {
            return 'ALL';
        }
        // Si el código no pertenece al catálogo, se conserva tal cual (con sus
        // variantes numéricas normalizadas) para no romper instalaciones que
        // usan códigos históricos de 4 u 8 dígitos.
        return $normalizado;
    }

    /**
     * Emite un token opaco de 64 caracteres hexadecimales. En la base solo se
     * persiste su hash SHA-256: una filtración de app_sesiones no permite
     * reutilizar tokens válidos.
     */
    public static function createSessionToken(string $dni, string $codEstab, string $platform, int $ttlSeconds = self::SESSION_TTL): string
    {
        $now = time();
        $ttlSeconds = $ttlSeconds > 0 ? $ttlSeconds : self::SESSION_TTL;
        $token = bin2hex(random_bytes(32));
        $codEstab = self::normalizarEstablecimientoSesion($codEstab);

        $pdo = self::getConnection();
        $stmt = $pdo->prepare("
            INSERT INTO app_sesiones (token_hash, dni, cod_estab, plataforma, created_at, last_activity, expires_at)
            VALUES (:hash, :dni, :estab, :platform, :created, :last_activity, :expires)
        ");
        $stmt->execute([
            ':hash' => hash('sha256', $token),
            ':dni' => $dni,
            ':estab' => $codEstab,
            ':platform' => $platform,
            ':created' => $now,
            ':last_activity' => $now,
            ':expires' => $now + $ttlSeconds,
        ]);
        self::sendSessionCookie($token, $ttlSeconds);
        return $token;
    }

    /**
     * Cookie persistente HttpOnly de 7 días. El navegador la reenvía incluso
     * después de cerrar la PWA; el token también viaja como Bearer.
     */
    public static function sendSessionCookie(string $token, int $ttlSeconds = self::SESSION_TTL): void
    {
        if (headers_sent()) {
            return;
        }
        $https = self::requestIsHttps();
        setcookie(self::SESSION_COOKIE, $token, [
            'expires' => time() + max(60, $ttlSeconds),
            'path' => '/',
            'secure' => $https,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    public static function clearSessionCookie(): void
    {
        if (headers_sent()) {
            return;
        }
        setcookie(self::SESSION_COOKIE, '', [
            'expires' => time() - 3600,
            'path' => '/',
            'secure' => self::requestIsHttps(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    public static function requestIsHttps(): bool
    {
        $forwarded = strtolower(trim((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')));
        return $forwarded === 'https'
            || (isset($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off');
    }

    /**
     * Extrae el token SOLO de los canales explícitos permitidos:
     * Authorization: Bearer, X-App-Token o el parámetro `token` (necesario
     * para descargas Excel que no pueden enviar cabeceras personalizadas).
     * Nunca usa cookies ni app_config.
     */
    public static function tokenFromRequest(): string
    {
        $candidatos = [];

        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        if (!is_string($auth) || trim($auth) === '') {
            $headers = function_exists('apache_request_headers')
                ? apache_request_headers()
                : (function_exists('getallheaders') ? getallheaders() : []);
            foreach ($headers as $name => $value) {
                if (strcasecmp((string)$name, 'Authorization') === 0) {
                    $auth = (string)$value;
                    break;
                }
            }
        }
        if (is_string($auth) && preg_match('/^Bearer\s+([a-f0-9]{64})$/i', trim($auth), $m)) {
            $candidatos[] = strtolower($m[1]);
        }

        $appToken = $_SERVER['HTTP_X_APP_TOKEN'] ?? '';
        if (!is_string($appToken) || trim($appToken) === '') {
            $headers = $headers ?? (function_exists('apache_request_headers')
                ? apache_request_headers()
                : (function_exists('getallheaders') ? getallheaders() : []));
            foreach ($headers as $name => $value) {
                if (strcasecmp((string)$name, 'X-App-Token') === 0) {
                    $appToken = (string)$value;
                    break;
                }
            }
        }
        if (is_string($appToken) && preg_match('/^[a-f0-9]{64}$/i', trim($appToken))) {
            $candidatos[] = strtolower(trim($appToken));
        }

        $queryToken = $_GET['token'] ?? '';
        if (is_string($queryToken) && preg_match('/^[a-f0-9]{64}$/i', trim($queryToken))) {
            $candidatos[] = strtolower(trim($queryToken));
        }

        return $candidatos[0] ?? '';
    }

    /**
     * Valida el token por petición con el JOIN exacto app_sesiones → app_usuarios.
     * NUNCA devuelve una sesión demo cuando falta el token.
     *
     * Regla de establecimiento:
     *  - OBSTETRA / JEFA_OBSTETRAS: siempre u.cod_estab (ignora parámetros).
     *  - ADMIN_ESTADISTICA / SUPER_ADMIN: "ALL" o el establecimiento elegido
     *    en su sesión; si no hay uno válido, u.cod_estab.
     *
     * @return array<string, mixed>|null
     */
    public static function authenticateSession(?string $requiredPlatform = null): ?array
    {
        $token = self::tokenFromRequest();
        if ($token === '') {
            return null;
        }
        $now = time();
        $pdo = self::getConnection();
        $hash = hash('sha256', $token);
        $stmt = $pdo->prepare("
            SELECT s.token_hash, s.dni, s.cod_estab, s.plataforma, s.expires_at,
                   s.last_activity, s.revoked,
                   u.cod_estab AS usuario_cod_estab, u.rol, u.activo,
                   u.protegido, u.puede_ver_red
            FROM app_sesiones s
            INNER JOIN app_usuarios u ON u.dni = s.dni
            WHERE s.token_hash = :th AND s.revoked = 0
            LIMIT 1
        ");
        $stmt->execute([':th' => $hash]);
        $row = $stmt->fetch();
        if (!$row) {
            return null;
        }
        // Expiración absoluta de 7 días. NO hay revocación por inactividad
        // corta: basta con que la sesión siga vigente y no esté revocada.
        if ((int)$row['expires_at'] < $now) {
            $pdo->prepare('UPDATE app_sesiones SET revoked = 1 WHERE token_hash = :th')
                ->execute([':th' => $hash]);
            self::clearSessionCookie();
            return null;
        }

        $dni = (string)$row['dni'];
        $esSuperAdmin = hospital_es_super_admin($dni);
        if ((int)($row['activo'] ?? 1) !== 1 && !$esSuperAdmin) {
            $pdo->prepare('UPDATE app_sesiones SET revoked = 1 WHERE token_hash = :th')
                ->execute([':th' => $hash]);
            self::clearSessionCookie();
            if (!headers_sent()) {
                http_response_code(401);
            }
            return null;
        }

        $rol = strtoupper(trim((string)($row['rol'] ?? 'OBSTETRA')));
        $puedeVerRedGuardado = (int)($row['puede_ver_red'] ?? 0);
        $esAdmin = esAdminSuperior([
            'rol' => $rol,
            'dni' => $dni,
            'puede_ver_red' => $puedeVerRedGuardado,
        ]);
        if ($esAdmin && $puedeVerRedGuardado !== 1) {
            // La jerarquía administrativa siempre tiene alcance de red, aunque
            // una fila histórica tenga el flag en 0.
            try {
                $pdo->prepare('UPDATE app_usuarios SET puede_ver_red = 1 WHERE dni = :dni LIMIT 1')
                    ->execute([':dni' => $dni]);
                self::olvidarAcceso($dni);
            } catch (Throwable $e) {
                // El flag se fuerza igualmente en la sesión.
            }
            $puedeVerRedGuardado = 1;
        }
        $estabUsuario = self::normalizarEstablecimientoSesion((string)($row['usuario_cod_estab'] ?? '000005481'));
        $estabSesion = normalizarCodEstab((string)($row['cod_estab'] ?? ''));
        if (!$esAdmin) {
            // La obstetra y la jefa NUNCA pueden elegir otro establecimiento.
            $codEstab = $estabUsuario;
        } elseif ($estabSesion === 'ALL') {
            $codEstab = 'ALL';
        } elseif ($estabSesion !== '') {
            $codEstab = self::normalizarEstablecimientoSesion($estabSesion);
            if (hospital_establecimiento($codEstab) === null) {
                $codEstab = $estabUsuario;
            }
        } else {
            $codEstab = $estabUsuario;
        }

        $codEstabGuardado = (string)($row['cod_estab'] ?? '');
        if ($codEstab !== $codEstabGuardado) {
            $pdo->prepare('UPDATE app_sesiones SET cod_estab = :estab WHERE token_hash = :th')
                ->execute([':estab' => $codEstab, ':th' => $hash]);
        }

        // Sliding expiration: se renueva la sesión como máximo una vez cada
        // 300 segundos. Evita un UPDATE remoto en cada GET de la PWA.
        $nuevoExpira = $now + self::SESSION_TTL;
        $ultimaActividad = (int)($row['last_activity'] ?? 0);
        if (($now - $ultimaActividad) > 300) {
            $pdo->prepare('UPDATE app_sesiones SET last_activity = :now, expires_at = :expires WHERE token_hash = :th')
                ->execute([':now' => $now, ':expires' => $nuevoExpira, ':th' => $hash]);
            $ultimaActividad = $now;
        } else {
            $nuevoExpira = max($nuevoExpira, (int)$row['expires_at']);
        }
        self::sendSessionCookie($token, self::SESSION_TTL);

        $platform = $requiredPlatform ?: ((string)($row['plataforma'] ?? '') ?: 'Web Desktop');
        return [
            'token' => $token,
            'dni' => $dni,
            'cod_estab' => $codEstab,
            'estab_nombre' => $codEstab === 'ALL'
                ? 'TODA LA RED HUARAL-CHANCAY'
                : hospital_nombre_establecimiento($codEstab),
            'platform' => $platform,
            'rol' => $rol,
            'activo' => (int)($row['activo'] ?? 1),
            'protegido' => (int)($row['protegido'] ?? 0),
            'puede_ver_red' => $esAdmin ? 1 : $puedeVerRedGuardado,
            'es_admin' => $esAdmin,
            'expires_at' => $nuevoExpira,
            'last_activity' => $ultimaActividad,
        ];
    }

    public static function revokeSession(string $token): void
    {
        $pdo = self::getConnection();
        $pdo->prepare('UPDATE app_sesiones SET revoked = 1 WHERE token_hash = :th')
            ->execute([':th' => hash('sha256', $token)]);
        self::clearSessionCookie();
    }

    /**
     * Cambia SOLO el establecimiento de la sesión actual. "ALL" es válido y
     * representa el alcance de red completa para administradores. La cuenta
     * (app_usuarios.cod_estab) no se modifica.
     */
    public static function cambiarEstablecimientoSesion(string $token, string $codEstab, string $dni): void
    {
        $codEstab = self::normalizarEstablecimientoSesion($codEstab);
        if ($codEstab !== 'ALL' && hospital_establecimiento($codEstab) === null) {
            return;
        }
        $pdo = self::getConnection();
        $pdo->prepare('UPDATE app_sesiones SET cod_estab = :estab WHERE token_hash = :th')
            ->execute([':estab' => $codEstab, ':th' => hash('sha256', $token)]);
    }

    public static function establecerEstablecimientoObstetra(string $dni, string $codEstab): string
    {
        $canonico = hospital_codigo_canonico($codEstab);
        if (hospital_establecimiento($canonico) === null) {
            $canonico = '000005481';
        }
        $pdo = self::getConnection();
        $pdo->prepare("
            INSERT INTO app_obstetra_establecimiento (dni, cod_estab) VALUES (:dni, :estab)
            ON DUPLICATE KEY UPDATE cod_estab = VALUES(cod_estab)
        ")->execute([':dni' => $dni, ':estab' => $canonico]);
        return $canonico;
    }

    public static function obtenerEstablecimientoObstetra(string $dni): string
    {
        $pdo = self::getConnection();
        $stmt = $pdo->prepare('SELECT cod_estab FROM app_obstetra_establecimiento WHERE dni = :dni LIMIT 1');
        $stmt->execute([':dni' => $dni]);
        $cod = $stmt->fetchColumn();
        return is_string($cod) && $cod !== '' ? $cod : '000005481';
    }

    // ========================================================================
    // DESAFÍOS 2FA (5 minutos, un solo uso)
    // ========================================================================
    public static function crearChallenge(string $dni, string $codEstab, string $platform): array
    {
        $id = bin2hex(random_bytes(24));
        $expires = time() + 300;
        $pdo = self::getConnection();
        $stmt = $pdo->prepare("
            INSERT INTO app_2fa_challenges (challenge_id, dni, cod_estab, plataforma, expires_at)
            VALUES (:id, :dni, :estab, :platform, :expires)
        ");
        $stmt->execute([
            ':id' => $id,
            ':dni' => $dni,
            ':estab' => $codEstab,
            ':platform' => $platform,
            ':expires' => $expires,
        ]);
        return ['challengeId' => $id, 'expiresAt' => $expires];
    }

    /** @return array<string, mixed>|null */
    public static function obtenerChallenge(string $challengeId): ?array
    {
        $pdo = self::getConnection();
        $stmt = $pdo->prepare("
            SELECT * FROM app_2fa_challenges
            WHERE challenge_id = :id AND used = 0 AND expires_at >= :now
            LIMIT 1
        ");
        $stmt->execute([':id' => $challengeId, ':now' => time()]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public static function marcarChallengeUsado(string $challengeId): void
    {
        self::getConnection()
            ->prepare('UPDATE app_2fa_challenges SET used = 1 WHERE challenge_id = :id')
            ->execute([':id' => $challengeId]);
    }

    /**
     * Conserva el contrato anterior para llamadas externas, pero ahora solo se
     * marca como usado cuando el código TOTP ya fue validado por api.php.
     *
     * @return array<string, mixed>|null
     */
    public static function consumeChallenge(string $challengeId): ?array
    {
        $row = self::obtenerChallenge($challengeId);
        if ($row !== null) {
            self::marcarChallengeUsado($challengeId);
        }
        return $row;
    }

    // ========================================================================
    // RATE LIMITING PERSISTENTE (anti-scraping / anti-fuerza bruta)
    // ========================================================================
    public static function rateLimitStatus(string $bucket, int $max, int $windowSeconds): array
    {
        $pdo = self::getConnection();
        $now = time();
        $pdo->prepare('DELETE FROM app_rate_limits WHERE bucket = :bucket AND reset_at <= :now')
            ->execute([':bucket' => $bucket, ':now' => $now]);
        $stmt = $pdo->prepare('SELECT hits, reset_at FROM app_rate_limits WHERE bucket = :bucket LIMIT 1');
        $stmt->execute([':bucket' => $bucket]);
        $row = $stmt->fetch();
        if (!$row) {
            return ['allowed' => true, 'hits' => 0, 'remaining' => $max, 'retryAfter' => 0];
        }
        $hits = (int)$row['hits'];
        return [
            'allowed' => $hits < $max,
            'hits' => $hits,
            'remaining' => max(0, $max - $hits),
            'retryAfter' => max(0, (int)$row['reset_at'] - $now),
        ];
    }

    public static function rateLimitHit(string $bucket, int $windowSeconds): void
    {
        $pdo = self::getConnection();
        $now = time();
        $pdo->prepare('DELETE FROM app_rate_limits WHERE bucket = :bucket AND reset_at <= :now')
            ->execute([':bucket' => $bucket, ':now' => $now]);
        $stmt = $pdo->prepare("
            INSERT INTO app_rate_limits (bucket, hits, reset_at) VALUES (:bucket, 1, :reset)
            ON DUPLICATE KEY UPDATE hits = hits + 1
        ");
        $stmt->execute([':bucket' => $bucket, ':reset' => $now + $windowSeconds]);
    }

    public static function rateLimitReset(string $bucket): void
    {
        self::getConnection()->prepare('DELETE FROM app_rate_limits WHERE bucket = :bucket')
            ->execute([':bucket' => $bucket]);
    }

    // ========================================================================
    // WAF (SQLi / XSS) Y SANITIZACIÓN
    // ========================================================================
    /** @return array{type: ?string, matched: string} */
    public static function detectMaliciousPayload(mixed $input): array
    {
        $serialized = is_string($input) ? $input : json_encode($input, JSON_UNESCAPED_UNICODE);
        $serialized = (string)$serialized;
        $targets = [$serialized];
        $decoded = rawurldecode($serialized);
        if ($decoded !== $serialized) {
            $targets[] = $decoded;
        }

        // \b evita falsos positivos con apellidos/direcciones en español:
        // "SELECTA", "COLECTA", "actualización" o "secuencia" NO coinciden.
        $sqli = [
            '/\b(?:SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|EXEC|EXECUTE|SLEEP|BENCHMARK|INFORMATION_SCHEMA)\b/i',
            '/\b(?:OR|AND)\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+/i',
            '/(?:--(?:\s|$)|\/\*|\*\/|;\s*(?:SELECT|DROP|DELETE|UPDATE|INSERT|ALTER)\b)/i',
            '/\b(?:sp_query_set|xp_cmdshell|load_file)\b/i',
            '/\bINTO\s+OUTFILE\b/i',
        ];
        $xss = [
            '/<\s*script\b[^>]*>/i',
            '/javascript\s*:/i',
            '/\bon(?:error|load|click|mouseover|focus|blur|submit|change)\s*=/i',
            '/<\s*(?:iframe|object|embed|svg|img|body|input|link|meta)\b[^>]*(?:on\w+\s*=|src\s*=\s*[\'"]?\s*javascript:)/i',
            '/\b(?:alert|prompt|confirm)\s*\(/i',
            '/\bdocument\.(?:cookie|location|write)\b/i',
            '/\bdata:text\/html\b/i',
            '/\bvbscript\s*:/i',
        ];
        $pathTraversal = [
            '/(?:^|[\\\\\/])\.\.(?:[\\\\\/]|$)/',
            '/(?:%2e%2e|%252e%252e)(?:%2f|%5c|\/|\\\\)/i',
            '/\b(?:etc\/(?:passwd|shadow|hosts)|proc\/self\/(?:environ|cmdline)|php:\/\/(?:filter|input)|expect:\/\/|zip:\/\/|phar:\/\/)\b/i',
            '/\b(?:file|gopher|dict):\/\//i',
        ];

        foreach ($targets as $target) {
            foreach ($sqli as $pattern) {
                if (preg_match($pattern, $target, $m)) {
                    return ['type' => 'SQLI', 'matched' => (string)$m[0]];
                }
            }
            foreach ($xss as $pattern) {
                if (preg_match($pattern, $target, $m)) {
                    return ['type' => 'XSS', 'matched' => (string)$m[0]];
                }
            }
            foreach ($pathTraversal as $pattern) {
                if (preg_match($pattern, $target, $m)) {
                    return ['type' => 'PATH_TRAVERSAL', 'matched' => (string)$m[0]];
                }
            }
        }
        return ['type' => null, 'matched' => ''];
    }

    public static function sanitizeText(mixed $value, int $maxLen = 150): string
    {
        $text = trim(strip_tags((string)($value ?? '')));
        $text = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/u', '', $text) ?? '';
        return mb_substr($text, 0, $maxLen, 'UTF-8');
    }

    public static function sanitizeForHtml(mixed $value, int $maxLen = 150): string
    {
        return htmlspecialchars(self::sanitizeText($value, $maxLen), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    // ========================================================================
    // UTILIDADES DE CLIENTE
    // ========================================================================
    public static function clientIp(): string
    {
        $forwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
        if ($forwarded !== '') {
            $ip = trim(explode(',', $forwarded)[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
        return (string)($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');
    }

    public static function detectPlatform(): string
    {
        $ua = strtolower((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
        if (str_contains($ua, 'android')) {
            return 'Android';
        }
        if (str_contains($ua, 'iphone') || str_contains($ua, 'ipad') || str_contains($ua, 'ipod')) {
            return 'iOS (iPhone/iPad)';
        }
        return 'Web Desktop';
    }

    // ========================================================================
    // CADENA DE AUDITORÍA INMUTABLE (SHA-256 HASH CHAIN)
    // ========================================================================
    public static function registrarAuditoria(
        string $actorDni,
        string $accion,
        string $detalle,
        string $actorEstab = '',
        ?string $plataforma = null
    ): void {
        try {
            $pdo = self::getConnection();
            $ip = self::clientIp();
            $platform = $plataforma ?: self::detectPlatform();
            $detalle = mb_substr($detalle, 0, 250, 'UTF-8');
            $actorEstab = mb_substr($actorEstab, 0, 9, 'UTF-8');
            $accion = mb_substr($accion, 0, 60, 'UTF-8');
            $fecha = date('Y-m-d H:i:s');

            $stmt = $pdo->query('SELECT hash_sha256 FROM auditoria_seguridad_app ORDER BY id DESC LIMIT 1');
            $prev = (string)($stmt->fetchColumn() ?: str_repeat('0', 64));
            $payload = implode('|', [$actorDni, $accion, $detalle, $ip, $platform, $actorEstab, $prev, $fecha]);
            $hash = hash('sha256', $payload);

            $stmt = $pdo->prepare("
                INSERT INTO auditoria_seguridad_app
                    (fecha_hora, actor_dni, actor_estab, accion, detalle, ip, plataforma, prev_hash, hash_sha256)
                VALUES
                    (:fecha, :dni, :estab, :accion, :detalle, :ip, :plataforma, :prev, :hash)
            ");
            $stmt->execute([
                ':fecha' => $fecha,
                ':dni' => mb_substr($actorDni, 0, 15),
                ':estab' => $actorEstab,
                ':accion' => $accion,
                ':detalle' => $detalle,
                ':ip' => $ip,
                ':plataforma' => $platform,
                ':prev' => $prev,
                ':hash' => $hash,
            ]);
        } catch (Throwable $e) {
            // La auditoría nunca debe interrumpir la atención clínica.
        }
    }

    /** @return array{valid: bool, verified: int, brokenAtId: ?int, latestHash: ?string} */
    public static function verificarCadenaAuditoria(): array
    {
        $pdo = self::getConnection();
        $rows = $pdo->query('SELECT id, fecha_hora, actor_dni, actor_estab, accion, detalle, ip, plataforma, prev_hash, hash_sha256 FROM auditoria_seguridad_app ORDER BY id ASC LIMIT 20000')->fetchAll();
        $expectedPrev = str_repeat('0', 64);
        $verified = 0;
        foreach ($rows as $row) {
            $payload = implode('|', [
                $row['actor_dni'],
                $row['accion'],
                $row['detalle'],
                $row['ip'],
                $row['plataforma'],
                $row['actor_estab'],
                $expectedPrev,
                $row['fecha_hora'],
            ]);
            $recalc = hash('sha256', $payload);
            if ($row['prev_hash'] !== $expectedPrev || !hash_equals($recalc, (string)$row['hash_sha256'])) {
                return [
                    'valid' => false,
                    'verified' => $verified,
                    'brokenAtId' => (int)$row['id'],
                    'latestHash' => $row['hash_sha256'] ?? null,
                ];
            }
            $expectedPrev = (string)$row['hash_sha256'];
            $verified++;
        }
        return [
            'valid' => true,
            'verified' => $verified,
            'brokenAtId' => null,
            'latestHash' => $verified > 0 ? $expectedPrev : null,
        ];
    }

    public static function ultimaAuditoria(int $limit = 30): array
    {
        $limit = max(1, min($limit, 200));
        $pdo = self::getConnection();
        $stmt = $pdo->query("SELECT * FROM auditoria_seguridad_app ORDER BY id DESC LIMIT {$limit}");
        return $stmt->fetchAll();
    }

    // ========================================================================
    // HELPERS DE PASSWORD (BCRYPT / SCRYPT / LEGADO)
    // ========================================================================
    public static function hashPassword(string $password): string
    {
        // Cost 10: ~75 ms por login en lugar de ~350 ms con cost 12. Con 20
        // obstetras simultáneas evita saturar la CPU del contenedor de Render.
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => 10]);
    }

    public static function verifyPassword(string $password, string $stored): bool
    {
        if ($stored === '') {
            return false;
        }
        if (password_verify($password, $stored)) {
            return true;
        }
        // Compatibilidad con registros antiguos de la tabla `usuario`.
        if (hash_equals(hash('sha256', $password), $stored)) {
            return true;
        }
        return hash_equals($stored, $password);
    }
}
