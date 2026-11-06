<?php
/**
 * sync_cloud_to_local.php
 * Sincronización Nube -> Base Local del Hospital San Juan Bautista Huaral
 * (MariaDB 10.4.32, base histórica de más de 5 GB).
 *
 * Uso CLI (recomendado, en la PC de Estadística):
 *   php sync_cloud_to_local.php --mode=direct --batch=500
 *   php sync_cloud_to_local.php --mode=bridge --batch=500
 *   php sync_cloud_to_local.php --mode=direct --dry-run --dump=.\sync_preview.sql
 *
 * Uso Web (protegido por token):
 *   https://servidor/sync_cloud_to_local.php?token=...&mode=direct
 *
 * REGLAS DE ORO:
 *   - Modo direct:  usuario, mstrpers, his_mstrpers, his_dl, his_dl_dt.
 *   - Modo bridge: usuario->r_his_digitad, his_mstrpers->r_his_mstrpers,
 *                  his_dl->r_his_dl, his_dl_dt->r_his_dl_dt +
 *                  CALL sp_get_recepcion() una sola vez al final.
 *   - NUNCA exporta pacientes_sin_metodo, auditoria_seguridad_app ni tablas app_*.
 *   - NUNCA ejecuta CREATE, ALTER, DROP, TRUNCATE ni DELETE.
 *   - INSERT ... ON DUPLICATE KEY UPDATE (idempotente) y lotes con LIMIT estricto.
 */
declare(strict_types=1);

require_once __DIR__ . '/catalogo_establecimientos.php';

if (PHP_SAPI !== 'cli') {
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
    header('Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=()');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Robots-Tag: noindex, nofollow');
}

$isCli = PHP_SAPI === 'cli';
$argvList = $isCli ? $argv : [];
$options = [];
foreach ($argvList as $arg) {
    if (preg_match('/^--([a-z0-9\-]+)(?:=(.*))?$/i', $arg, $m)) {
        $options[$m[1]] = $m[2] ?? '1';
    }
}

$mode = strtolower((string)($options['mode'] ?? ($_GET['mode'] ?? 'direct')));
if (!in_array($mode, ['direct', 'bridge'], true)) {
    $mode = 'direct';
}
$batch = (int)($options['batch'] ?? ($_GET['batch'] ?? 500));
$batch = max(1, min($batch, 2000));
$dryRun = isset($options['dry-run']) || isset($_GET['dry_run']);
$dumpPath = trim((string)($options['dump'] ?? ($_GET['dump'] ?? '')));

function sync_out(array $data, int $status = 200): void
{
    if (PHP_SAPI !== 'cli') {
        http_response_code($status);
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_HEX_TAG | JSON_HEX_AMP);
        exit;
    }
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . PHP_EOL;
    exit($status >= 400 ? 1 : 0);
}

// ---------------------------------------------------------------------------
// Autorización de ejecución web
// ---------------------------------------------------------------------------
if (!$isCli) {
    $expected = (string)(getenv('SYNC_TOKEN') ?: '');
    $provided = (string)($_SERVER['HTTP_X_SYNC_TOKEN'] ?? ($_GET['token'] ?? ''));
    if ($expected === '' || !hash_equals($expected, $provided)) {
        sync_out(['error' => 'No autorizado. Configure SYNC_TOKEN y envíelo en X-Sync-Token.'], 403);
    }
}

/**
 * Conexión PDO endurecida. La nube usa TLS obligatorio cuando el puerto es 4000
 * o el host pertenece a TiDB Cloud; la base local del hospital no usa TLS.
 */
function sync_pdo(array $cfg, bool $isCloud): PDO
{
    $dsn = sprintf(
        'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
        $cfg['host'],
        $cfg['port'],
        $cfg['dbname']
    );
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_STRINGIFY_FETCHES => false,
        PDO::ATTR_PERSISTENT => false,
        PDO::ATTR_TIMEOUT => 20,
    ];

    $host = (string)$cfg['host'];
    $port = (string)$cfg['port'];
    $useSsl = $isCloud && (
        getenv('CLOUD_DB_SSL') === '1'
        || getenv('DB_SSL') === '1'
        || $port === '4000'
        || str_contains($host, 'tidbcloud.com')
    );
    if ($useSsl) {
        if (defined('PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT')) {
            $options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = false;
        }
        $ca = (string)(getenv('CLOUD_DB_SSL_CA') ?: (getenv('DB_SSL_CA') ?: ''));
        if ($ca !== '' && is_readable($ca) && defined('PDO::MYSQL_ATTR_SSL_CA')) {
            $options[PDO::MYSQL_ATTR_SSL_CA] = $ca;
        }
    }

    return new PDO($dsn, $cfg['user'], $cfg['pass'], $options);
}

$cloudCfg = [
    'host' => getenv('CLOUD_DB_HOST') ?: (getenv('DB_HOST') ?: '127.0.0.1'),
    'port' => getenv('CLOUD_DB_PORT') ?: (getenv('DB_PORT') ?: '3306'),
    'dbname' => getenv('CLOUD_DB_NAME') ?: (getenv('DB_NAME') ?: 'app'),
    'user' => getenv('CLOUD_DB_USER') ?: (getenv('DB_USER') ?: 'root'),
    'pass' => getenv('CLOUD_DB_PASS') !== false ? (string)getenv('CLOUD_DB_PASS') : (getenv('DB_PASS') ?: ''),
];
$localCfg = [
    'host' => getenv('LOCAL_DB_HOST') ?: '127.0.0.1',
    'port' => getenv('LOCAL_DB_PORT') ?: '3306',
    'dbname' => getenv('LOCAL_DB_NAME') ?: 'app',
    'user' => getenv('LOCAL_DB_USER') ?: (getenv('DB_USER') ?: 'root'),
    'pass' => getenv('LOCAL_DB_PASS') !== false ? (string)getenv('LOCAL_DB_PASS') : (getenv('DB_PASS') ?: ''),
];

$allowedTables = ['usuario', 'mstrpers', 'his_mstrpers', 'his_dl', 'his_dl_dt'];
$bridgeMap = [
    'usuario' => 'r_his_digitad',
    'his_mstrpers' => 'r_his_mstrpers',
    'his_dl' => 'r_his_dl',
    'his_dl_dt' => 'r_his_dl_dt',
];
$neverTables = [
    'pacientes_sin_metodo',
    'auditoria_seguridad_app',
    'app_2fa_challenges',
    'app_obstetra_establecimiento',
    'app_rate_limits',
    'app_sesiones',
    'app_sync_runs',
    'app_totp_secretos',
];
$keyColumns = [
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

function sync_is_forbidden(string $table): bool
{
    global $neverTables;
    $table = strtolower($table);
    if (in_array($table, $neverTables, true)) {
        return true;
    }
    // Toda tabla de seguridad de la app es exclusiva de la nube.
    return str_starts_with($table, 'app_');
}

function table_exists(PDO $pdo, string $table): bool
{
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t');
    $stmt->execute([':t' => $table]);
    return (int)$stmt->fetchColumn() > 0;
}

/** @return array<int, string> */
function table_columns(PDO $pdo, string $table): array
{
    $stmt = $pdo->prepare('SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t ORDER BY ORDINAL_POSITION');
    $stmt->execute([':t' => $table]);
    return array_map(static fn ($row) => (string)$row['COLUMN_NAME'], $stmt->fetchAll());
}

function safe_identifier(string $identifier): bool
{
    return (bool)preg_match('/^[A-Za-z0-9_]{1,64}$/', $identifier);
}

function qcol(string $identifier): string
{
    return '`' . str_replace('`', '``', $identifier) . '`';
}

function sql_literal(PDO $pdo, mixed $value): string
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
 * Bloquea cualquier sentencia que no sea un INSERT ... ON DUPLICATE KEY UPDATE.
 * Se ignoran comentarios y literales para no confundir apellidos o direcciones
 * ("selecta", "actualización") con SQL peligroso.
 */
function sync_sql_seguro(string $sql): bool
{
    $limpio = preg_replace('/^\s*--.*$/m', '', $sql) ?? '';
    $limpio = preg_replace("/'(?:\\\\.|''|[^'\\\\])*'/s", "''", $limpio) ?? '';
    if (preg_match('/\b(CREATE|ALTER|DROP|TRUNCATE|DELETE|REPLACE|GRANT|REVOKE)\b/i', $limpio)) {
        return false;
    }
    // Solo se permiten uno o más INSERT (un lote por tabla).
    return (bool)preg_match('/^\s*INSERT\s+INTO\b/i', $limpio);
}

/**
 * @param array<int, array<string, mixed>> $rows
 * @param array<int, string> $commonColumns
 * @param array<int, string> $keys
 */
function upsert_sql(PDO $pdo, string $table, array $rows, array $commonColumns, array $keys): string
{
    if (!$rows || !$commonColumns) {
        return '';
    }
    $cols = array_values(array_filter($commonColumns, static fn ($c) => safe_identifier((string)$c)));
    if (!$cols) {
        return '';
    }
    $colSql = implode(', ', array_map('qcol', $cols));
    $tuples = [];
    foreach ($rows as $row) {
        $values = [];
        foreach ($cols as $col) {
            $values[] = sql_literal($pdo, $row[$col] ?? null);
        }
        $tuples[] = '(' . implode(', ', $values) . ')';
    }
    $updateCols = array_values(array_diff($cols, $keys));
    if (!$updateCols) {
        $updateCols = [$cols[0]];
    }
    $updateSql = implode(', ', array_map(static fn ($c) => qcol($c) . ' = VALUES(' . qcol($c) . ')', $updateCols));
    return 'INSERT INTO ' . qcol($table) . ' (' . $colSql . ")\nVALUES\n  "
        . implode(",\n  ", $tuples)
        . "\nON DUPLICATE KEY UPDATE " . $updateSql . ";\n";
}

/**
 * Paginación por keyset (sin OFFSET) para no saturar la red ni la base de 5 GB.
 * @return array<int, array<string, mixed>>
 */
function fetch_batch(PDO $pdo, string $table, array $keys, array $columns, ?array $lastKey, int $limit): array
{
    foreach (array_merge($keys, $columns) as $c) {
        if (!safe_identifier((string)$c)) {
            throw new RuntimeException('Identificador no permitido: ' . $c);
        }
    }
    $limit = max(1, min($limit, 2000));
    $where = '';
    $params = [];
    if ($lastKey !== null && count($lastKey) === count($keys)) {
        if (count($keys) === 1) {
            $where = ' WHERE ' . qcol($keys[0]) . ' > :k0';
            $params[':k0'] = $lastKey[0];
        } else {
            $parts = [];
            foreach ($keys as $i => $key) {
                $parts[] = ':k' . $i;
                $params[':k' . $i] = $lastKey[$i];
            }
            $where = ' WHERE (' . implode(', ', array_map('qcol', $keys)) . ') > (' . implode(', ', $parts) . ')';
        }
    }
    $order = implode(', ', array_map('qcol', $keys));
    $sql = 'SELECT ' . implode(', ', array_map('qcol', $columns)) . ' FROM ' . qcol($table) . $where . ' ORDER BY ' . $order . ' LIMIT ' . $limit;
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

// El dump opcional solo puede escribirse dentro de esta carpeta (nunca en rutas
// arbitrarias del servidor del hospital).
if ($dumpPath !== '') {
    $baseDir = realpath(__DIR__);
    $dumpDir = realpath(dirname($dumpPath));
    $basePrefix = $baseDir !== false ? rtrim($baseDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR : '';
    if (
        $baseDir === false
        || $dumpDir === false
        || ($dumpDir !== $baseDir && ($basePrefix === '' || !str_starts_with($dumpDir, $basePrefix)))
    ) {
        sync_out(['error' => 'La ruta del dump debe estar dentro de la carpeta de la aplicación.'], 400);
    }
}

try {
    $cloud = sync_pdo($cloudCfg, true);
    $local = sync_pdo($localCfg, false);
} catch (Throwable $e) {
    sync_out(['error' => 'No se pudo conectar a la base Nube o Local. Detalle: ' . $e->getMessage()], 503);
}

$report = [
    'startedAt' => date('c'),
    'mode' => $mode,
    'batch' => $batch,
    'dryRun' => $dryRun,
    'dump' => $dumpPath !== '' ? $dumpPath : null,
    'tables' => [],
    'neverSynced' => $neverTables,
    'errors' => [],
];
$dumpHandle = null;
if ($dumpPath !== '') {
    $dumpHandle = fopen($dumpPath, 'wb');
    if ($dumpHandle === false) {
        sync_out(['error' => 'No se pudo abrir el archivo de dump: ' . $dumpPath], 400);
    }
    fwrite($dumpHandle, "-- Sincronización Nube -> Local · " . date('c') . " · modo {$mode}\n");
    fwrite($dumpHandle, "SET NAMES utf8mb4;\nSET @OLD_SQL_MODE=@@SQL_MODE;\nSET SQL_MODE='STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION';\n");
}

// Plan estricto de tablas. En modo directo nunca se tocan las tablas puente y en
// modo bridge nunca se escribe mstrpers (no tiene tabla receptora nativa).
$plan = $mode === 'bridge' ? $bridgeMap : array_combine($allowedTables, $allowedTables);

foreach ($plan as $sourceTable => $targetTable) {
    if (
        !in_array($sourceTable, $allowedTables, true)
        || !safe_identifier($sourceTable)
        || !safe_identifier($targetTable)
        || sync_is_forbidden($sourceTable)
        || sync_is_forbidden($targetTable)
    ) {
        $report['errors'][] = "Tabla no permitida: {$sourceTable} -> {$targetTable}";
        continue;
    }
    if (!table_exists($cloud, $sourceTable)) {
        $report['tables'][$sourceTable] = ['skipped' => true, 'reason' => 'No existe en la base Nube.'];
        continue;
    }
    if (!table_exists($local, $targetTable)) {
        // REGLA DE ORO: jamás intentar escribir en una tabla inexistente del hospital.
        $report['tables'][$sourceTable] = [
            'skipped' => true,
            'target' => $targetTable,
            'reason' => 'No existe en la base local del hospital.',
        ];
        continue;
    }

    $cloudColumns = table_columns($cloud, $sourceTable);
    $localColumns = table_columns($local, $targetTable);
    $common = array_values(array_intersect($cloudColumns, $localColumns));
    $keys = $keyColumns[$targetTable] ?? [];
    $keys = array_values(array_intersect($keys, $common));
    if (!$common || !$keys) {
        $report['tables'][$sourceTable] = [
            'skipped' => true,
            'target' => $targetTable,
            'reason' => 'Sin columnas/clave común compatibles.',
        ];
        continue;
    }

    $processed = 0;
    $batches = 0;
    $lastKey = null;
    $started = microtime(true);
    try {
        while (true) {
            $rows = fetch_batch($cloud, $sourceTable, $keys, $common, $lastKey, $batch);
            if (!$rows) {
                break;
            }
            $batches++;
            $sql = upsert_sql($local, $targetTable, $rows, $common, $keys);
            if ($sql === '') {
                break;
            }
            if (!sync_sql_seguro($sql)) {
                throw new RuntimeException('El lote generado fue bloqueado por la política SQL del hospital.');
            }
            if ($dumpHandle !== null) {
                fwrite($dumpHandle, "-- {$sourceTable} -> {$targetTable} · lote {$batches} · " . count($rows) . " filas\n");
                fwrite($dumpHandle, $sql . "\n");
            }
            if (!$dryRun) {
                $local->beginTransaction();
                try {
                    $local->exec($sql);
                    $local->commit();
                } catch (Throwable $e) {
                    $local->rollBack();
                    throw $e;
                }
            }
            $processed += count($rows);
            $lastRow = $rows[count($rows) - 1];
            $lastKey = array_map(static fn ($k) => $lastRow[$k], $keys);
            if (count($rows) < $batch) {
                break;
            }
        }

        $report['tables'][$sourceTable] = [
            'target' => $targetTable,
            'rows' => $processed,
            'batches' => $batches,
            'seconds' => round(microtime(true) - $started, 3),
        ];
    } catch (Throwable $e) {
        $report['errors'][] = "{$sourceTable} -> {$targetTable}: " . $e->getMessage();
        $report['tables'][$sourceTable] = [
            'target' => $targetTable,
            'error' => $e->getMessage(),
            'rows' => $processed,
        ];
    }
}

if ($dumpHandle !== null) {
    if ($mode === 'bridge') {
        fwrite($dumpHandle, "\n-- Procedimiento nativo del hospital: integra las tablas receptoras.\nCALL sp_get_recepcion();\n");
    } else {
        fwrite($dumpHandle, "\n-- Modo directo: no se invoca sp_get_recepcion() para evitar doble inserción.\n");
    }
    fwrite($dumpHandle, "SET SQL_MODE=@OLD_SQL_MODE;\n");
    fclose($dumpHandle);
}

// El procedimiento del hospital procesa las tablas puente una sola vez, al final,
// cuando ya se cargaron todos los lotes. Nunca se ejecuta en modo directo.
if ($mode === 'bridge' && !$dryRun) {
    try {
        $local->exec('CALL sp_get_recepcion()');
        $report['sp_get_recepcion'] = 'OK';
    } catch (Throwable $e) {
        $report['errors'][] = 'CALL sp_get_recepcion() falló: ' . $e->getMessage();
    }
}

// Registro de la corrida (solo en la nube; si la tabla no existe se ignora).
// app_sync_runs es una tabla de metadatos: jamás se exporta a la base local.
try {
    $cloud->prepare("
        INSERT INTO app_sync_runs (actor_dni, modo, tablas, filas)
        VALUES (:dni, :modo, :tablas, :filas)
    ")->execute([
        ':dni' => $isCli ? 'SYNC_CLI' : 'SYNC_WEB',
        ':modo' => $mode,
        ':tablas' => implode(',', array_keys($report['tables'])),
        ':filas' => array_sum(array_map(static fn ($t) => (int)($t['rows'] ?? 0), $report['tables'])),
    ]);
} catch (Throwable $e) {
    // La tabla app_sync_runs puede no existir en una instalación nueva.
}

$report['finishedAt'] = date('c');
sync_out($report);
