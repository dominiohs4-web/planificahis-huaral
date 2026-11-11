<?php
/**
 * sync_cloud_to_local.php
 * Sincronización Nube <-> Base Local del Hospital San Juan Bautista Huaral
 * (MariaDB 10.4.32, base histórica de más de 5 GB).
 *
 * Uso CLI (recomendado, en la PC de Estadística):
 *   php sync_cloud_to_local.php --direction=bidirectional --batch=500
 *   php sync_cloud_to_local.php --direction=cloud-to-local --mode=direct
 *   php sync_cloud_to_local.php --direction=cloud-to-local --mode=bridge
 *   php sync_cloud_to_local.php --direction=local-to-cloud --batch=500
 *   php sync_cloud_to_local.php --direction=bidirectional --dry-run --dump=.\sync_preview.sql
 *   php sync_cloud_to_local.php --direction=local-to-cloud --full
 *
 * Uso Web (protegido por token):
 *   https://servidor/sync_cloud_to_local.php?token=...&direction=bidirectional
 *
 * REGLAS DE ORO:
 *   - Solo se sincronizan tablas ORIGINALES del hospital:
 *       usuario, mstrpers, his_mstrpers, his_dl, his_dl_dt.
 *   - cloud-to-local modo bridge usa tablas receptoras nativas:
 *       usuario->r_his_digitad, his_mstrpers->r_his_mstrpers,
 *       his_dl->r_his_dl, his_dl_dt->r_his_dl_dt + CALL sp_get_recepcion().
 *   - local-to-cloud sube SOLO las tablas originales y NUNCA crea tablas en el
 *     servidor del hospital. Las tablas `app_*`, `pacientes_sin_metodo` y
 *     `auditoria_seguridad_app` jamás salen de la nube ni se replican al HIS.
 *   - NUNCA ejecuta CREATE, ALTER, DROP, TRUNCATE ni DELETE sobre las tablas
 *     del HIS. La única excepción es una migración idempotente y aditiva
 *     (ADD COLUMN IF NOT EXISTS) sobre la tabla PROPIA `pacientes_sin_metodo`
 *     para asegurar la columna `tipo_doc` del soporte multi-documento.
 *   - INSERT ... ON DUPLICATE KEY UPDATE (idempotente) y lotes con LIMIT estricto.
 *   - Incremental local-to-cloud: `ANO >= año actual - 1` en tablas clínicas y
 *     keyset por PK en tablas pequeñas; `--full` fuerza la carga completa.
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

$option = static function (string $name, string $default = '') use ($options): string {
    if (array_key_exists($name, $options)) {
        return (string)$options[$name];
    }
    if (array_key_exists($name, $_GET)) {
        return (string)$_GET[$name];
    }
    return $default;
};

$direction = strtolower($option('direction', 'cloud-to-local'));
// Compatibilidad con el parámetro anterior --mode=direct|bridge.
if ($direction === 'nube-a-local' || $direction === 'cloud_to_local' || $direction === 'cloud-to-local') {
    $direction = 'cloud-to-local';
} elseif ($direction === 'local-a-nube' || $direction === 'local_to_cloud' || $direction === 'local-to-cloud') {
    $direction = 'local-to-cloud';
} elseif ($direction === 'bidireccional' || $direction === 'bidirectional') {
    $direction = 'bidirectional';
}
if (!in_array($direction, ['cloud-to-local', 'local-to-cloud', 'bidirectional'], true)) {
    $direction = 'cloud-to-local';
}

$mode = strtolower($option('mode', 'direct'));
if (!in_array($mode, ['direct', 'bridge'], true)) {
    $mode = 'direct';
}
$batch = (int)$option('batch', '500');
$batch = max(1, min($batch, 2000));
$dryRun = isset($options['dry-run']) || isset($_GET['dry_run']);
$fullSync = isset($options['full']) || isset($_GET['full']);
$dumpPath = trim($option('dump', ''));
$sinceYear = (int)$option('since', (string)((int)date('Y') - 1));
$sinceYear = max(1900, min(2100, $sinceYear));

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
 * Conexión PDO endurecida. La nube usa TLS cuando CLOUD_DB_SSL/DB_SSL valen 1;
 * la base local del hospital no usa TLS.
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

    $useSsl = $isCloud && (
        getenv('CLOUD_DB_SSL') === '1'
        || getenv('DB_SSL') === '1'
    );
    if ($useSsl) {
        if (defined('PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT')) {
            $options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = false;
        }
        $ca = (string)(getenv('CLOUD_DB_SSL_CA') ?: (getenv('DB_SSL_CA') ?: ''));
        if ($ca !== '' && is_readable($ca) && defined(PDO::MYSQL_ATTR_SSL_CA)) {
            $options[PDO::MYSQL_ATTR_SSL_CA] = $ca;
        }
    }

    return new PDO($dsn, $cfg['user'], $cfg['pass'], $options);
}

// Infraestructura dedicada en DigitalOcean (MySQL 8.0).
$cloudCfg = [
    'host' => '206.189.225.149',
    'port' => '3306',
    'dbname' => 'app',
    'user' => 'admin_planifica',
    'pass' => '75100725L@uis',
];
$localCfg = [
    'host' => getenv('LOCAL_DB_HOST') ?: '127.0.0.1',
    'port' => getenv('LOCAL_DB_PORT') ?: '3306',
    'dbname' => getenv('LOCAL_DB_NAME') ?: 'app',
    'user' => getenv('LOCAL_DB_USER') ?: (getenv('DB_USER') ?: 'root'),
    'pass' => getenv('LOCAL_DB_PASS') !== false ? (string)getenv('LOCAL_DB_PASS') : (getenv('DB_PASS') ?: ''),
];

// Lista blanca estricta: solo tablas originales del hospital.
$originalTables = ['usuario', 'mstrpers', 'his_mstrpers', 'his_dl', 'his_dl_dt'];
$bridgeMap = [
    'usuario' => 'r_his_digitad',
    'his_mstrpers' => 'r_his_mstrpers',
    'his_dl' => 'r_his_dl',
    'his_dl_dt' => 'r_his_dl_dt',
];
$neverTables = [
    'pacientes_sin_metodo',
    'auditoria_seguridad_app',
    'app_catalogo_metodos',
    'app_usuarios',
    'app_usuarios_accesos',
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
    'his_mstrpers' => ['CODPSAL', 'COD_ESTAB'],
    'his_dl' => ['ID'],
    'his_dl_dt' => ['ID', 'num'],
    'r_his_dl' => ['ID'],
    'r_his_dl_dt' => ['ID', 'num'],
    'r_his_mstrpers' => ['CODPSAL', 'COD_ESTAB'],
    'r_his_digitad' => ['dni'],
];
// Columnas de año para el modo incremental local-to-cloud.
$incrementalYearColumns = [
    'his_dl' => ['ANO'],
    'his_dl_dt' => ['ano'],
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

/**
 * Migración aditiva y estrictamente acotada a la tabla PROPIA de la app.
 * Asegura `pacientes_sin_metodo.tipo_doc` para el soporte multi-documento
 * (DNI, CE, Pasaporte, PTP, CNV/SIS). Nunca toca tablas del HIS.
 *
 * @return array<string, mixed>
 */
function sync_asegurar_esquema_app(PDO $local): array
{
    $tabla = 'pacientes_sin_metodo';
    if (!table_exists($local, $tabla)) {
        return ['tabla' => $tabla, 'aplicado' => false, 'motivo' => 'tabla_no_existe'];
    }
    try {
        if (in_array('tipo_doc', table_columns($local, $tabla), true)) {
            return ['tabla' => $tabla, 'aplicado' => false, 'motivo' => 'columna_ya_existe'];
        }
        $local->exec(
            "ALTER TABLE `pacientes_sin_metodo` "
            . "ADD COLUMN `tipo_doc` varchar(15) CHARACTER SET utf8 COLLATE utf8_general_ci "
            . "NOT NULL DEFAULT 'DNI' AFTER `dni`"
        );
        return ['tabla' => $tabla, 'aplicado' => true, 'motivo' => 'columna_creada'];
    } catch (Throwable $e) {
        return ['tabla' => $tabla, 'aplicado' => false, 'motivo' => 'error', 'detalle' => $e->getMessage()];
    }
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
 * `$extraWhere` debe venir sin la palabra WHERE y con sus propios parámetros.
 *
 * @return array<int, array<string, mixed>>
 */
function fetch_batch(
    PDO $pdo,
    string $table,
    array $keys,
    array $columns,
    ?array $lastKey,
    int $limit,
    string $extraWhere = '',
    array $extraParams = []
): array {
    foreach (array_merge($keys, $columns) as $c) {
        if (!safe_identifier((string)$c)) {
            throw new RuntimeException('Identificador no permitido: ' . $c);
        }
    }
    $limit = max(1, min($limit, 2000));
    $where = [];
    $params = [];
    if ($lastKey !== null && count($lastKey) === count($keys)) {
        if (count($keys) === 1) {
            $where[] = qcol($keys[0]) . ' > :k0';
            $params[':k0'] = $lastKey[0];
        } else {
            $parts = [];
            foreach ($keys as $i => $key) {
                $parts[] = ':k' . $i;
                $params[':k' . $i] = $lastKey[$i];
            }
            $where[] = '(' . implode(', ', array_map('qcol', $keys)) . ') > (' . implode(', ', $parts) . ')';
        }
    }
    if ($extraWhere !== '') {
        $where[] = '(' . $extraWhere . ')';
        $params = array_merge($params, $extraParams);
    }
    $whereSql = $where ? (' WHERE ' . implode(' AND ', $where)) : '';
    $order = implode(', ', array_map('qcol', $keys));
    $sql = 'SELECT ' . implode(', ', array_map('qcol', $columns)) . ' FROM ' . qcol($table) . $whereSql . ' ORDER BY ' . $order . ' LIMIT ' . $limit;
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

/**
 * Sincroniza un sentido completo. Devuelve el reporte del sentido.
 *
 * @param array<int, string> $plan source => target
 * @return array<string, mixed>
 */
function sync_direction(
    string $direction,
    PDO $source,
    PDO $target,
    array $plan,
    array $keyColumns,
    array $incrementalYearColumns,
    int $batch,
    bool $dryRun,
    bool $fullSync,
    int $sinceYear,
    $dumpHandle
): array {
    $report = [
        'direction' => $direction,
        'tables' => [],
        'errors' => [],
    ];

    foreach ($plan as $sourceTable => $targetTable) {
        if (
            !safe_identifier((string)$sourceTable)
            || !safe_identifier((string)$targetTable)
            || sync_is_forbidden((string)$sourceTable)
            || sync_is_forbidden((string)$targetTable)
        ) {
            $report['errors'][] = "Tabla no permitida: {$sourceTable} -> {$targetTable}";
            continue;
        }
        if (!table_exists($source, (string)$sourceTable)) {
            $report['tables'][$sourceTable] = ['skipped' => true, 'reason' => 'No existe en la base de origen.'];
            continue;
        }
        if (!table_exists($target, (string)$targetTable)) {
            // REGLA DE ORO: jamás intentar escribir en una tabla inexistente.
            $report['tables'][$sourceTable] = [
                'skipped' => true,
                'target' => $targetTable,
                'reason' => 'No existe en la base de destino.',
            ];
            continue;
        }

        $sourceColumns = table_columns($source, (string)$sourceTable);
        $targetColumns = table_columns($target, (string)$targetTable);
        $common = array_values(array_intersect($sourceColumns, $targetColumns));
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

        // local-to-cloud incremental: las tablas clínicas se limitan por ANO.
        $extraWhere = '';
        $extraParams = [];
        if ($direction === 'local-to-cloud' && !$fullSync) {
            foreach (($incrementalYearColumns[$sourceTable] ?? []) as $yearColumn) {
                if (in_array($yearColumn, $sourceColumns, true) && in_array($yearColumn, $common, true)) {
                    $extraWhere = qcol($yearColumn) . ' >= :ano_min';
                    $extraParams = [':ano_min' => $sinceYear];
                    break;
                }
            }
        }

        $processed = 0;
        $batches = 0;
        $lastKey = null;
        $started = microtime(true);
        try {
            while (true) {
                $rows = fetch_batch($source, (string)$sourceTable, $keys, $common, $lastKey, $batch, $extraWhere, $extraParams);
                if (!$rows) {
                    break;
                }
                $batches++;
                $sql = upsert_sql($target, (string)$targetTable, $rows, $common, $keys);
                if ($sql === '') {
                    break;
                }
                if (!sync_sql_seguro($sql)) {
                    throw new RuntimeException('El lote generado fue bloqueado por la política SQL del hospital.');
                }
                if ($dumpHandle !== null) {
                    fwrite($dumpHandle, "-- [{$direction}] {$sourceTable} -> {$targetTable} · lote {$batches} · " . count($rows) . " filas\n");
                    fwrite($dumpHandle, $sql . "\n");
                }
                if (!$dryRun) {
                    $target->beginTransaction();
                    try {
                        $target->exec($sql);
                        $target->commit();
                    } catch (Throwable $e) {
                        $target->rollBack();
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
                'incremental' => $extraWhere !== '' ? ['where' => $extraWhere, 'since' => $sinceYear] : null,
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

    return $report;
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
    'direction' => $direction,
    'mode' => $mode,
    'batch' => $batch,
    'dryRun' => $dryRun,
    'full' => $fullSync,
    'sinceYear' => $sinceYear,
    'dump' => $dumpPath !== '' ? $dumpPath : null,
    'neverSynced' => $neverTables,
    'schemaMigration' => [],
    'directions' => [],
    'tables' => [],
    'errors' => [],
];

if (!$dryRun) {
    $report['schemaMigration'] = sync_asegurar_esquema_app($local);
}

$dumpHandle = null;
if ($dumpPath !== '') {
    $dumpHandle = fopen($dumpPath, 'wb');
    if ($dumpHandle === false) {
        sync_out(['error' => 'No se pudo abrir el archivo de dump: ' . $dumpPath], 400);
    }
    fwrite($dumpHandle, "-- Sincronización PlanificaHIS · " . date('c') . " · dirección {$direction} · modo {$mode}\n");
    fwrite($dumpHandle, "SET NAMES utf8mb4;\nSET @OLD_SQL_MODE=@@SQL_MODE;\nSET SQL_MODE='STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION';\n");
}

if ($direction === 'cloud-to-local' || $direction === 'bidirectional') {
    // En modo bridge solo se tocan las tablas receptoras nativas del hospital.
    $plan = $mode === 'bridge' ? $bridgeMap : array_combine($originalTables, $originalTables);
    $sub = sync_direction(
        'cloud-to-local',
        $cloud,
        $local,
        $plan,
        $keyColumns,
        $incrementalYearColumns,
        $batch,
        $dryRun,
        true, // La bajada conserva la carga histórica completa por keyset.
        $sinceYear,
        $dumpHandle
    );
    $report['directions']['cloud-to-local'] = $sub;
    foreach (($sub['tables'] ?? []) as $tabla => $info) {
        $report['tables']['cloud-to-local:' . $tabla] = $info;
    }
    foreach (($sub['errors'] ?? []) as $error) {
        $report['errors'][] = 'cloud-to-local: ' . $error;
    }
    if ($direction === 'cloud-to-local' && $mode === 'bridge' && !$dryRun) {
        try {
            $local->exec('CALL sp_get_recepcion()');
            $report['sp_get_recepcion'] = 'OK';
        } catch (Throwable $e) {
            $report['errors'][] = 'CALL sp_get_recepcion() falló: ' . $e->getMessage();
        }
    }
}

if ($direction === 'local-to-cloud' || $direction === 'bidirectional') {
    // Subida: SOLO tablas originales. Nunca app_*, pacientes_sin_metodo ni
    // auditoria_seguridad_app. Esto garantiza que el hospital no reciba tablas
    // nuevas ni datos exclusivos de la nube.
    $plan = array_combine($originalTables, $originalTables);
    $sub = sync_direction(
        'local-to-cloud',
        $local,
        $cloud,
        $plan,
        $keyColumns,
        $incrementalYearColumns,
        $batch,
        $dryRun,
        $fullSync,
        $sinceYear,
        $dumpHandle
    );
    $report['directions']['local-to-cloud'] = $sub;
    foreach (($sub['tables'] ?? []) as $tabla => $info) {
        $report['tables']['local-to-cloud:' . $tabla] = $info;
    }
    foreach (($sub['errors'] ?? []) as $error) {
        $report['errors'][] = 'local-to-cloud: ' . $error;
    }
}

if ($dumpHandle !== null) {
    if ($direction !== 'local-to-cloud' && $mode === 'bridge') {
        fwrite($dumpHandle, "\n-- Procedimiento nativo del hospital: integra las tablas receptoras.\nCALL sp_get_recepcion();\n");
    }
    fwrite($dumpHandle, "SET SQL_MODE=@OLD_SQL_MODE;\n");
    fclose($dumpHandle);
}

// Registro de la corrida (solo en la nube; si la tabla no existe se ignora).
// app_sync_runs es una tabla de metadatos: jamás se exporta a la base local.
try {
    $cloud->prepare("
        INSERT INTO app_sync_runs (actor_dni, modo, tablas, filas)
        VALUES (:dni, :modo, :tablas, :filas)
    ")->execute([
        ':dni' => $isCli ? 'SYNC_CLI' : 'SYNC_WEB',
        ':modo' => $direction,
        ':tablas' => implode(',', array_keys($report['tables'])),
        ':filas' => array_sum(array_map(static fn ($t) => (int)($t['rows'] ?? 0), $report['tables'])),
    ]);
} catch (Throwable $e) {
    // La tabla app_sync_runs puede no existir en una instalación nueva.
}

$report['finishedAt'] = date('c');
sync_out($report);
