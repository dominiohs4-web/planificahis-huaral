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

require_once __DIR__ . '/catalogo_establecimientos.php';

final class HospitalHuaralDB
{
    private static ?PDO $pdo = null;

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
     * OWASP ASVS L3: en producción no se admite la clave de demostración.
     * HUARAL_AES_SECRET / HUARAL_SESSION_SECRET son obligatorias; ENCRYPTION_SECRET
     * se mantiene solo como compatibilidad con instalaciones anteriores.
     */
    private static function configuredSecret(string $name, string $legacyName, string $developmentDefault): string
    {
        $value = getenv($name);
        if (!is_string($value) || trim($value) === '') {
            if (self::isProductionEnvironment()) {
                throw new RuntimeException(
                    "Falta la variable de entorno {$name}. En producción no se admite " .
                    'la clave de demostración ni el fallback legacy ENCRYPTION_SECRET.'
                );
            }
            $value = getenv($legacyName);
        }
        $value = is_string($value) ? trim($value) : '';
        if ($value === '') {
            if (self::isProductionEnvironment()) {
                throw new RuntimeException(
                    "Falta la variable de entorno {$name} (o {$legacyName}). " .
                    'No se permite usar la clave por defecto en producción.'
                );
            }
            return $developmentDefault;
        }
        if (self::isProductionEnvironment() && strlen($value) < 32) {
            throw new RuntimeException("La variable de entorno {$name} debe tener al menos 32 caracteres en producción.");
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
        if (self::$pdo === null) {
            $host = (string)(getenv('DB_HOST') ?: '127.0.0.1');
            $port = (string)(getenv('DB_PORT') ?: '3306');
            $dbname = (string)(getenv('DB_NAME') ?: 'app');
            $user = (string)(getenv('DB_USER') ?: 'root');
            $pass = getenv('DB_PASS') !== false ? (string)getenv('DB_PASS') : '';

            $dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset=utf8mb4";
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                // BLOQUEO REAL DE SQLi: el driver no interpola parámetros.
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_STRINGIFY_FETCHES => false,
                PDO::ATTR_PERSISTENT => false,
                PDO::ATTR_TIMEOUT => 10,
            ];

            // TiDB Cloud exige TLS en el puerto 4000. La verificación de cadena se
            // desactiva porque TiDB Cloud usa certificados gestionados; si existe
            // DB_SSL_CA legible se usa como CA explícita.
            if (getenv('DB_SSL') === '1' || $port === '4000' || str_contains($host, 'tidbcloud.com')) {
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

            self::$pdo = new PDO($dsn, $user, $pass, $options);
            // ALLOW_INVALID_DATES conserva la lectura de fechas históricas
            // '0000-00-00' de his_dl / his_dl_dt sin relajar STRICT_TRANS_TABLES.
            self::$pdo->exec("SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION,ALLOW_INVALID_DATES'");

            // En TiDB Cloud cada ALTER ... ADD COLUMN IF NOT EXISTS repetido en
            // cada request HTTP añade latencia. El esquema se crea una sola vez
            // (semáforo en /tmp) salvo que DB_AUTO_MIGRATE=1.
            $autoMigrate = getenv('DB_AUTO_MIGRATE') === '1';
            $schemaLock = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR)
                . DIRECTORY_SEPARATOR . 'planificahis_schema_v3.lock';
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
              `dias_ciclo` int NOT NULL DEFAULT 30,
              `requiere_cita` tinyint(1) DEFAULT 1,
              `activo` tinyint(1) DEFAULT 1,
              PRIMARY KEY (`codigo_dx`)
            ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
        ");
        $pdo->exec("
            INSERT IGNORE INTO `app_catalogo_metodos`
                (`codigo_dx`, `nombre_metodo`, `dias_ciclo`, `requiere_cita`, `activo`)
            VALUES
                ('90782',   'Inyectable Hormonal Mensual (Ampolla 1 mes)', 30, 1, 1),
                ('9920801', 'Administración de Inyectable Mensual', 30, 1, 1),
                ('Z304',    'Inyectable Hormonal Trimestral (Ampolla 3 meses)', 90, 1, 1),
                ('9920802', 'Administración de Inyectable Trimestral', 90, 1, 1),
                ('99208',   'Atención / Procedimiento en Planificación Familiar (99208)', 30, 1, 1),
                ('9940204', 'Orientación y Consejería en Planificación Familiar', 30, 1, 1),
                ('Z301',    'Inserción de DIU / T de Cobre (Control)', 365, 1, 1),
                ('58300',   'Inserción de DIU', 365, 1, 1),
                ('11981',   'Implante Subdérmico (Control)', 1095, 1, 1),
                ('Z300',    'Consejería General sin Método Activo', 15, 1, 1)
        ");

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
            "ALTER TABLE `pacientes_sin_metodo` ADD COLUMN IF NOT EXISTS `cod_estab` varchar(9) NULL DEFAULT NULL AFTER `codpsal_obstetra`",
            "ALTER TABLE `pacientes_sin_metodo` ADD COLUMN IF NOT EXISTS `atencion_99208` tinyint(1) NOT NULL DEFAULT 0 AFTER `cod_estab`",
            "ALTER TABLE `auditoria_seguridad_app` ADD COLUMN IF NOT EXISTS `actor_estab` varchar(9) NOT NULL DEFAULT '' AFTER `actor_dni`",
            "ALTER TABLE `auditoria_seguridad_app` ADD COLUMN IF NOT EXISTS `plataforma` varchar(30) NOT NULL DEFAULT 'Web Desktop' AFTER `ip`",
            "ALTER TABLE `auditoria_seguridad_app` ADD COLUMN IF NOT EXISTS `prev_hash` char(64) NOT NULL DEFAULT '' AFTER `plataforma`",
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
    // SESIONES FIRMADAS HMAC-SHA256 + EXPIRACIÓN POR INACTIVIDAD
    // ========================================================================
    public static function createSessionToken(string $dni, string $codEstab, string $platform, int $ttlSeconds = 28800): string
    {
        $now = time();
        $payload = [
            'v' => 1,
            'dni' => $dni,
            'estab' => $codEstab,
            'iat' => $now,
            'exp' => $now + $ttlSeconds,
            'nonce' => bin2hex(random_bytes(16)),
            'platform' => $platform,
        ];
        $encoded = self::base64UrlEncode(json_encode($payload, JSON_UNESCAPED_SLASHES) ?: '');
        $signature = hash_hmac('sha256', 'ph1.' . $encoded, self::sessionSecret());
        $token = 'ph1.' . $encoded . '.' . $signature;

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
        return $token;
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $data): string
    {
        $pad = strlen($data) % 4;
        if ($pad) {
            $data .= str_repeat('=', 4 - $pad);
        }
        return base64_decode(strtr($data, '-_', '+/'), true) ?: '';
    }

    /**
     * Valida el Bearer Token y devuelve la sesión. NUNCA devuelve una sesión demo
     * cuando falta el token: todo endpoint clínico debe fallar con 401.
     *
     * @return array<string, mixed>|null
     */
    public static function authenticateSession(?string $requiredPlatform = null): ?array
    {
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        if (!is_string($auth) || trim($auth) === '') {
            // Respaldo para Apache/XAMPP y PHP-FPM, donde la cabecera no
            // siempre llega a $_SERVER.
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
        if (!preg_match('/^Bearer\s+(ph1\.[A-Za-z0-9\-_\.]+)$/', trim($auth), $m)) {
            return null;
        }
        $token = $m[1];
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }
        [, $encoded, $signature] = $parts;
        $expected = hash_hmac('sha256', 'ph1.' . $encoded, self::sessionSecret());
        if (!hash_equals($expected, $signature)) {
            return null;
        }
        $payload = json_decode(self::base64UrlDecode($encoded), true);
        if (!is_array($payload) || ($payload['v'] ?? 0) !== 1 || (int)($payload['exp'] ?? 0) < time()) {
            return null;
        }
        $now = time();
        $pdo = self::getConnection();
        $stmt = $pdo->prepare("
            SELECT * FROM app_sesiones
            WHERE token_hash = :hash AND revoked = 0
            LIMIT 1
        ");
        $stmt->execute([':hash' => hash('sha256', $token)]);
        $row = $stmt->fetch();
        if (!$row) {
            return null;
        }
        // Expiración absoluta (8 h) y por inactividad (30 min).
        if ((int)$row['expires_at'] < $now || ($now - (int)$row['last_activity']) > 1800) {
            $pdo->prepare('UPDATE app_sesiones SET revoked = 1 WHERE token_hash = :hash')
                ->execute([':hash' => hash('sha256', $token)]);
            return null;
        }
        $pdo->prepare('UPDATE app_sesiones SET last_activity = :now WHERE token_hash = :hash')
            ->execute([':now' => $now, ':hash' => hash('sha256', $token)]);

        $platform = $requiredPlatform ?: ($row['plataforma'] ?? 'Web Desktop');
        return [
            'token' => $token,
            'dni' => (string)$row['dni'],
            'cod_estab' => (string)$row['cod_estab'],
            'estab_nombre' => hospital_nombre_establecimiento((string)$row['cod_estab']),
            'platform' => $platform,
            'expires_at' => (int)$row['expires_at'],
            'last_activity' => $now,
        ];
    }

    public static function revokeSession(string $token): void
    {
        $pdo = self::getConnection();
        $pdo->prepare('UPDATE app_sesiones SET revoked = 1 WHERE token_hash = :hash')
            ->execute([':hash' => hash('sha256', $token)]);
    }

    public static function cambiarEstablecimientoSesion(string $token, string $codEstab, string $dni): void
    {
        $canonico = hospital_codigo_canonico($codEstab);
        $pdo = self::getConnection();
        $pdo->prepare('UPDATE app_sesiones SET cod_estab = :estab WHERE token_hash = :hash AND dni = :dni')
            ->execute([':estab' => $canonico, ':hash' => hash('sha256', $token), ':dni' => $dni]);
        $pdo->prepare("
            INSERT INTO app_obstetra_establecimiento (dni, cod_estab) VALUES (:dni, :estab)
            ON DUPLICATE KEY UPDATE cod_estab = VALUES(cod_estab)
        ")->execute([':dni' => $dni, ':estab' => $canonico]);
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
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
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
