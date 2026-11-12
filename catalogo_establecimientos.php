<?php
/**
 * catalogo_establecimientos.php
 * Catálogo oficial IPRESS / RENIPRESS — Red de Salud Huaral-Chancay (53 establecimientos).
 * Fuente: Establecimientos.xlsx.
 *
 * IMPORTANTE: este archivo es de solo lectura. No modifica ni elimina columnas de
 * las tablas originales del hospital (`his_dl`, `his_dl_dt`, `mstrpers`, `establec`, etc.).
 */
declare(strict_types=1);

if (!function_exists('hospital_establecimientos')) {
    /**
     * @return array<int, array<string, string>>
     */
    function hospital_establecimientos(): array
    {
        static $catalogo = null;
        if ($catalogo !== null) {
            return $catalogo;
        }

        $base = [
            'DESC_RED' => 'RED DE SALUD HUARAL - CHANCAY',
            'COD_DISA' => '15',
            'COD_RED' => '06',
        ];
        $ubigeo = [
            'HUARAL' => '150601',
            'ATAVILLOS ALTO' => '150602',
            'ATAVILLOS BAJO' => '150603',
            'AUCALLAMA' => '150604',
            'CHANCAY' => '150605',
            'IHUARI' => '150606',
            'LAMPIAN' => '150607',
            'PACARAOS' => '150608',
            'SAN MIGUEL DE ACOS' => '150609',
            'SANTA CRUZ DE ANDAMARCA' => '150610',
            'SUMBILCA' => '150611',
            'VEINTISIETE DE NOVIEMBRE' => '150612',
        ];

        $e = static function (
            string $codEstab,
            string $descEstab,
            string $categoria,
            string $distrito,
            string $codIpress,
            string $codMic,
            ?string $codIpressAlt = null
        ) use ($base, $ubigeo): array {
            $row = [
                'COD_ESTAB' => $codEstab,
                'COD_IPRESS' => $codIpress,
                'DESC_ESTAB' => $descEstab,
                'CATEGORIA' => $categoria,
                'DISTRITO' => $distrito,
                'UBIGEO' => $ubigeo[$distrito],
                'DESC_RED' => $base['DESC_RED'],
                'DESC_MICRO' => 'MICRORED ' . $distrito,
                'COD_DISA' => $base['COD_DISA'],
                'COD_RED' => $base['COD_RED'],
                'COD_MIC' => $codMic,
            ];
            if ($codIpressAlt !== null) {
                $row['COD_IPRESS_ALT'] = $codIpressAlt;
            }
            return $row;
        };

        $catalogo = [
            // HUARAL (12)
            $e('000005481', 'HOSPITAL DE APOYO HUARAL / SAN JUAN BAUTISTA', 'II-2', 'HUARAL', '000007637', '01', '000005481'),
            $e('000005831', 'C.S. BASE HUARAL', 'I-3', 'HUARAL', '000005831', '01'),
            $e('000005833', 'C.S. EL TRÉBOL', 'I-3', 'HUARAL', '000005833', '01'),
            $e('000005826', 'C.S. LA QUERENCIA', 'I-3', 'HUARAL', '000005826', '01'),
            $e('000005827', 'P.S. TÚPAC AMARU', 'I-2', 'HUARAL', '000005827', '01'),
            $e('000005828', 'P.S. CABUYAL', 'I-2', 'HUARAL', '000005828', '01'),
            $e('000005829', 'P.S. HUERTA MARGARET', 'I-2', 'HUARAL', '000005829', '01'),
            $e('000005832', 'P.S. JECUÁN', 'I-2', 'HUARAL', '000005832', '01'),
            $e('000005830', 'P.S. CENTENARIO HUACHO CHICO', 'I-2', 'HUARAL', '000005830', '01'),
            $e('000007188', 'P.S. LUMBRA', 'I-1', 'HUARAL', '000007188', '01'),
            $e('000007189', 'P.S. CUYO', 'I-1', 'HUARAL', '000007189', '01'),
            $e('000010937', 'P.S. CONTIGO PERÚ', 'I-2', 'HUARAL', '000010937', '01'),

            // ATAVILLOS ALTO (5)
            $e('000005586', 'C.S. PIRCA', 'I-2', 'ATAVILLOS ALTO', '000005586', '02'),
            $e('000005587', 'P.S. PASAC', 'I-1', 'ATAVILLOS ALTO', '000005587', '02'),
            $e('000007195', 'P.S. CHISQUE', 'I-1', 'ATAVILLOS ALTO', '000007195', '02'),
            $e('000005588', 'P.S. BAÑOS', 'I-1', 'ATAVILLOS ALTO', '000005588', '02'),
            $e('000005589', 'P.S. HUAROQUÍN', 'I-1', 'ATAVILLOS ALTO', '000005589', '02'),

            // ATAVILLOS BAJO (4)
            $e('000005578', 'C.S. HUAYOPAMPA', 'I-3', 'ATAVILLOS BAJO', '000005578', '03'),
            $e('000005579', 'P.S. LA PERLA', 'I-2', 'ATAVILLOS BAJO', '000005579', '03'),
            $e('000007208', 'P.S. PALLAC', 'I-1', 'ATAVILLOS BAJO', '000007208', '03'),
            $e('000005580', 'P.S. LA FLORIDA', 'I-1', 'ATAVILLOS BAJO', '000005580', '03'),

            // IHUARI (5)
            $e('000005593', 'P.S. HUACHINGA', 'I-1', 'IHUARI', '000005593', '04'),
            $e('000005594', 'P.S. OTEC', 'I-1', 'IHUARI', '000005594', '04'),
            $e('000005595', 'P.S. IHUARÍ', 'I-2', 'IHUARI', '000005595', '04'),
            $e('000005596', 'P.S. YUNGUY', 'I-3', 'IHUARI', '000005596', '04'),
            $e('000005597', 'P.S. ÑAUPAY', 'I-2', 'IHUARI', '000005597', '04'),

            // LAMPIAN (2)
            $e('000005581', 'P.S. LAMPIÁN', 'I-1', 'LAMPIAN', '000005581', '05'),
            $e('000010936', 'P.S. CANCHAPILCA', 'I-1', 'LAMPIAN', '000010936', '05'),

            // PACARAOS (4)
            $e('000005590', 'C.S. PACARAOS', 'I-3', 'PACARAOS', '000005590', '06'),
            $e('000007190', 'P.S. VISCAS', 'I-1', 'PACARAOS', '000007190', '06'),
            $e('000007193', 'P.S. RAVIRA', 'I-1', 'PACARAOS', '000007193', '06'),
            $e('000005591', 'P.S. VICHAYCOCHA', 'I-2', 'PACARAOS', '000005591', '06'),

            // SAN MIGUEL DE ACOS (2)
            $e('000005582', 'C.S. ACOS', 'I-3', 'SAN MIGUEL DE ACOS', '000005582', '07'),
            $e('000005583', 'P.S. HUASCOY', 'I-1', 'SAN MIGUEL DE ACOS', '000005583', '07'),

            // SANTA CRUZ DE ANDAMARCA (3)
            $e('000005592', 'C.S. SANTA CRUZ DE ANDAMARCA', 'I-2', 'SANTA CRUZ DE ANDAMARCA', '000005592', '08'),
            $e('000007194', 'P.S. SANTA CATALINA', 'I-1', 'SANTA CRUZ DE ANDAMARCA', '000007194', '08'),
            $e('000007196', 'P.S. CHAUCA', 'I-1', 'SANTA CRUZ DE ANDAMARCA', '000007196', '08'),

            // SUMBILCA (4)
            $e('000005584', 'C.S. SUMBILCA', 'I-1', 'SUMBILCA', '000005584', '09'),
            $e('000007191', 'P.S. RAUMA', 'I-1', 'SUMBILCA', '000007191', '09'),
            $e('000007192', 'P.S. HUÁNDARO', 'I-1', 'SUMBILCA', '000007192', '09'),
            $e('000010938', 'P.S. PISCOCOTO', 'I-1', 'SUMBILCA', '000010938', '09'),

            // VEINTISIETE DE NOVIEMBRE (2)
            $e('000005585', 'P.S. CARAC', 'I-1', 'VEINTISIETE DE NOVIEMBRE', '000005585', '10'),
            $e('000007209', 'P.S. COTO', 'I-1', 'VEINTISIETE DE NOVIEMBRE', '000007209', '10'),

            // CHANCAY (6)
            $e('000007638', 'HOSPITAL DE CHANCAY', 'II-2', 'CHANCAY', '000007638', '11'),
            $e('000005485', 'C.S. PERALVILLO', 'I-3', 'CHANCAY', '000005729', '11', '000005485'),
            $e('000005731', 'C.S. PEDRO CANEVARO GARAY - CHANCAYLLO', 'I-3', 'CHANCAY', '000005731', '11'),
            $e('000005730', 'P.S. PAMPA LIBRE', 'I-3', 'CHANCAY', '000005730', '11'),
            $e('000005733', 'C.S. QUEPEPAMPA', 'I-3', 'CHANCAY', '000005733', '11'),
            $e('000005732', 'P.S. CERRO LA CULEBRA', 'I-2', 'CHANCAY', '000005732', '11'),

            // AUCALLAMA (4)
            $e('000005489', 'C.S. AUCALLAMA', 'I-3', 'AUCALLAMA', '000005726', '12', '000005489'),
            $e('000005727', 'P.S. PALPA', 'I-3', 'AUCALLAMA', '000005727', '12'),
            $e('000005728', 'P.S. PASAMAYO', 'I-2', 'AUCALLAMA', '000005728', '12'),
            $e('000010990', 'P.S. CAQUI', 'I-3', 'AUCALLAMA', '000010990', '12'),
        ];

        return $catalogo;
    }

    /**
     * Alias de compatibilidad con registros antiguos de la app.
     * @return array<string, string>
     */
    function hospital_alias_establecimientos(): array
    {
        return [
            '000005482' => '000005831', // C.S. Base Huaral (código antiguo de la app)
        ];
    }

    /**
     * @return array<string, string>|null
     */
    function hospital_establecimiento(?string $codigo): ?array
    {
        $codigo = trim((string)$codigo);
        if ($codigo === '') {
            return null;
        }
        $alias = hospital_alias_establecimientos();
        $canonico = $alias[$codigo] ?? $codigo;
        foreach (hospital_establecimientos() as $est) {
            if (
                $est['COD_ESTAB'] === $canonico ||
                $est['COD_IPRESS'] === $canonico ||
                (isset($est['COD_IPRESS_ALT']) && $est['COD_IPRESS_ALT'] === $canonico)
            ) {
                return $est;
            }
        }
        return null;
    }

    function hospital_codigo_canonico(?string $codigo): string
    {
        $est = hospital_establecimiento($codigo);
        return $est['COD_ESTAB'] ?? trim((string)$codigo);
    }

    /**
     * Códigos indexables equivalentes de una IPRESS, generados 100% en PHP a
     * partir del catálogo oficial (equivalente a `app_catalogo_establecimientos`).
     *
     * Devuelve, sin funciones SQL sobre la columna:
     *   - COD_ESTAB de 9 dígitos  (ej. 000005583)
     *   - COD_IPRESS / alterno    (ej. 000005583 / 000005485)
     *   - versión de 8 dígitos    (ej. 00005583)
     *   - versión sin ceros       (ej. 5583, (string)(int)$codEstab)
     *
     * Se usa SIEMPRE dentro de `h.COD_ESTAB IN (...)` para conservar los
     * índices B-Tree del HIS y evitar `LPAD(TRIM(h.COD_ESTAB), 9, '0')`.
     *
     * @return array<int, string>
     */
    function hospital_codigos_equivalentes_catalogo(?string $codigo): array
    {
        $codigo = trim((string)$codigo);
        if ($codigo === '') {
            return [];
        }
        $centinela = strtoupper($codigo);
        if (in_array($centinela, ['ALL', 'TODOS', 'RED'], true)) {
            return [];
        }

        $est = hospital_establecimiento($codigo);
        if ($est === null) {
            // Acepta códigos cortos (ej. "5583") para llamadas antiguas.
            $digitosBuscados = preg_replace('/\D/', '', $codigo) ?? '';
            $cortoBuscado = ltrim($digitosBuscados, '0');
            foreach (hospital_establecimientos() as $candidate) {
                $cortos = [
                    ltrim((string)$candidate['COD_ESTAB'], '0'),
                    ltrim((string)$candidate['COD_IPRESS'], '0'),
                ];
                if (isset($candidate['COD_IPRESS_ALT'])) {
                    $cortos[] = ltrim((string)$candidate['COD_IPRESS_ALT'], '0');
                }
                if ($cortoBuscado !== '' && in_array($cortoBuscado, $cortos, true)) {
                    $est = $candidate;
                    break;
                }
            }
        }

        $resultado = [];
        $agregar = static function (?string $valor) use (&$resultado): void {
            $valor = trim((string)$valor);
            if ($valor === '') {
                return;
            }
            $resultado[$valor] = $valor;
            $digitos = preg_replace('/\D/', '', $valor) ?? '';
            if ($digitos !== '') {
                $sinCeros = ltrim($digitos, '0');
                if ($sinCeros === '') {
                    $sinCeros = '0';
                }
                foreach ([
                    str_pad($sinCeros, 9, '0', STR_PAD_LEFT),
                    str_pad($sinCeros, 8, '0', STR_PAD_LEFT),
                    $sinCeros,
                ] as $variante) {
                    if ($variante !== '') {
                        $resultado[$variante] = $variante;
                    }
                }
            }
        };

        $agregar($codigo);
        if ($est !== null) {
            $agregar($est['COD_ESTAB'] ?? null);
            $agregar($est['COD_IPRESS'] ?? null);
            $agregar($est['COD_IPRESS_ALT'] ?? null);
        }
        return array_values($resultado);
    }

    /**
     * Busca variantes históricas reales del establecimiento en las tablas del
     * hospital. Solo se ejecuta si hay PDO y siempre con consultas limitadas y
     * almacenadas en caché por request.
     *
     * @param array<string, string>|null $est
     * @param array<int, string> $base
     * @return array<int, string>
     */
    function hospital_variantes_establecimiento_bd(?string $codigo, ?array $est, array $base, ?PDO $pdo = null): array
    {
        static $cache = [];
        $codigo = trim((string)$codigo);
        if ($codigo === '' || !$pdo instanceof PDO) {
            return [];
        }
        $cacheKey = $codigo . '|' . (string)($est['COD_ESTAB'] ?? '');
        if (array_key_exists($cacheKey, $cache)) {
            return $cache[$cacheKey];
        }

        $resultado = [];
        $agregar = static function ($valor) use (&$resultado): void {
            $valor = trim((string)$valor);
            if ($valor !== '') {
                $resultado[] = $valor;
                $sinCeros = ltrim($valor, '0');
                if ($sinCeros !== '' && $sinCeros !== $valor) {
                    $resultado[] = $sinCeros;
                }
            }
        };

        $codEstab = trim((string)($est['COD_ESTAB'] ?? $codigo));
        $corto = ltrim($codEstab, '0');
        $ubigeo = trim((string)($est['UBIGEO'] ?? ''));
        $candidatos = array_values(array_unique(array_filter(array_map('strval', array_merge(
            $base,
            [$codigo, ltrim($codigo, '0'), $codEstab, $corto]
        )), static fn (string $v): bool => trim($v) !== '')));

        foreach (['establec', 'maestro_sys_establecimiento'] as $tabla) {
            try {
                $columnas = $pdo->query("SHOW COLUMNS FROM `{$tabla}`")->fetchAll(PDO::FETCH_COLUMN, 0);
            } catch (Throwable $e) {
                continue;
            }
            if (!$columnas) {
                continue;
            }
            $columnas = array_map('strtoupper', array_map('strval', $columnas));
            $condiciones = [];
            $params = [];
            $columnasCodigo = array_values(array_intersect(
                ['COD_ESTAB', 'COD_2000', 'CODIGO', 'COD_IPRESS', 'CODIGO_ESTAB', 'COD_ESTAB_ANT', 'COD_ESTAB_ANTIGUO'],
                $columnas
            ));
            foreach ($columnasCodigo as $columna) {
                $marcas = implode(',', array_fill(0, count($candidatos), '?'));
                $condiciones[] = "`{$columna}` IN ({$marcas})";
                $params = array_merge($params, $candidatos);
            }
            if ($ubigeo !== '' && in_array('UBIGEO', $columnas, true)) {
                $condiciones[] = '`UBIGEO` = ?';
                $params[] = $ubigeo;
            }
            if (!$condiciones) {
                continue;
            }
            try {
                $sql = "SELECT * FROM `{$tabla}` WHERE (" . implode(' OR ', $condiciones) . ') LIMIT 80';
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);
                foreach ($stmt->fetchAll() as $fila) {
                    foreach (['COD_ESTAB', 'COD_2000', 'CODIGO', 'COD_IPRESS', 'CODIGO_ESTAB', 'COD_ESTAB_ANT', 'COD_ESTAB_ANTIGUO'] as $columna) {
                        if (array_key_exists($columna, $fila)) {
                            $agregar($fila[$columna]);
                        }
                    }
                }
            } catch (Throwable $e) {
                // Tabla/columna no disponible: se conservan las variantes base.
            }
        }

        // Variantes realmente usadas por el HIS. La consulta es index-only sobre
        // idx_his_dl_estab_fecha y está acotada con LIMIT.
        try {
            $marcas = implode(',', array_fill(0, count($candidatos), '?'));
            $stmt = $pdo->prepare("SELECT DISTINCT COD_ESTAB FROM his_dl WHERE COD_ESTAB IN ({$marcas}) LIMIT 120");
            $stmt->execute($candidatos);
            foreach ($stmt->fetchAll(PDO::FETCH_COLUMN, 0) as $variante) {
                $agregar($variante);
            }
        } catch (Throwable $e) {
            // Sin acceso al HIS: no se bloquea la operación.
        }

        // Captaciones propias de la app (tabla pequeña). Aquí sí conviene buscar
        // también por dígitos finales porque almacena códigos digitados a mano.
        try {
            $condiciones = [];
            $params = [];
            $marcas = implode(',', array_fill(0, count($candidatos), '?'));
            $condiciones[] = "cod_estab IN ({$marcas})";
            $params = array_merge($params, $candidatos);
            if ($corto !== '') {
                $condiciones[] = 'cod_estab LIKE ?';
                $params[] = '%' . $corto;
            }
            $stmt = $pdo->prepare('SELECT DISTINCT cod_estab FROM pacientes_sin_metodo WHERE (' . implode(' OR ', $condiciones) . ') LIMIT 120');
            $stmt->execute($params);
            foreach ($stmt->fetchAll(PDO::FETCH_COLUMN, 0) as $variante) {
                $agregar($variante);
            }
        } catch (Throwable $e) {
            // La tabla de captación puede no existir en una instalación nueva.
        }

        $cache[$cacheKey] = array_values(array_unique(array_filter($resultado, static fn ($v): bool => trim((string)$v) !== '')));
        return $cache[$cacheKey];
    }

    /**
     * Variantes indexables de un establecimiento para his_dl.COD_ESTAB.
     *
     * El HIS histórico guarda el mismo establecimiento con código IPRESS de 9
     * dígitos, código interno de 4 dígitos o código con ceros a la izquierda.
     * Esta lista permite usar h.COD_ESTAB IN (...) sin RIGHT(TRIM(...)), que
     * invalidaba el índice compuesto idx_his_dl_dni_estab_ups.
     *
     * @return array<int, string>
     */
    function hospital_codigos_busqueda_establecimiento(?string $codigo, ?PDO $pdo = null): array
    {
        static $cache = [];
        $codigo = trim((string)$codigo);
        if ($codigo === '') {
            return [];
        }
        $cacheKey = $codigo . '|' . ($pdo instanceof PDO ? spl_object_id($pdo) : '0');
        if (array_key_exists($cacheKey, $cache)) {
            return $cache[$cacheKey];
        }

        $est = hospital_establecimiento($codigo);
        if ($est === null) {
            // Acepta también códigos cortos (ej. "5481") para llamadas antiguas.
            foreach (hospital_establecimientos() as $candidate) {
                $cortos = [
                    ltrim((string)$candidate['COD_ESTAB'], '0'),
                    ltrim((string)$candidate['COD_IPRESS'], '0'),
                ];
                if (isset($candidate['COD_IPRESS_ALT'])) {
                    $cortos[] = ltrim((string)$candidate['COD_IPRESS_ALT'], '0');
                }
                if (in_array($codigo, $cortos, true)) {
                    $est = $candidate;
                    break;
                }
            }
        }

        // Base 100% PHP desde el catálogo oficial: 9 dígitos, 8 dígitos,
        // IPRESS, alterno y sin ceros. Es la lista que viaja en el IN indexado.
        $variantes = hospital_codigos_equivalentes_catalogo($codigo);

        if (!$pdo instanceof PDO && class_exists('HospitalHuaralDB')) {
            try {
                $pdo = HospitalHuaralDB::getConnection();
            } catch (Throwable $e) {
                $pdo = null;
            }
        }
        $historicas = hospital_variantes_establecimiento_bd($codigo, $est, $variantes, $pdo);
        if ($historicas) {
            $variantes = array_values(array_unique(array_merge($variantes, $historicas)));
        }

        $cache[$cacheKey] = $variantes;
        return $variantes;
    }

    function hospital_nombre_establecimiento(?string $codigo): string
    {
        $est = hospital_establecimiento($codigo);
        return $est['DESC_ESTAB'] ?? (trim((string)$codigo) !== '' ? trim((string)$codigo) : 'SIN ESTABLECIMIENTO');
    }

    /**
     * @return array<string, array<int, array<string, string>>>
     */
    function hospital_establecimientos_por_distrito(): array
    {
        $grupos = [];
        foreach (hospital_establecimientos() as $est) {
            $grupos[$est['DISTRITO']][] = $est;
        }
        return $grupos;
    }
}
