-- ============================================================================
-- optimizar_indices_5gb.sql
-- Hospital San Juan Bautista Huaral · Red de Salud Huaral-Chancay
-- Base histórica: bdoriginalhospital / app · MariaDB 10.4.32 · > 5 GB
--
-- OBJETIVO: consultas de validación DNI, código 99208 y UPS de Planificación
-- Familiar en menos de 50 ms, sin bloquear ni alterar columnas originales.
--
-- REGLAS:
--   - Solo CREA ÍNDICES. No modifica columnas, no borra datos, no renombra tablas.
--   - Los índices se crean solo si no existen (idempotente).
--   - Ejecutar en ventana de mantenimiento (madrugada) con respaldo previo.
--   - En MariaDB 10.4 el DDL de InnoDB es online para ADD INDEX; aun así,
--     evite ejecutarlo en hora punta de atención del hospital.
-- ============================================================================

SET NAMES utf8mb4;
SET @OLD_SQL_MODE = @@SQL_MODE;
SET SQL_MODE = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION';

-- ----------------------------------------------------------------------------
-- Procedimiento auxiliar idempotente: crea el índice solo si no existe.
-- ----------------------------------------------------------------------------
DROP PROCEDURE IF EXISTS sp_planifica_crear_indice;
DELIMITER $$
CREATE PROCEDURE sp_planifica_crear_indice(
    IN p_tabla VARCHAR(64),
    IN p_indice VARCHAR(64),
    IN p_columnas VARCHAR(255),
    IN p_tipo VARCHAR(20)
)
BEGIN
    DECLARE v_existe INT DEFAULT 0;
    DECLARE v_sql TEXT;

    SELECT COUNT(*) INTO v_existe
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = p_tabla
      AND INDEX_NAME = p_indice;

    IF v_existe = 0 THEN
        IF p_tipo = 'UNIQUE' THEN
            SET v_sql = CONCAT('CREATE UNIQUE INDEX `', p_indice, '` ON `', p_tabla, '` (', p_columnas, ')');
        ELSE
            SET v_sql = CONCAT('CREATE INDEX `', p_indice, '` ON `', p_tabla, '` (', p_columnas, ')');
        END IF;
        SET @ddl = v_sql;
        PREPARE stmt FROM @ddl;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END$$
DELIMITER ;

-- ----------------------------------------------------------------------------
-- 1. ÍNDICES OBLIGATORIOS DEL REQUERIMIENTO
-- ----------------------------------------------------------------------------

-- Búsqueda por DNI + establecimiento + UPS (validador / 99208 / Planificación Familiar)
CALL sp_planifica_crear_indice(
    'his_dl',
    'idx_his_dl_dni_estab_ups',
    '`DNI`, `COD_ESTAB`, `COD_SERVSA`',
    'INDEX'
);

-- Cruce detalle por ID y código de diagnóstico/procedimiento (99208, 90782, Z304...)
CALL sp_planifica_crear_indice(
    'his_dl_dt',
    'idx_his_dl_dt_id_dx',
    '`ID`, `DX`',
    'INDEX'
);

-- ----------------------------------------------------------------------------
-- 2. ÍNDICES COMPLEMENTARIOS PARA AGENDA Y AUDITORÍA (< 50 ms)
-- ----------------------------------------------------------------------------

-- Última atención por DNI ordenada por año/mes/día (sin OFFSET).
CALL sp_planifica_crear_indice(
    'his_dl',
    'idx_his_dl_dni_fecha',
    '`DNI`, `ANO`, `MES`, `DIA`',
    'INDEX'
);

-- Agenda por establecimiento (30/90 días) y reporte de la obstetra.
CALL sp_planifica_crear_indice(
    'his_dl',
    'idx_his_dl_estab_fecha',
    '`COD_ESTAB`, `ANO`, `MES`, `DIA`',
    'INDEX'
);

-- Búsqueda de atenciones por profesional (CODPSAL) y fecha.
CALL sp_planifica_crear_indice(
    'his_dl',
    'idx_his_dl_codpsal_fecha',
    '`CODPSAL`, `ANO`, `MES`, `DIA`',
    'INDEX'
);

-- Detalle por diagnóstico para agenda de ampollas / 99208.
CALL sp_planifica_crear_indice(
    'his_dl_dt',
    'idx_his_dl_dt_dx_id',
    '`DX`, `ID`',
    'INDEX'
);

-- Cobertura del JOIN con establecimientos por código (RIGHT(...,5)).
-- Se indexa el código completo; MariaDB puede usarlo en búsquedas por prefijo/sufijo
-- cuando el optimizador reescribe la comparación. Evite funciones en el WHERE si
-- consulta directamente por código completo.
CALL sp_planifica_crear_indice(
    'establec',
    'idx_establec_cod_estab',
    '`COD_ESTAB`',
    'INDEX'
);

-- Padrón de profesionales.
CALL sp_planifica_crear_indice(
    'mstrpers',
    'idx_mstrpers_codpsal_estab',
    '`CODPSAL`, `COD_ESTAB`',
    'INDEX'
);

-- Pacientes captadas: búsqueda por obstetra, establecimiento y estado.
-- (Tabla propia de la app, no del HIS original.)
CALL sp_planifica_crear_indice(
    'pacientes_sin_metodo',
    'idx_pacientes_obstetra_estado',
    '`codpsal_obstetra`, `estado_paciente`',
    'INDEX'
);
CALL sp_planifica_crear_indice(
    'pacientes_sin_metodo',
    'idx_pacientes_estab_fecha',
    '`cod_estab`, `fecha_registro`',
    'INDEX'
);

-- Auditoría: consultas por actor/acción/fecha y encadenamiento por id.
CALL sp_planifica_crear_indice(
    'auditoria_seguridad_app',
    'idx_auditoria_actor_accion',
    '`actor_dni`, `accion`, `fecha_hora`',
    'INDEX'
);
CALL sp_planifica_crear_indice(
    'auditoria_seguridad_app',
    'idx_auditoria_hash',
    '`hash_sha256`',
    'INDEX'
);

-- App: autenticación y sesiones multi-obstetra (tablas propias de la nube).
CALL sp_planifica_crear_indice(
    'app_usuarios',
    'idx_app_usuarios_rol_estab_activo',
    '`rol`, `cod_estab`, `activo`',
    'INDEX'
);
CALL sp_planifica_crear_indice(
    'app_sesiones',
    'idx_app_sesiones_dni_expira',
    '`dni`, `expires_at`',
    'INDEX'
);
CALL sp_planifica_crear_indice(
    'app_sesiones',
    'idx_app_sesiones_actividad',
    '`last_activity`, `expires_at`',
    'INDEX'
);

-- ----------------------------------------------------------------------------
-- 2-B. ÍNDICES COMPUESTOS OFICIALES PARA REPORTES SARGABLES (v2.1.0)
-- Usados por reporte_programacion y alertas_programaticas_datos. Permiten
-- resolver (ANO, MES, DIA) y el cruce DX -> ID sin escanear los 5 GB.
-- ----------------------------------------------------------------------------
CALL sp_planifica_crear_indice(
    'his_dl',
    'idx_his_dl_ano_mes_dia',
    '`ANO`, `MES`, `DIA`',
    'INDEX'
);
CALL sp_planifica_crear_indice(
    'his_dl',
    'idx_his_dl_estab_ano_mes_dia',
    '`COD_ESTAB`, `ANO`, `MES`, `DIA`',
    'INDEX'
);
CALL sp_planifica_crear_indice(
    'his_dl',
    'idx_his_dl_codpsal_ano_mes_dia',
    '`CODPSAL`, `ANO`, `MES`, `DIA`',
    'INDEX'
);
CALL sp_planifica_crear_indice(
    'his_dl',
    'idx_his_dl_dni_ano_mes_dia',
    '`DNI`, `ANO`, `MES`, `DIA`',
    'INDEX'
);
CALL sp_planifica_crear_indice(
    'his_dl_dt',
    'idx_his_dl_dt_dx_id',
    '`DX`, `ID`',
    'INDEX'
);
CALL sp_planifica_crear_indice(
    'his_dl_dt',
    'idx_his_dl_dt_id_dx',
    '`ID`, `DX`',
    'INDEX'
);
-- Cobertura del cruce DX -> ID -> DNI/fecha sin leer la fila clustered de 5 GB.
CALL sp_planifica_crear_indice(
    'his_dl',
    'idx_his_dl_id_dni_fecha',
    '`ID`, `DNI`, `ANO`, `MES`, `DIA`',
    'INDEX'
);

-- ----------------------------------------------------------------------------
-- 3. ACTUALIZAR ESTADÍSTICAS DEL OPTIMIZADOR (sin bloquear escrituras)
-- ----------------------------------------------------------------------------
ANALYZE TABLE his_dl, his_dl_dt, establec, mstrpers, pacientes_sin_metodo, auditoria_seguridad_app;

-- ----------------------------------------------------------------------------
-- 4. CONSULTAS DE REFERENCIA CON LIMIT ESTRICTO
-- ----------------------------------------------------------------------------
-- 4.1 Última atención de una paciente (LIMIT 1):
-- SELECT h.ID, h.DNI, h.COD_ESTAB, h.ANO, h.MES, h.DIA, h.CODPSAL
-- FROM his_dl h
-- WHERE h.DNI = :dni
-- ORDER BY h.ANO DESC, h.MES DESC, h.DIA DESC
-- LIMIT 1;
--
-- 4.2 Verificación del código 99208 (LIMIT 5):
-- SELECT h.ID, h.DNI, h.COD_ESTAB, h.DIA, h.MES, h.ANO, h.fecha_reg,
--        dt.DX, dt.TDX, dt.LDX, dt.fecha_reg AS fecha_dx
-- FROM his_dl h
-- INNER JOIN his_dl_dt dt ON dt.ID = h.ID
-- WHERE h.DNI = :dni AND TRIM(dt.DX) = '99208'
-- ORDER BY h.ANO DESC, h.MES DESC, h.DIA DESC
-- LIMIT 5;
--
-- 4.3 UPS Planificación Familiar en el establecimiento de la obstetra (LIMIT 20):
-- SELECT h.ID, h.COD_ESTAB, h.COD_SERVSA, h.CODPSAL, h.ANO, h.MES, h.DIA,
--        dt.DX, dt.TDX, dt.LDX
-- FROM his_dl h
-- INNER JOIN his_dl_dt dt ON dt.ID = h.ID
-- WHERE h.DNI = :dni
--   AND h.COD_ESTAB = :cod_estab
--   AND (h.COD_SERVSA = '302304' OR dt.DX IN ('99208','90782','Z304','Z301','Z300'))
-- ORDER BY h.ANO DESC, h.MES DESC, h.DIA DESC
-- LIMIT 20;
--
-- 4.4 Agenda de ampollas (LIMIT 40), nunca full scan:
-- SELECT h.ID, h.DNI, h.COD_ESTAB, h.ANO, h.MES, h.DIA, dt.DX
-- FROM his_dl h
-- INNER JOIN his_dl_dt dt ON dt.ID = h.ID
-- WHERE h.COD_ESTAB = :cod_estab
--   AND dt.DX IN ('90782','Z304','Z301','99208','Z300')
--   AND h.ANO >= YEAR(CURDATE()) - 1
-- ORDER BY h.ANO DESC, h.MES DESC, h.DIA DESC
-- LIMIT 40;
--
-- 4.5 NUNCA ejecutar en producción:
--        SELECT * FROM his_dl;                 -- 5 GB sin LIMIT
--        SELECT * FROM his_dl_dt;              -- sin LIMIT
--        consultas con OFFSET alto (LIMIT 100000, 50)
--     Use siempre paginación por keyset: WHERE ID > :ultimo_id ORDER BY ID LIMIT 500.

DROP PROCEDURE IF EXISTS sp_planifica_crear_indice;

SET SQL_MODE = @OLD_SQL_MODE;

-- ============================================================================
-- FIN DEL SCRIPT DE INDEXACIÓN
-- ============================================================================
