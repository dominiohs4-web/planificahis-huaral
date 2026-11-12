-- ============================================================================
-- Vista de compatibilidad `establecimiento`
-- Hospital San Juan Bautista Huaral · Red de Salud Huaral-Chancay
--
-- OBJETIVO
--   Dejar una vista de solo lectura sobre la tabla original `establec` sin
--   DEFINER fijo (nada de 'root'@'%') y sin filtros de otra DISA. En MySQL 8.0
--   debe ejecutarse con los privilegios del usuario que consulta (INVOKER),
--   de modo que cada instalación vea únicamente lo que sus permisos allow.
--
-- NOTA
--   La aplicación actual resuelve los 53 establecimientos desde
--   catalogo_establecimientos.php y app_catalogo_establecimientos; esta vista
--   es opcional para instalaciones que la usen en reportes externos.
--
-- Ejecutar en la base del HIS (no en la base app) con un usuario que tenga
-- CREATE VIEW. No modifica datos ni índices.
-- ============================================================================

CREATE OR REPLACE SQL SECURITY INVOKER VIEW `establecimiento` AS
SELECT *
FROM `establec`;

-- Verificación: SHOW CREATE VIEW establecimiento;
-- La salida debe incluir SQL SECURITY INVOKER y NO debe incluir DEFINER.
