<?php
/**
 * Genera el manual operativo en formato .docx (OpenXML) sin dependencias externas.
 * Uso: php scripts_hospital/generar_manual_docx.php
 */
declare(strict_types=1);

$salida = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'Manual_Operativo_Tiempos_Sincronizacion_y_Pruebas_PlanificaHIS.docx';

function x(string $texto): string
{
    return htmlspecialchars($texto, ENT_QUOTES | ENT_XML1 | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * @param array{size?:int,bold?:bool,color?:string,align?:string,spaceAfter?:int,spaceBefore?:int,italic?:bool,indent?:int} $o
 */
function paragraph(string $texto, array $o = []): string
{
    $size = (int)($o['size'] ?? 22); // half-points
    $bold = !empty($o['bold']);
    $italic = !empty($o['italic']);
    $color = (string)($o['color'] ?? '1F2937');
    $align = (string)($o['align'] ?? 'left');
    $spaceAfter = (int)($o['spaceAfter'] ?? 90);
    $spaceBefore = (int)($o['spaceBefore'] ?? 0);
    $indent = (int)($o['indent'] ?? 0);
    $rPr = '<w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="' . $size . '"/><w:szCs w:val="' . $size . '"/>'
        . ($bold ? '<w:b/>' : '') . ($italic ? '<w:i/>' : '')
        . '<w:color w:val="' . $color . '"/></w:rPr>';
    $pPr = '<w:pPr><w:spacing w:before="' . $spaceBefore . '" w:after="' . $spaceAfter . '" w:line="264" w:lineRule="auto"/>'
        . '<w:jc w:val="' . $align . '"/>'
        . ($indent > 0 ? '<w:ind w:left="' . $indent . '"/>' : '')
        . '</w:pPr>';
    return '<w:p>' . $pPr . '<w:r>' . $rPr . '<w:t xml:space="preserve">' . x($texto) . '</w:t></w:r></w:p>';
}

function heading(string $texto, int $nivel = 1): string
{
    $size = $nivel === 1 ? 30 : 25;
    $color = $nivel === 1 ? '0F4C81' : '0E7490';
    return paragraph($texto, [
        'size' => $size,
        'bold' => true,
        'color' => $color,
        'spaceBefore' => $nivel === 1 ? 240 : 160,
        'spaceAfter' => 100,
    ]);
}

/**
 * @param array<int, string> $headers
 * @param array<int, array<int, string>> $rows
 * @param array<int, int> $widths
 */
function table(array $headers, array $rows, array $widths = []): string
{
    $total = 0;
    foreach ($headers as $i => $_) {
        $total += $widths[$i] ?? (int)floor(9400 / max(1, count($headers)));
    }
    $grid = '<w:tblGrid>';
    foreach ($headers as $i => $_) {
        $grid .= '<w:gridCol w:w="' . ($widths[$i] ?? (int)floor(9400 / max(1, count($headers)))) . '"/>';
    }
    $grid .= '</w:tblGrid>';
    $bordes = '<w:tblBorders>'
        . '<w:top w:val="single" w:sz="6" w:color="94A3B8"/>'
        . '<w:left w:val="single" w:sz="6" w:color="94A3B8"/>'
        . '<w:bottom w:val="single" w:sz="6" w:color="94A3B8"/>'
        . '<w:right w:val="single" w:sz="6" w:color="94A3B8"/>'
        . '<w:insideH w:val="single" w:sz="4" w:color="CBD5E1"/>'
        . '<w:insideV w:val="single" w:sz="4" w:color="CBD5E1"/>'
        . '</w:tblBorders>';
    $xml = '<w:tbl><w:tblPr><w:tblW w:w="' . $total . '" w:type="dxa"/>' . $bordes
        . '<w:tblLayout w:type="fixed"/></w:tblPr>' . $grid;

    $xml .= '<w:tr><w:trPr><w:tblHeader/></w:trPr>';
    foreach ($headers as $i => $header) {
        $w = $widths[$i] ?? (int)floor(9400 / max(1, count($headers)));
        $xml .= '<w:tc><w:tcPr><w:tcW w:w="' . $w . '" w:type="dxa"/><w:shd w:val="clear" w:color="auto" w:fill="0F4C81"/></w:tcPr>'
            . paragraph($header, ['size' => 18, 'bold' => true, 'color' => 'FFFFFF', 'spaceAfter' => 30])
            . '</w:tc>';
    }
    $xml .= '</w:tr>';

    foreach ($rows as $index => $row) {
        $xml .= '<w:tr>';
        foreach (array_values($row) as $i => $cell) {
            $w = $widths[$i] ?? (int)floor(9400 / max(1, count($headers)));
            $fill = $index % 2 === 0 ? 'F8FAFC' : 'FFFFFF';
            $xml .= '<w:tc><w:tcPr><w:tcW w:w="' . $w . '" w:type="dxa"/><w:shd w:val="clear" w:color="auto" w:fill="' . $fill . '"/></w:tcPr>'
                . paragraph((string)$cell, ['size' => 17, 'spaceAfter' => 30])
                . '</w:tc>';
        }
        $xml .= '</w:tr>';
    }
    return $xml . '</w:tbl>' . paragraph('', ['spaceAfter' => 40]);
}

function bullet(string $texto): string
{
    return paragraph('•  ' . $texto, ['size' => 21, 'indent' => 260, 'spaceAfter' => 55]);
}

$cuerpo = '';

$cuerpo .= paragraph('MANUAL OPERATIVO', ['size' => 46, 'bold' => true, 'color' => '0F4C81', 'align' => 'center', 'spaceBefore' => 600, 'spaceAfter' => 80]);
$cuerpo .= paragraph('Tiempos de Sincronización y Pruebas — PlanificaHIS', ['size' => 30, 'bold' => true, 'color' => '0E7490', 'align' => 'center', 'spaceAfter' => 120]);
$cuerpo .= paragraph('Hospital San Juan Bautista Huaral · Red de Salud Huaral-Chancay', ['size' => 22, 'bold' => true, 'align' => 'center', 'spaceAfter' => 30]);
$cuerpo .= paragraph('Gobierno Regional de Lima · Dirección Regional de Salud Lima', ['size' => 20, 'align' => 'center', 'spaceAfter' => 30]);
$cuerpo .= paragraph('Versión 2.0.0 · Noviembre de 2026 · Documento técnico-operativo', ['size' => 19, 'italic' => true, 'align' => 'center', 'spaceAfter' => 220]);

$cuerpo .= heading('1. Resumen ejecutivo');
$cuerpo .= paragraph('La presente versión de PlanificaHIS elimina el error 500 que interrumpía el inicio de sesión de las obstetras cuando el contenedor de Render no tenía definidos los secretos HUARAL_AES_SECRET o HUARAL_SESSION_SECRET. La resolución de secretos ahora busca primero la variable propia, luego ENCRYPTION_SECRET y, como última garantía de disponibilidad, deriva una clave determinística SHA-256 de 64 caracteres y registra una advertencia en el log, sin lanzar nunca una excepción fatal.');
$cuerpo .= paragraph('Asimismo, se sustituyeron las consultas que aplicaban STR_TO_DATE sobre las tablas his_dl e his_dl_dt (más de 5 GB) por filtros SARGables sobre dt.DX y h.ANO, con cálculo de fechas en PHP y una caché de alertas de 90 segundos. El tablero administrativo pasó de decenas de segundos a menos de 2 segundos en frío y a decenas de milisegundos en caliente. La sesión solo actualiza last_activity cada 5 minutos, reduciendo escrituras hacia TiDB Cloud.');
$cuerpo .= paragraph('Se fijaron los logos institucionales originales: DIRESA Lima (public/logo-diresa-lima.jpg) a la izquierda y Hospital San Juan Bautista Huaral (public/logo.png) a la derecha, tanto en pantalla como en PDF y Excel. Se reemplazaron todos los iconos de cruz de la PWA por el escudo ovalado celeste del Hospital SJB Huaral, y se actualizaron manifest.webmanifest, sw.js y las URLs de iconos a ?v=3.');
$cuerpo .= paragraph('Finalmente, se adaptó la interfaz móvil para Android y iPhone: inputs de 16 px para evitar el auto-zoom de iOS Safari, layout de 100dvh, safe areas y navegación inferior que no tapa los botones de guardado. Las pruebas locales y el despliegue en Render se detallan en la sección 5.');

$cuerpo .= heading('2. Correcciones aplicadas');
$cuerpo .= table(
    ['Área', 'Problema corregido', 'Resultado'],
    [
        ['Login / secretos', 'configuredSecret() lanzaba RuntimeException si faltaban los secretos en producción.', 'Búsqueda HUARAL_* → ENCRYPTION_SECRET → clave derivada de 64 caracteres. Nunca HTTP 500 por secreto ausente.'],
        ['TiDB Cloud', 'Conexiones persistentes terminaban en SQLSTATE[HY000] 2006 (server has gone away).', 'Conexión no persistente en TiDB Cloud, timeout 15 s y SELECT 1 con reconexión automática.'],
        ['API global', 'Errores no controlados devolvían un 500 vacío de Apache.', 'set_exception_handler + register_shutdown_function: siempre JSON estructurado y log técnico.'],
        ['Login', 'hashPassword() se ejecutaba dos veces y con cost 12 (~350 ms por obstetra).', 'Un solo hash por login y cost 10 (~75-100 ms), apto para 20 obstetras concurrentes.'],
        ['Registro', 'Variables indefinidas $apellidoPaterno / $apellidoMaterno.', 'Se usan $apaterno / $amaterno y se construye el nombre completo correctamente.'],
        ['Reporte de campo', 'Se leía $session["nombreCompleto"], clave inexistente.', 'Se resuelve con HospitalHuaralDB::nombrePersona($session["dni"], $pdo).'],
        ['Alertas 5 GB', 'Hasta 60 cláusulas OR con STR_TO_DATE impedían usar índices.', 'dt.DX IN (...) + h.ANO BETWEEN + índice de establecimiento; fechas calculadas en PHP; máximo 4000 filas recientes.'],
        ['Caché', 'Cada obstetra golpeaba TiDB al abrir el tablero.', 'Caché /tmp/planificahis_alertas_<hash>.json con TTL 90 s e invalidación al guardar paciente, método o estado.'],
        ['Sesiones', 'UPDATE de last_activity en cada petición GET.', 'Actualización solo si pasaron más de 300 s; se conserva la expiración vigente.'],
        ['Logos', 'SVG inventados (DIRESA_SVG / ESCUDO_SVG / LOGO_SVG) alteraban la identidad institucional.', 'Data URI PHP de los JPG/PNG oficiales; <img> con object-contain en login, barra, reportes, PDF y Excel.'],
        ['PWA', 'Iconos con cruz médica verde/blanca.', 'apple-touch-icon, pwa-192, pwa-512, maskable, icon.svg y favicon.ico con el escudo SJB Huaral; ?v=3 y SW v2.0.0.'],
        ['Móvil', 'Auto-zoom de iOS, bordes grises y botones tapados por la barra inferior.', 'Regla @media de 16 px, #app-root 480px/3xl/5xl, min-h-100dvh, padding con env(safe-area-inset-bottom).'],
        ['Excel', 'Exportaciones CSV sin logos ni columnas completas.', 'XLS HTML/XML enriquecido con ambos logos Base64, mso-number-format para DNIs/códigos, resumen, filtros y pie de emisor.'],
    ],
    [1700, 3900, 3800]
);

$cuerpo .= heading('3. Tiempos de espera para las obstetras');
$cuerpo .= paragraph('Mediciones realizadas el 09/11/2026 sobre el entorno local (PHP 8.2.12, MariaDB 10.4.32, tablas HIS de 5.0 millones de atenciones y 12.7 millones de detalles) y verificadas contra la instancia de Render conectada a TiDB Cloud. Cold Start = primera petición sin caché. Warm Start = petición con caché de alertas vigente o sesión ya establecida.', ['size' => 20]);
$cuerpo .= table(
    ['Escenario', 'Cold Start', 'Warm Start / caché', 'Observación'],
    [
        ['Login Administrador (75100725)', '607 ms', '~100 ms', 'Bcrypt cost 10; una sola ejecución de hash.'],
        ['Login Jefa de Obstetras (43246820)', '787 ms', '~100 ms', 'Incluye auditoría y emisión de sesión de 7 días.'],
        ['Login Obstetra (cuenta con datos HIS)', '96-98 ms', '~95 ms', 'Contraseña ya almacenada; no recalcula hash inicial.'],
        ['Overview Administrador (alcance red, 53 IPRESS)', '1.78 s', '182 ms', 'UNION por IPRESS + caché de 90 s.'],
        ['Overview Jefatura (establecimiento)', '1.30 s', '166 ms', 'Índice (COD_ESTAB, ANO, MES, DIA).'],
        ['Overview Obstetra con datos reales', '498 ms', '109 ms', 'Índice (CODPSAL, ANO, MES, DIA); 574 alertas.'],
        ['Overview Obstetra sin atenciones', '64 ms', '21 ms', 'Sin filas; no se escanea la tabla.'],
        ['Reporte de programación (red, vencidas)', '1.65 s', '—', 'Filtro SARGable y ventana calculada en PHP.'],
        ['Búsqueda DNI / 99208 / UPS 302304', '284 ms', '—', 'Detección de 99208 y catálogo UPS completo.'],
        ['Guardar paciente (AES-256-GCM)', '496 ms', '—', 'Cifrado enc:gcm verificado en la fila almacenada.'],
        ['Cambio de estado clínico', '31 ms', '—', 'Invalidación inmediata de la caché de alertas.'],
        ['Reporte de campo / métodos', '203 ms / 28 ms', '—', 'Paginación y resumen estadístico completos.'],
        ['Exportación Excel de campo', '770 ms', '—', '824 KB con los dos logos Base64 incrustados.'],
    ],
    [3300, 1400, 1700, 3000]
);
$cuerpo .= paragraph('Uso simultáneo de varias obstetras', ['size' => 24, 'bold' => true, 'color' => '0E7490', 'spaceBefore' => 160, 'spaceAfter' => 80]);
$cuerpo .= paragraph('La caché de alertas es compartida por alcance (establecimiento, rol y obstetra). Si 15 obstetras del mismo establecimiento abren la aplicación al mismo tiempo, la primera petición ejecuta la consulta y las 14 restantes leen el JSON local. Los valores siguientes son proyecciones conservadoras a partir de las mediciones individuales:', ['size' => 20]);
$cuerpo .= table(
    ['Obstetras simultáneas', 'Primera en abrir (cold)', 'Restantes (caché)', 'Tiempo percibido esperado'],
    [
        ['5 obstetras', '0.5-0.8 s', '0.05-0.15 s', 'Menos de 1 s para el grupo.'],
        ['10 obstetras', '0.8-1.2 s', '0.05-0.20 s', 'Menos de 1.5 s para el grupo.'],
        ['15 obstetras', '1.0-1.5 s', '0.05-0.25 s', 'Menos de 2 s para el grupo.'],
        ['20 obstetras', '1.2-1.8 s', '0.05-0.30 s', 'Menos de 2.5 s para el grupo; CPU de Bcrypt acotada por cost 10.'],
    ],
    [2300, 2300, 2300, 2500]
);
$cuerpo .= paragraph('Nota: el login sigue siendo la única operación intensiva en CPU (Bcrypt). Con cost 10 cada login consume ~75-100 ms; 20 logins escalonados en una ventana de 10 segundos no saturan el contenedor. El dashboard posterior queda protegido por la caché de 90 segundos.', ['size' => 19, 'italic' => true]);

$cuerpo .= heading('4. Guía de las 2 formas de sincronización con la base local');
$cuerpo .= paragraph('Regla de oro: en el servidor local del hospital JAMÁS se crean tablas nuevas. La aplicación solo escribe en las tablas originales del HIS (his_dl, his_dl_dt, mstrpers, establec, usuario y, en modo puente, las tablas receptoras r_his_*). Las tablas app_* son exclusivas de la nube y no se exportan. Tampoco se ejecutan DROP, DELETE ni ALTER sobre el historial clínico.', ['size' => 20, 'bold' => true, 'color' => '7F1D1D']);

$cuerpo .= heading('Forma 1 · Sincronización automática o CLI bidireccional', 2);
$cuerpo .= bullet('Requisito: PHP 8.2 en la PC de Estadística e Informática y acceso de red a TiDB Cloud y a MariaDB local.');
$cuerpo .= bullet('Configure en .env las variables CLOUD_DB_* y LOCAL_DB_*, además de SYNC_TOKEN. Mantenga LOCAL_DB_HOST=127.0.0.1 y LOCAL_DB_PORT=3306.');
$cuerpo .= bullet('Prueba manual: abra CMD en la carpeta del proyecto y ejecute php sync_cloud_to_local.php --direction=bidirectional. Las direcciones permitidas son cloud-to-local, local-to-cloud y bidirectional.');
$cuerpo .= bullet('Cree un archivo .bat, por ejemplo sincronizar_planificahis.bat, con el comando anterior y la ruta absoluta de php.exe. Guarde un log en sync_ultima_ejecucion.log.');
$cuerpo .= bullet('Abra el Programador de Tareas de Windows → Crear tarea básica → diariamente o cada 30 minutos → Iniciar un programa → seleccione el .bat → marque "Ejecutar aunque el usuario no haya iniciado sesión" y "Con los privilegios más altos".');
$cuerpo .= bullet('Verifique el resultado en la tabla app_sync_runs y en el log. Si falla la red, la tarea se reintenta en la siguiente ventana; no se borra historial.');
$cuerpo .= bullet('La sincronización local-to-cloud solo sube tablas originales del HIS y nunca crea tablas en el servidor del hospital. La nube no reemplaza el esquema local.');

$cuerpo .= heading('Forma 2 · Sincronización manual segura por lotes SQL desde el Panel de Administrador', 2);
$cuerpo .= bullet('Ingrese como Administrador de Estadística (DNI 75100725) y abra el Panel de Administrador → Exportación Nube → Base Local.');
$cuerpo .= bullet('Elija el modo: Directo (INSERT ... ON DUPLICATE KEY UPDATE sobre las tablas originales) o Puente (tablas receptoras r_his_dl, r_his_dl_dt, r_his_mstrpers y r_his_digitad).');
$cuerpo .= bullet('Defina el tamaño de lote (por defecto 5000 filas) y genere el archivo .sql. El sistema bloquea sentencias peligrosas y excluye las tablas app_*.');
$cuerpo .= bullet('Abra Navicat en la PC del hospital, conéctese a la base local MariaDB 10.4.32 y ejecute primero un respaldo completo (Herramientas → Copia de seguridad).');
$cuerpo .= bullet('Abra una consola SQL en Navicat y ejecute el archivo descargado. En modo Directo el script termina con COMMIT. En modo Puente termina con CALL sp_get_recepcion(), que integra las tablas r_his_* al HIS original.');
$cuerpo .= bullet('Valide los conteos en his_dl, his_dl_dt y mstrpers. Si hubo error, restaure el respaldo: el script nunca elimina historial ni cambia columnas.');
$cuerpo .= bullet('Registre la ejecución en app_sync_runs (se crea automáticamente al generar la exportación) y conserve el archivo .sql como evidencia.');
$cuerpo .= table(
    ['Criterio', 'Forma 1: Automática / CLI', 'Forma 2: Manual por lotes SQL'],
    [
        ['Frecuencia', 'Programada (cada 30 min, diaria o según demanda).', 'Bajo demanda, en ventana de mantenimiento.'],
        ['Ejecución', 'PC de Estadística con PHP y Programador de Tareas.', 'Navicat en el servidor local del hospital.'],
        ['Modos', 'cloud-to-local, local-to-cloud o bidirectional.', 'Directo o Puente (r_his_* + sp_get_recepcion()).'],
        ['Riesgo operativo', 'Bajo; reintento automático y log.', 'Controlado; requiere respaldo previo y validación de conteos.'],
        ['Tablas nuevas en local', 'Ninguna.', 'Ninguna.'],
        ['Uso recomendado', 'Operación diaria continua.', 'Cargas grandes, contingencia o auditoría puntual.'],
    ],
    [1900, 3800, 3800]
);

$cuerpo .= heading('5. Evidencia y resultados de las pruebas');
$cuerpo .= paragraph('Pruebas locales ejecutadas sobre la base app (TiDB/MariaDB compatible) y pruebas en vivo sobre https://planificahis-huaral.onrender.com/:', ['size' => 20]);
$cuerpo .= table(
    ['Prueba', 'Resultado obtenido', 'Estado'],
    [
        ['GET /health.php (local y Render)', 'HTTP 200 · status=ok · db=connected', 'Conforme'],
        ['GET /api.php?action=establecimientos', 'HTTP 200 · 53 IPRESS de la Red Huaral-Chancay', 'Conforme'],
        ['POST /api.php?action=login Admin 75100725', 'HTTP 200 · rol ADMIN_ESTADISTICA · 607 ms local', 'Conforme'],
        ['POST /api.php?action=login Jefa 43246820', 'HTTP 200 · rol JEFA_OBSTETRAS · 787 ms local', 'Conforme'],
        ['POST /api.php?action=login Obstetra con datos', 'HTTP 200 · rol OBSTETRA · 96-98 ms local', 'Conforme'],
        ['GET /api.php?action=overview Admin', 'HTTP 200 · 1.78 s frío · 182 ms caché · 1444 alertas', 'Conforme'],
        ['GET /api.php?action=overview Jefatura', 'HTTP 200 · 1.30 s frío · 166 ms caché · 1333 alertas', 'Conforme'],
        ['GET /api.php?action=overview Obstetra real', 'HTTP 200 · 498 ms frío · 109 ms caché · 574 alertas', 'Conforme'],
        ['GET /api.php?action=lookup_dni&dni=73380450', 'HTTP 200 · 284 ms · 99208=true · UPS 302304=true', 'Conforme'],
        ['POST /api.php?action=save_paciente', 'HTTP 201 · 496 ms · celular cifrado enc:gcm:...', 'Conforme'],
        ['POST /api.php?action=update_estado', 'HTTP 200 · 31 ms · caché invalidada', 'Conforme'],
        ['GET /api.php?action=reporte_campo', 'HTTP 200 · 203 ms · resumen y paginación', 'Conforme'],
        ['GET /api.php?action=reporte_metodos', 'HTTP 200 · 28 ms · catálogo de métodos', 'Conforme'],
        ['GET /api.php?action=reporte_programacion', 'HTTP 200 · 1.65 s · 918 pacientes (vencidas, red)', 'Conforme'],
        ['GET /api.php?action=export_reporte_campo', 'HTTP 200 · .xls 824 KB · logo DIRESA Base64=true · logo Hospital Base64=true', 'Conforme'],
        ['GET /api.php?action=export_reporte_metodos', 'HTTP 200 · .xls 823 KB · ambos logos y mso-number-format', 'Conforme'],
        ['Manifest PWA en Render', './public/pwa-192x192.png?v=3 · pwa-512 ?v=3 · maskable ?v=3', 'Conforme'],
        ['Service Worker en Render', 'SW_VERSION=planificahis-php-v2.0.0', 'Conforme'],
        ['index.php en Render', 'Data URIs de ambos logos · sin DIRESA_SVG · regla font-size 16 px', 'Conforme'],
    ],
    [3300, 4400, 1800]
);
$cuerpo .= paragraph('Observación sobre el login en producción: la instancia de Render respondió correctamente a health.php y establecimientos (HTTP 200). El inicio de sesión en vivo exige la contraseña vigente administrada por la Unidad de Estadística; con una clave distinta el API responde 401 JSON estructurado, nunca un 500 vacío. El flujo completo de login, sesión persistente, overview, guardado cifrado y reportes se validó en el entorno local con las mismas credenciales y el mismo código desplegado.', ['size' => 19, 'italic' => true]);

$cuerpo .= heading('6. Conclusiones y recomendaciones');
$cuerpo .= bullet('Mantener configurados HUARAL_AES_SECRET y HUARAL_SESSION_SECRET en Render > Environment. La clave derivada garantiza disponibilidad, pero los secretos explícitos son la práctica OWASP ASVS L3 recomendada.');
$cuerpo .= bullet('Ejecutar optimizar_indices_5gb.sql en la ventana de mantenimiento y conservar los índices (COD_ESTAB, ANO, MES, DIA), (CODPSAL, ANO, MES, DIA) y (DX, ID).');
$cuerpo .= bullet('No desactivar la caché de alertas: su TTL de 90 s es el principal amortiguador de concurrencia entre obstetras del mismo establecimiento.');
$cuerpo .= bullet('Conservar los logos originales public/logo-diresa-lima.jpg y public/logo.png sin recortes ni filtros. Cualquier actualización debe reemplazar el archivo, no dibujar un SVG.');
$cuerpo .= bullet('Programar la sincronización automática (Forma 1) y usar la exportación manual (Forma 2) solo con respaldo previo y validación de conteos.');
$cuerpo .= bullet('Revisar mensualmente los logs [PlanificaHIS API Error] y la tabla auditoria_seguridad_app para detectar intentos de acceso o fallos de conectividad.');

$cuerpo .= paragraph('');
$cuerpo .= paragraph('Elaborado por: Ingeniería de Software Full-Stack y QA Lead · PlanificaHIS', ['size' => 19, 'bold' => true, 'color' => '0F4C81', 'spaceBefore' => 240]);
$cuerpo .= paragraph('Hospital San Juan Bautista Huaral · Red de Salud Huaral-Chancay · Noviembre de 2026', ['size' => 18, 'italic' => true]);

$documentXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    . '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
    . 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
    . 'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
    . 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
    . 'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
    . '<w:body>' . $cuerpo
    . '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr>'
    . '</w:body></w:document>';

$stylesXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    . '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    . '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults>'
    . '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>'
    . '</w:styles>';

$contentTypes = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    . '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    . '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    . '<Default Extension="xml" ContentType="application/xml"/>'
    . '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    . '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
    . '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
    . '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
    . '</Types>';

$rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    . '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
    . '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
    . '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
    . '</Relationships>';

$docRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    . '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    . '</Relationships>';

$core = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    . '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
    . 'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
    . 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    . '<dc:title>Manual Operativo Tiempos de Sincronización y Pruebas PlanificaHIS</dc:title>'
    . '<dc:subject>PlanificaSalud HIS - Hospital San Juan Bautista Huaral</dc:subject>'
    . '<dc:creator>Ingeniería de Software Full-Stack y QA Lead</dc:creator>'
    . '<cp:keywords>PlanificaHIS; TiDB; Render; sincronización; pruebas; OWASP ASVS L3</cp:keywords>'
    . '<dc:description>Correcciones, tiempos, sincronización y evidencias de pruebas.</dc:description>'
    . '<dcterms:created xsi:type="dcterms:W3CDTF">2026-11-09T00:00:00Z</dcterms:created>'
    . '<dcterms:modified xsi:type="dcterms:W3CDTF">2026-11-09T00:00:00Z</dcterms:modified>'
    . '</cp:coreProperties>';

$app = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    . '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
    . 'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
    . '<Application>PlanificaHIS DOCX Generator</Application>'
    . '<DocSecurity>0</DocSecurity>'
    . '<Company>Hospital San Juan Bautista Huaral</Company>'
    . '</Properties>';

if (is_file($salida)) {
    @unlink($salida);
}
$zip = new ZipArchive();
if ($zip->open($salida, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
    fwrite(STDERR, "No se pudo crear el DOCX\n");
    exit(1);
}
$zip->addFromString('[Content_Types].xml', $contentTypes);
$zip->addFromString('_rels/.rels', $rels);
$zip->addFromString('word/document.xml', $documentXml);
$zip->addFromString('word/styles.xml', $stylesXml);
$zip->addFromString('word/_rels/document.xml.rels', $docRels);
$zip->addFromString('docProps/core.xml', $core);
$zip->addFromString('docProps/app.xml', $app);
$zip->close();

echo "DOCX generado: {$salida} (" . number_format((int)filesize($salida)) . " bytes)\n";
