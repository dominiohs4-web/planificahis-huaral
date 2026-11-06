<?php
/**
 * health.php — Alias estable para el health check de Render.
 *
 * Render exige un path sin parámetros; este archivo reutiliza el endpoint
 * ?action=health de api.php (SELECT 1, sin sesión ni datos clínicos).
 */
declare(strict_types=1);

$_GET['action'] = 'health';
$_REQUEST['action'] = 'health';
require __DIR__ . '/api.php';
