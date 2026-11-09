@echo off
chcp 65001 >nul
setlocal EnableExtensions
cd /d "%~dp0.."

rem ============================================================================
rem PlanificaHIS - Sincronizacion incremental Hospital <-> Nube
rem - Solo tablas originales del HIS. Nunca crea tablas en el servidor local.
rem - cloud-to-local baja datos oficiales; local-to-cloud sube atenciones nuevas.
rem - Ejecutable manualmente o desde el Programador de tareas de Windows.
rem ============================================================================

set "PHP_EXE="
where php >nul 2>nul && set "PHP_EXE=php"
if not defined PHP_EXE if exist "C:\xampp\php\php.exe" set "PHP_EXE=C:\xampp\php\php.exe"
if not defined PHP_EXE (
    echo [ERROR] No se encontro PHP. Instale XAMPP o agregue php.exe al PATH.
    exit /b 9009
)

if not exist "scripts_hospital\logs" mkdir "scripts_hospital\logs"
set "LOG=scripts_hospital\logs\sync_hospital.log"

echo [%DATE% %TIME%] Inicio sincronizacion bidireccional>>"%LOG%"
"%PHP_EXE%" sync_cloud_to_local.php --direction=bidirectional --batch=500 >>"%LOG%" 2>&1
set "RC=%ERRORLEVEL%"
echo [%DATE% %TIME%] Fin de sincronizacion. Codigo=%RC%>>"%LOG%"

rem La tarea programada no debe abrir ventanas ni esperar confirmacion.
if not defined SESSIONNAME (
    exit /b %RC%
)
if /i "%~1"=="--silencioso" exit /b %RC%
echo.
echo Sincronizacion finalizada con codigo %RC%. Revise scripts_hospital\logs\sync_hospital.log
exit /b %RC%
