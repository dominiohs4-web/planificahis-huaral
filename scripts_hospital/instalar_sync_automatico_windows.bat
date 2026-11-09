@echo off
chcp 65001 >nul
setlocal EnableExtensions

rem ============================================================================
rem PlanificaHIS - Instala la sincronizacion automatica cada 15 minutos.
rem Ejecute este archivo como Administrador en la PC de Estadistica.
rem ============================================================================

set "TAREA=PlanificaHIS Sync Hospital"
set "SCRIPT=%~dp0sincronizar_hospital_nube.bat"

if not exist "%SCRIPT%" (
    echo [ERROR] No se encontro "%SCRIPT%".
    pause
    exit /b 1
)

schtasks /Query /TN "%TAREA%" >nul 2>nul
if not errorlevel 1 (
    echo Eliminando tarea anterior "%TAREA%"...
    schtasks /Delete /TN "%TAREA%" /F >nul 2>nul
)

echo Creando tarea programada "%TAREA%" cada 15 minutos...
schtasks /Create /TN "%TAREA%" /TR "\"%SCRIPT%\" --silencioso" /SC MINUTE /MO 15 /F
if errorlevel 1 (
    echo.
    echo [ERROR] No se pudo crear la tarea. Abra este archivo con clic derecho
    echo         "Ejecutar como administrador" e intente nuevamente.
    pause
    exit /b 1
)

echo.
echo [OK] Tarea creada. La sincronizacion bidireccional se ejecutara cada 15 minutos.
echo      Probar ahora:  schtasks /Run /TN "%TAREA%"
echo      Ver estado:    schtasks /Query /TN "%TAREA%" /V /FO LIST
echo      Quitar tarea:  schtasks /Delete /TN "%TAREA%" /F
pause
exit /b 0
