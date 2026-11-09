# PlanificaHIS — Hospital San Juan Bautista Huaral

Aplicación web/PWA de captación y seguimiento de Planificación Familiar para el
Hospital San Juan Bautista Huaral y la Red Huaral-Chancay. La variante de
producción es **PHP 8.2 + Apache + MariaDB/TiDB Cloud**. El repositorio contiene
únicamente la aplicación PHP y sus recursos PWA; el prototipo React/Vite de
AI Studio fue retirado.

## Seguridad

- Autenticación con contraseña y token Bearer HMAC-SHA256. El segundo factor
  TOTP (RFC 6238) es opcional y se activa con `APP_2FA_REQUIRED=1`.
- PII cifrada con AES-256-GCM (`enc:gcm:<iv>:<tag>:<ciphertext>`).
- Consultas PDO preparadas nativas, WAF, rate limiting y auditoría SHA-256.
- Cabeceras OWASP ASVS L3, CORS restringido por `ALLOWED_ORIGIN` y HSTS.
- En producción son obligatorios `HUARAL_AES_SECRET` y
  `HUARAL_SESSION_SECRET` (mínimo 32 caracteres). `ENCRYPTION_SECRET` no se
  acepta como respaldo en producción.

## Catálogo oficial y alertas de seguimiento

- El catálogo contiene los **14 métodos oficiales HIS** (preservativos, hormonales,
  inyectables, implante, DIU, BTB, vasectomía, MELA, Billings, ritmo y días fijos)
  con sus códigos punteados y sin punto (`99208.04` / `9920804`, etc.). Las
  atenciones históricas se resuelven por alias, sin duplicar métodos.
- `dias_ciclo` define el intervalo de control de cada método y puede editarse
  desde **Reportes → Programación y Seguimiento** con rol administrador.
- Al abrir la app, el tablero y la barra superior muestran
  **🔔 Alertas de Seguimiento Programático** con los controles de **MAÑANA (+1 día)**,
  **HOY** y **VENCIDAS**, además de los botones para ver pacientes a llamar y
  descargar el Excel de la alerta.

## Roles, accesos y recuperación de clave

| Rol | DNI | Alcance |
| --- | --- | --- |
| `ADMIN_ESTADISTICA` | `75100725` | Toda la red, catálogo, accesos, auditoría y sincronización |
| `JEFA_OBSTETRAS` | `43246820` | Toda la red; puede resetear claves de obstetras |
| `OBSTETRA` | — | Solo sus propios registros y exportaciones |

- Las cuentas preactivadas se crean en `app_usuarios_accesos`; su clave inicial es
  el propio DNI o `APP_PREACTIVATED_PASSWORD`, y funcionan aunque el DNI no exista
  todavía en `his_mstrpers`.
- **¿Olvidaste tu contraseña?** valida DNI + PIN de recuperación (o los últimos
  4 dígitos del DNI/celular) + establecimiento.
- En **Perfil → Mis Datos Personales y Seguridad** cada usuaria actualiza nombres,
  celular, correo, PIN de 4 dígitos y contraseña.
- Solo `ADMIN_ESTADISTICA` administra altas, roles y estado de accesos; la jefa de
  obstetras y el administrador pueden resetear la clave de una obstetra a su DNI
  en un clic.

## Reportes oficiales

La pestaña **Reportes** incluye cuatro salidas con membrete institucional (escudo
del Gobierno Regional de Lima y logo del Hospital San Juan Bautista de Huaral):

1. **Pacientes captadas en campo/barrido** (`pacientes_sin_metodo`).
2. **Productividad diaria por obstetra**.
3. **Programación y seguimiento por método** (14 códigos HIS, filtros mañana,
   hoy, 7 días, vencidas y fecha exacta).
4. **Padrón de pacientes por llamar** (teléfono y prioridad de llamada).

Cada reporte ofrece **Descargar Excel Oficial (.xls con membrete y bordes)** e
**Imprimir / Guardar PDF Oficial** en tamaño A4 horizontal, con fecha de emisión,
periodo, establecimiento y datos del emisor.

## Ejecución local (XAMPP)

1. Copie `.env.example` a `.env` y complete los datos de la base local.
2. Coloque la carpeta en `C:\xampp\htdocs\app_planificacion`.
3. Inicie Apache y MySQL desde el panel de XAMPP.
4. Abra `http://localhost/app_planificacion/index.php`.
5. El esquema propio de la app se crea una vez por instancia. Para forzarlo en
   cada arranque use `DB_AUTO_MIGRATE=1`; en producción mantenga `0`.

## Despliegue en Render

El blueprint `render.yaml` usa el `Dockerfile` (`php:8.2-apache`), escucha en
`$PORT` y verifica `/health.php`.

Variables mínimas en Render:

| Variable | Valor |
| --- | --- |
| `APP_ENV` | `production` |
| `APP_DEMO_MODE` | `0` |
| `DB_HOST` / `DB_PORT` | host TiDB Cloud / `4000` |
| `DB_NAME` / `DB_USER` / `DB_PASS` | credenciales TiDB |
| `DB_SSL` | `1` |
| `DB_SSL_CA` | ruta o contenido del CA, si aplica |
| `DB_AUTO_MIGRATE` | `0` |
| `HUARAL_AES_SECRET` | 32+ caracteres aleatorios |
| `HUARAL_SESSION_SECRET` | 32+ caracteres aleatorios |
| `ALLOWED_ORIGIN` | URL HTTPS exacta del servicio |
| `SYNC_TOKEN` | token largo para la sincronización web |
| `APP_ADMIN_DNI` / `APP_ADMIN_NIVELID` | administrador opcional |

No ejecute migraciones ni sincronizaciones contra TiDB Cloud mientras haya una
carga masiva de datos en curso.

## PWA

- Manifest: `/manifest.webmanifest`
- Service Worker: `/sw.js` (no cachea `api.php` ni respuestas clínicas)
- Iconos: `/public/pwa-*.png`

En iPhone: Safari → Compartir → Agregar a pantalla de inicio. En Android:
Chrome → Instalar aplicación.

## Sincronización Nube ↔ Local

Ejecute en la PC de Estadística, con respaldo previo de la base local:

```bat
php sync_cloud_to_local.php --direction=bidirectional --batch=500
php sync_cloud_to_local.php --direction=cloud-to-local --mode=direct
php sync_cloud_to_local.php --direction=cloud-to-local --mode=bridge
php sync_cloud_to_local.php --direction=local-to-cloud --batch=500
php sync_cloud_to_local.php --direction=local-to-cloud --full
php sync_cloud_to_local.php --direction=bidirectional --dry-run --dump=.\sync_preview.sql
```

- **cloud-to-local**: baja `usuario`, `mstrpers`, `his_mstrpers`, `his_dl` y
  `his_dl_dt`. Con `--mode=bridge` escribe las tablas receptoras
  `r_his_digitad`, `r_his_mstrpers`, `r_his_dl`, `r_his_dl_dt` y llama a
  `sp_get_recepcion()`.
- **local-to-cloud**: sube únicamente las tablas originales del HIS a la nube.
  Es incremental por defecto (`ANO >= año actual - 1` y keyset por PK); use
  `--full` o `--since=AAAA` para forzar otro rango.
- **bidirectional**: ejecuta ambas direcciones en la misma corrida.
- `INSERT ... ON DUPLICATE KEY UPDATE` mantiene la sincronización idempotente y
  por lotes (`--batch`, máximo 2000).
- El script **nunca** ejecuta `CREATE`, `ALTER`, `DROP`, `TRUNCATE` ni `DELETE`.
- **Nunca** se exportan `pacientes_sin_metodo`, `auditoria_seguridad_app`,
  `app_usuarios_accesos`, `app_catalogo_metodos`, `app_sesiones` ni ninguna
  tabla `app_*`. La base del hospital jamás recibe tablas nuevas de la app.
- Las tablas locales que no existan se omiten.

Automatización en Windows (ejecutar como administrador):

```bat
scripts_hospital\sincronizar_hospital_nube.bat
scripts_hospital\instalar_sync_automatico_windows.bat
```

El instalador crea la tarea programada **PlanificaHIS Sync Hospital** cada
15 minutos; el registro queda en `scripts_hospital\logs\sync_hospital.log`.

La exportación web `GET /api.php?action=sync_export_local_sql&modo=directo|puente`
requiere sesión 2FA **y rol de administrador** (`APP_ADMIN_DNI` o
`APP_ADMIN_NIVELID=1`). Devuelve un script SQL para ejecutar en Navicat sobre la
base local y está limitada a 10 exportaciones por minuto.
