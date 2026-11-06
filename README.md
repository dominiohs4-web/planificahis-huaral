# PlanificaHIS — Hospital San Juan Bautista Huaral

Aplicación web/PWA de captación y seguimiento de Planificación Familiar para el
Hospital San Juan Bautista Huaral y la Red Huaral-Chancay. La variante de
producción es **PHP 8.2 + Apache + MariaDB/TiDB Cloud**; los archivos React/Vite
de AI Studio que aún viven en el repositorio no se usan en el contenedor.

## Seguridad

- Autenticación con contraseña + TOTP (RFC 6238) y token Bearer HMAC-SHA256.
- PII cifrada con AES-256-GCM (`enc:gcm:<iv>:<tag>:<ciphertext>`).
- Consultas PDO preparadas nativas, WAF, rate limiting y auditoría SHA-256.
- Cabeceras OWASP ASVS L3, CORS restringido por `ALLOWED_ORIGIN` y HSTS.
- En producción son obligatorios `HUARAL_AES_SECRET` y
  `HUARAL_SESSION_SECRET` (mínimo 32 caracteres). `ENCRYPTION_SECRET` no se
  acepta como respaldo en producción.

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
Chrome → Instalar aplicación. El APK es opcional; si existe
`public/planificahis.apk`, la app muestra el botón de descarga.

## Sincronización Nube → Local

Ejecute en la PC de Estadística, con respaldo previo de la base local:

```bat
php sync_cloud_to_local.php --mode=direct --batch=500
php sync_cloud_to_local.php --mode=bridge --batch=500
php sync_cloud_to_local.php --mode=direct --dry-run --dump=.\sync_preview.sql
```

- **direct**: `usuario`, `mstrpers`, `his_mstrpers`, `his_dl`, `his_dl_dt`.
- **bridge**: `usuario→r_his_digitad`, `his_mstrpers→r_his_mstrpers`,
  `his_dl→r_his_dl`, `his_dl_dt→r_his_dl_dt` + `CALL sp_get_recepcion()`.
- El script **nunca** ejecuta `CREATE`, `ALTER`, `DROP`, `TRUNCATE` ni `DELETE`.
- **Nunca** se exportan `pacientes_sin_metodo`, `auditoria_seguridad_app` ni
  ninguna tabla `app_*`.
- Las tablas locales que no existan se omiten; no se crean tablas nuevas.

La exportación web `GET /api.php?action=sync_export_local_sql&modo=directo|puente`
requiere sesión 2FA **y rol de administrador** (`APP_ADMIN_DNI` o
`APP_ADMIN_NIVELID=1`). Devuelve un script SQL para ejecutar en Navicat sobre la
base local y está limitada a 10 exportaciones por minuto.
