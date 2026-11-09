<?php
/**
 * index.php — Interfaz móvil oficial (Apache + PHP + MariaDB / XAMPP)
 * Hospital San Juan Bautista Huaral — Red de Salud Huaral-Chancay
 *
 * Esta variante consume api.php con Bearer Token emitido tras validar DNI y
 * contraseña en un solo paso (sin 2FA) y sesión persistente de 7 días.
 * No contiene datos clínicos en el HTML: todo se carga por API autenticada.
 */
declare(strict_types=1);

require_once __DIR__ . '/catalogo_establecimientos.php';

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
header('Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=()');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cross-Origin-Resource-Policy: same-origin');
header('X-Robots-Tag: noindex, nofollow');

$catalogo = hospital_establecimientos();
$porDistrito = hospital_establecimientos_por_distrito();
$catalogoJson = json_encode($catalogo, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
$porDistritoJson = json_encode($porDistrito, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
$totalEstablecimientos = count($catalogo);
// El APK es opcional: si Estadística lo publica en public/, la app muestra la
// descarga directa. Si no existe, se ofrecen las instrucciones de instalación PWA.
$apkDisponible = is_file(__DIR__ . '/public/planificahis.apk');
$apkJson = json_encode($apkDisponible ? './public/planificahis.apk' : '', JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

// Logos oficiales pre-codificados en Base64: disponibles al instante en modo
// offline, PDF y Excel sin depender de una petición adicional al servidor.
$diresaLogoPath = __DIR__ . '/public/logo-diresa-lima.jpg';
$hospitalLogoPath = __DIR__ . '/public/logo.png';
$diresaLogoDataUri = is_file($diresaLogoPath)
    ? 'data:image/jpeg;base64,' . base64_encode((string)file_get_contents($diresaLogoPath))
    : './public/logo-diresa-lima.jpg';
$hospitalLogoDataUri = is_file($hospitalLogoPath)
    ? 'data:image/png;base64,' . base64_encode((string)file_get_contents($hospitalLogoPath))
    : './public/logo.png';
$diresaLogoJson = json_encode($diresaLogoDataUri, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
$hospitalLogoJson = json_encode($hospitalLogoDataUri, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
  <title>PlanificaSalud HIS — Hospital San Juan Bautista Huaral</title>
  <meta name="description" content="Captación y seguimiento de Planificación Familiar del Hospital San Juan Bautista Huaral y la Red Huaral-Chancay. Seguridad AES-256-GCM y auditoría SHA-256." />
  <meta name="theme-color" content="#0f172a" />
  <meta name="mobile-web-app-capable" content="yes" />
  <meta name="apple-mobile-web-app-capable" content="yes" />
  <meta name="apple-mobile-web-app-status-bar-style" content="default" />
  <meta name="apple-mobile-web-app-title" content="PlanificaHIS" />
  <link rel="manifest" href="./manifest.webmanifest" />
  <link rel="icon" type="image/svg+xml" href="./public/icon.svg?v=3" />
  <link rel="icon" type="image/x-icon" href="./public/favicon.ico?v=3" />
  <link rel="apple-touch-icon" href="./public/apple-touch-icon.png?v=3" sizes="180x180" />
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
  <style>
    body { font-family: 'Plus Jakarta Sans', sans-serif; -webkit-tap-highlight-color: transparent; }
    .font-mono { font-family: 'JetBrains Mono', monospace; font-variant-numeric: tabular-nums; }
    .hide-scrollbar::-webkit-scrollbar { display: none; }
    .safe-bottom { padding-bottom: env(safe-area-inset-bottom); }
    /* iOS Safari: evita el auto-zoom al enfocar inputs/selects/textareas. */
    @media (max-width: 768px) {
      input, select, textarea { font-size: 16px !important; }
    }
  </style>
</head>
<body class="bg-slate-200/70 text-slate-900 antialiased min-h-[100dvh] flex flex-col items-center">
  <div id="app-root" class="w-full max-w-[480px] md:max-w-3xl lg:max-w-5xl min-h-[100dvh] bg-slate-50 shadow-2xl border-x border-slate-200 flex flex-col relative"></div>
  <div id="ios-banner-root"></div>

  <script>
    'use strict';

    const CATALOGO = <?= $catalogoJson ?>;
    const POR_DISTRITO = <?= $porDistritoJson ?>;
    const TOTAL_ESTABLECIMIENTOS = <?= (int)$totalEstablecimientos ?>;
    const APK_URL = <?= $apkJson ?>;
    const DIRESA_LOGO_DATA_URI = <?= $diresaLogoJson ?>;
    const HOSPITAL_LOGO_DATA_URI = <?= $hospitalLogoJson ?>;
    const API = './api.php';
    const TOKEN_KEY = 'planificahis.php.token.v1';
    const SESSION_KEY = 'planificahis.php.session.v1';
    const QUEUE_KEY = 'planificahis.php.offline.queue.v1';
    const DEVICE_KEY = 'planificahis.php.offline.device-key.v1';
    const IOS_DISMISS_KEY = 'planificahis.php.ios-install-dismissed.v1';
    const LOGO_REPORTES_KEY = 'planificahis.php.logo.reportes.v1';
    const ESTADOS = {
      INSATISFECHA_SIN_METODO: 'Sin Método (Insatisfecha)',
      SEGUIMIENTO_DOMICILIARIO: 'En Seguimiento',
      CONSEJERIA_REALIZADA: 'Consejería Realizada',
      CAPTADA_CON_METODO: 'Con Método (Satisfecha)',
      RECHAZA_METODO: 'Rechaza método'
    };
    const DISTRITOS = [
      'HUARAL', 'CHANCAY', 'AUCALLAMA', 'IHUARI', 'ATAVILLOS ALTO', 'ATAVILLOS BAJO',
      'LAMPIAN', 'PACARAOS', 'SAN MIGUEL DE ACOS', 'SANTA CRUZ DE ANDAMARCA', 'SUMBILCA',
      'VEINTISIETE DE NOVIEMBRE'
    ];

    // Logo oficial del Hospital San Juan Bautista Huaral (public/logo.png).
    // Se usa SIEMPRE la imagen original, sin SVG inventados ni filtros.
    const HOSPITAL_LOGO_HTML = '<img src="' + HOSPITAL_LOGO_DATA_URI + '" alt="Hospital San Juan Bautista Huaral" class="w-full h-full object-contain" />';


    function localIsoDate(offsetDays) {
      const d = new Date();
      d.setDate(d.getDate() + Number(offsetDays || 0));
      const mm = String(d.getMonth() + 1).padStart(2, '0');
      const dd = String(d.getDate()).padStart(2, '0');
      return d.getFullYear() + '-' + mm + '-' + dd;
    }

    function primerDiaMesIso() {
      const d = new Date();
      return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-01';
    }

    function filtrosReportePorDefecto() {
      return {
        fecha_desde: primerDiaMesIso(),
        fecha_hasta: localIsoDate(0),
        estado_paciente: 'TODOS',
        sector: 'TODOS',
        obstetra: 'TODOS',
        codigo_metodo: 'TODOS',
        estado_vencimiento: 'TODOS',
        q: '',
        page: 1,
        per_page: 25
      };
    }

    function formatIsoToDdMmYyyy(iso) {
      const value = String(iso || '').slice(0, 10);
      const parts = value.split('-');
      return parts.length === 3 ? (parts[2] + '/' + parts[1] + '/' + parts[0]) : '';
    }

    let state = {
      token: localStorage.getItem(TOKEN_KEY) || sessionStorage.getItem(TOKEN_KEY) || '',
      session: null,
      authTab: 'LOGIN',
      authStep: 'CREDENTIALS',
      challengeId: '',
      demoCode: '',
      pendingUser: null,
      activeTab: 'CAPTAR',
      pacientes: [],
      agendaAmpollas: [],
      produccionObstetras: [],
      auditLogs: [],
      catalogoMetodos: [],
      alertas: {
        manana: 0, hoy: 0, vencidas: 0, total: 0,
        listas: { manana: [], hoy: [], vencidas: [] }
      },
      agendaGrupo: 'TODAS',
      distritos: DISTRITOS,
      stats: {
        insatisfechasSinMetodo: 0, citasAmpollaHoyManana: 0, atenciones99208: 0,
        totalCaptadas: 0, captadasConMetodo: 0
      },
      securityMetrics: {
        sqliBlockedCount: 0, xssBlockedCount: 0, totpVerifiedCount: 0,
        encryptedRecordsCount: 0, failedLoginsBlocked: 0, auditLogCount: 0
      },
      hisLookup: null,
      formDraft: null,
      formVisible: false,
      nombresDesbloqueados: false,
      feedback: null,
      distritoSelect: 'HUARAL',
      distritoOtros: '',
      chainVerification: null,
      wafResult: null,
      syncExport: null,
      syncMode: 'directo',
      loadingSync: false,
      offlinePending: 0,
      syncingOffline: false,
      changingEstab: false,
      canInstall: false,
      logoPersonalizadoData: (function () { try { return localStorage.getItem(LOGO_REPORTES_KEY) || ''; } catch (e) { return ''; } })(),
      iosBanner: false,
      iosStep: 1,
      showSecurity: true,
      booted: false,
      reporteVista: 'CAMPO',
      campoFiltros: filtrosReportePorDefecto(),
      campoData: null,
      campoLoading: false,
      campoError: '',
      metodosFiltros: filtrosReportePorDefecto(),
      metodosData: null,
      metodosLoading: false,
      metodosError: '',
      productividadFiltros: filtrosReportePorDefecto(),
      productividadData: null,
      productividadLoading: false,
      productividadError: '',
      padronData: null,
      padronLoading: false,
      padronError: '',
      padronGrupo: 'todas',
      accesosData: null,
      accesosLoading: false,
      accesosError: '',
      accesosFiltros: { q: '', rol: 'TODOS', cod_estab: 'TODOS', activo: 'TODOS' },
      accesoForm: { dni: '', nombre_completo: '', nombres: '', apellido_paterno: '', apellido_materno: '', rol: 'OBSTETRA', cod_estab: '', pin: '', email: '', celular: '', activo: 1 },
      personasSugeridas: [],
      showAccesoModal: false,
      adminTab: 'DIRECTORIO',
      movimientosData: null,
      movimientosLoading: false,
      movimientosError: '',
      movimientosFiltros: { q: '', accion: 'TODAS', cod_estab: 'TODOS', fecha_desde: '', fecha_hasta: '' },
      equipoData: null,
      equipoLoading: false,
      resetDni: '',
      guardandoMetodo: false,
      reporteFecha: localIsoDate(0),
      reporteModo: 'exacto',
      reporteAlcance: 'establecimiento',
      reporteAmbito: 'mis_atenciones',
      reporteObstetra: '',
      reporteMetodo: 'TODOS',
      reporteProgramacion: null,
      reporteLoading: false,
      reporteError: ''
    };

    function esc(value) {
      return String(value === null || value === undefined ? '' : value)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function authHeaders(extra) {
      const headers = Object.assign({ 'Content-Type': 'application/json' }, extra || {});
      if (state.token) headers.Authorization = 'Bearer ' + state.token;
      return headers;
    }

    async function apiGet(action, params) {
      const query = new URLSearchParams(Object.assign({ action: action }, params || {}));
      const res = await fetch(API + '?' + query.toString(), { headers: authHeaders(), cache: 'no-store' });
      const data = await res.json().catch(function () { return {}; });
      if (res.status === 401) {
        clearSession();
        throw new Error(data.error || 'Sesión expirada.');
      }
      if (!res.ok) throw new Error(data.error || 'Error de API (' + res.status + ').');
      return data;
    }

    async function apiPost(action, body) {
      const res = await fetch(API + '?action=' + encodeURIComponent(action), {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(body || {})
      });
      const data = await res.json().catch(function () { return {}; });
      if (res.status === 401) {
        clearSession();
        throw new Error(data.error || 'Sesión expirada.');
      }
      if (!res.ok) {
        const error = new Error(data.error || 'Error de API (' + res.status + ').');
        error.data = data;
        throw error;
      }
      return data;
    }

    function clearSession() {
      state.token = '';
      state.session = null;
      state.authStep = 'CREDENTIALS';
      state.challengeId = '';
      state.hisLookup = null;
      state.formDraft = null;
      state.formVisible = false;
      state.nombresDesbloqueados = false;
      state.campoData = null;
      state.metodosData = null;
      try {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(SESSION_KEY);
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.removeItem(SESSION_KEY);
      } catch (e) {}
    }

    function persistSession() {
      try {
        if (state.token) localStorage.setItem(TOKEN_KEY, state.token);
        if (state.session) localStorage.setItem(SESSION_KEY, JSON.stringify(state.session));
        // Se limpian las claves antiguas para evitar sesiones duplicadas.
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.removeItem(SESSION_KEY);
      } catch (e) {}
    }

    function establishName(codigo) {
      const found = CATALOGO.find(function (e) { return e.COD_ESTAB === codigo; });
      return found ? found.DESC_ESTAB : (codigo || 'SIN ESTABLECIMIENTO');
    }

    function optionsEstablecimientos(selected) {
      return Object.keys(POR_DISTRITO).map(function (distrito) {
        const lista = POR_DISTRITO[distrito];
        return '<optgroup label="' + esc(distrito) + ' (' + lista.length + ')">' +
          lista.map(function (e) {
            return '<option value="' + esc(e.COD_ESTAB) + '"' +
              (e.COD_ESTAB === selected ? ' selected' : '') + '>' +
              esc(e.DESC_ESTAB) + ' · ' + esc(e.CATEGORIA) + '</option>';
          }).join('') + '</optgroup>';
      }).join('');
    }

    function optionsDistritos(selected) {
      return DISTRITOS.map(function (d) {
        return '<option value="' + esc(d) + '"' + (d === selected ? ' selected' : '') + '>' + esc(d) + '</option>';
      }).join('') + '<option value="OTROS"' + (selected === 'OTROS' ? ' selected' : '') + '>OTROS (Fuera de Huaral)</option>';
    }

    function statusLabel(value) { return ESTADOS[value] || value || 'Sin estado'; }

    function showFeedback(type, text) {
      state.feedback = { type: type, text: text };
      render();
    }

    // ---------------------------------------------------------------------
    // Cola offline cifrada (AES-256-GCM / Web Crypto)
    // ---------------------------------------------------------------------
    function bytesToB64(bytes) {
      let binary = '';
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      return btoa(binary);
    }
    function b64ToBytes(value) {
      const binary = atob(value);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes;
    }
    function offlineSupported() {
      return typeof window !== 'undefined' && !!window.crypto && !!window.crypto.subtle && !!window.localStorage;
    }
    async function getOfflineKey() {
      let raw = localStorage.getItem(DEVICE_KEY);
      let secret;
      if (raw) {
        try { secret = b64ToBytes(raw); } catch (e) { localStorage.removeItem(QUEUE_KEY); }
      }
      if (!secret) {
        secret = crypto.getRandomValues(new Uint8Array(32));
        localStorage.setItem(DEVICE_KEY, bytesToB64(secret));
      }
      return crypto.subtle.importKey('raw', secret, 'AES-GCM', false, ['encrypt', 'decrypt']);
    }
    function readQueueRaw() {
      try {
        const parsed = JSON.parse(localStorage.getItem(QUEUE_KEY) || '[]');
        return Array.isArray(parsed) ? parsed : [];
      } catch (e) { return []; }
    }
    function writeQueueRaw(items) {
      localStorage.setItem(QUEUE_KEY, JSON.stringify(items.slice(-200)));
      state.offlinePending = items.length;
      updatePendingIndicators();
    }
    async function queueOfflinePatient(payload) {
      if (!offlineSupported()) throw new Error('Este navegador no soporta cifrado local.');
      const key = await getOfflineKey();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        new TextEncoder().encode(JSON.stringify(payload))
      );
      const items = readQueueRaw();
      items.push({
        id: (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + '-' + Math.random().toString(16).slice(2)),
        createdAt: new Date().toISOString(),
        iv: bytesToB64(iv),
        ciphertext: bytesToB64(new Uint8Array(ciphertext))
      });
      writeQueueRaw(items);
    }
    async function syncOfflineQueue(silent) {
      if (!state.token || state.syncingOffline || !offlineSupported()) return;
      const items = readQueueRaw();
      if (!items.length) { state.offlinePending = 0; updatePendingIndicators(); return; }
      state.syncingOffline = true;
      const remaining = [];
      let synced = 0;
      for (let i = 0; i < items.length; i++) {
        try {
          const key = await getOfflineKey();
          const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: b64ToBytes(items[i].iv) },
            key,
            b64ToBytes(items[i].ciphertext)
          );
          const payload = JSON.parse(new TextDecoder().decode(decrypted));
          await apiPost('save_paciente', payload);
          synced++;
        } catch (e) {
          if (String(e.message || '').indexOf('Sesión') !== -1) { remaining.push(items[i]); break; }
          remaining.push(items[i]);
          if (!navigator.onLine) break;
        }
      }
      writeQueueRaw(remaining);
      state.syncingOffline = false;
      if (synced > 0) {
        state.feedback = { type: 'success', text: synced + ' captación(es) offline sincronizada(s) con el servidor del hospital.' };
        await loadOverview();
      } else if (!silent) {
        render();
      }
      updatePendingIndicators();
    }

    function updatePendingIndicators() {
      document.querySelectorAll('[data-pending]').forEach(function (node) {
        node.textContent = state.offlinePending > 0 ? String(state.offlinePending) + ' offline' : '';
        node.classList.toggle('hidden', state.offlinePending <= 0);
      });
    }

    // ---------------------------------------------------------------------
    // Render principal
    // ---------------------------------------------------------------------
    function render() {
      const root = document.getElementById('app-root');
      if (!state.session) {
        root.innerHTML = renderLogin();
      } else {
        root.innerHTML = renderApp();
      }
      renderIosBanner();
      updatePendingIndicators();
    }

    function renderLogin() {
      return `
        <div class="bg-gradient-to-b from-sky-50/80 to-white border-b border-slate-100 px-6 pt-8 pb-5 text-center">
          <div class="w-24 h-24 mx-auto mb-3">${HOSPITAL_LOGO_HTML}</div>
          <h1 class="text-lg font-bold text-slate-900 tracking-tight">Hospital San Juan Bautista Huaral</h1>
          <p class="text-xs text-slate-500 mt-0.5">Planificación Familiar · Captación y Seguimiento Obstétrico</p>
          <p class="text-[10px] text-sky-700 mt-1 font-medium">${TOTAL_ESTABLECIMIENTOS} IPRESS · Red Huaral-Chancay</p>
        </div>
        <div class="flex-1 px-6 py-5 space-y-4">
          ${state.authStep === 'CREDENTIALS' ? `
            <div class="grid grid-cols-2 gap-1 p-1 bg-slate-100 rounded-xl">
              <button type="button" onclick="setAuthTab('LOGIN')" class="min-h-[42px] rounded-lg text-xs font-semibold ${state.authTab === 'LOGIN' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600'}">Iniciar Sesión</button>
              <button type="button" onclick="setAuthTab('REGISTER')" class="min-h-[42px] rounded-lg text-xs font-semibold ${state.authTab === 'REGISTER' ? 'bg-white text-sky-800 shadow-xs' : 'text-slate-600'}">Crear Cuenta Obstetra</button>
            </div>` : ''}
          ${state.feedback ? `<div class="p-3.5 rounded-xl border text-xs ${state.feedback.type === 'error' ? 'bg-red-50 border-red-200 text-red-800' : 'bg-emerald-50 border-emerald-200 text-emerald-900'}">${esc(state.feedback.text)}</div>` : ''}
          ${state.authStep === 'CREDENTIALS' && state.authTab === 'LOGIN' ? `
            <div class="p-3 rounded-xl bg-sky-50 border border-sky-200 text-[11px] text-sky-950 leading-relaxed">
              <strong>Acceso clínico protegido:</strong> ingrese su DNI de obstetra y su contraseña.
            </div>
            <form onsubmit="handleLogin(event)" class="space-y-4">
              <div>
                <label class="block text-xs font-semibold text-slate-700 mb-1.5">DNI de la Obstetra</label>
                <input id="login-dni" type="text" inputmode="numeric" maxlength="11" required placeholder="Ingrese su DNI (8 dígitos)" class="w-full min-h-[48px] px-4 rounded-xl border border-slate-300 text-sm font-mono" />
              </div>
              <div>
                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Contraseña</label>
                <input id="login-pass" type="password" required placeholder="••••••••" class="w-full min-h-[48px] px-4 rounded-xl border border-slate-300 text-sm" />
              </div>
              <button type="submit" class="w-full min-h-[50px] rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-sm font-semibold">Ingresar a la Aplicación</button>
            </form>
            <div class="text-center">
              <button type="button" onclick="setAuthStep('RECOVER')" class="min-h-[36px] text-[11px] font-semibold text-sky-700 underline underline-offset-2">¿Olvidaste tu contraseña?</button>
            </div>` : ''}
          ${state.authStep === 'RECOVER' ? renderRecuperarClave() : ''}
          ${state.authStep === 'CREDENTIALS' && state.authTab === 'REGISTER' ? `
            <form onsubmit="handleRegister(event)" class="space-y-3">
              <p class="text-xs text-slate-600">Cada obstetra crea su propio acceso vinculado a su DNI, correo y establecimiento.</p>
              <div class="grid grid-cols-2 gap-2.5">
                <div><label class="block text-xs font-semibold text-slate-700 mb-1">DNI (8 dígitos)</label><input id="reg-dni" type="text" inputmode="numeric" maxlength="8" required placeholder="43819205" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm font-mono" /></div>
                <div><label class="block text-xs font-semibold text-slate-700 mb-1">Celular</label><input id="reg-cel" type="tel" inputmode="numeric" maxlength="9" required placeholder="987654321" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm font-mono" /></div>
              </div>
              <div><label class="block text-xs font-semibold text-slate-700 mb-1">Nombres</label><input id="reg-nom" type="text" required placeholder="PATRICIA" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm" /></div>
              <div class="grid grid-cols-2 gap-2.5">
                <div><label class="block text-xs font-semibold text-slate-700 mb-1">Apellido Paterno</label><input id="reg-ap" type="text" required class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm" /></div>
                <div><label class="block text-xs font-semibold text-slate-700 mb-1">Apellido Materno</label><input id="reg-am" type="text" required class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm" /></div>
              </div>
              <div><label class="block text-xs font-semibold text-slate-700 mb-1">Correo Electrónico</label><input id="reg-email" type="email" required placeholder="obstetra@hospitalhuaral.gob.pe" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm" /></div>
              <div>
                <label class="block text-xs font-semibold text-slate-700 mb-1">Establecimiento (${TOTAL_ESTABLECIMIENTOS} IPRESS)</label>
                <select id="reg-estab" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-xs bg-white">${optionsEstablecimientos('000005481')}</select>
              </div>
              <div><label class="block text-xs font-semibold text-slate-700 mb-1">Contraseña (mínimo 8 caracteres)</label><input id="reg-pass" type="password" required minlength="8" placeholder="Mínimo 8 caracteres" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm" /></div>
              <button type="submit" class="w-full min-h-[48px] rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-sm font-semibold">Crear Cuenta de Obstetra</button>
            </form>` : ''}
        </div>
        <div class="px-6 py-4 bg-slate-50 border-t border-slate-100 flex items-center justify-between">
          <span class="text-xs text-slate-500">App Móvil Oficial</span>
          <button type="button" onclick="installPwa()" class="min-h-[40px] px-3 rounded-xl bg-slate-900 text-white text-xs font-semibold">Instalar</button>
        </div>`;
    }

    function renderRecuperarClave() {
      return `<div class="p-4 rounded-2xl bg-amber-50 border-2 border-amber-300 space-y-3">
        <div class="flex items-start justify-between gap-2">
          <div>
            <h3 class="text-sm font-bold text-amber-950">Recuperar contraseña</h3>
            <p class="text-[11px] text-amber-900 mt-0.5">Valide su DNI, su PIN de recuperación (o los últimos 4 dígitos de su DNI/celular) y su establecimiento registrado. No se solicita código TOTP.</p>
          </div>
          <button type="button" onclick="setAuthStep('CREDENTIALS')" aria-label="Volver" class="min-h-[34px] min-w-[34px] rounded-lg bg-white border border-amber-300 text-amber-900 text-sm font-bold shrink-0">×</button>
        </div>
        <form onsubmit="handleRecover(event)" class="space-y-3">
          <div>
            <label class="block text-xs font-semibold text-slate-700 mb-1">DNI registrado</label>
            <input id="rec-dni" type="text" inputmode="numeric" maxlength="11" required placeholder="Ingrese su DNI" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm font-mono" />
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-700 mb-1">PIN de recuperación o últimos 4 dígitos</label>
            <input id="rec-pin" type="text" inputmode="numeric" maxlength="8" required placeholder="Ej. 4 últimos dígitos de su DNI o celular" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm font-mono" />
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-700 mb-1">Establecimiento registrado</label>
            <select id="rec-estab" required class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-xs bg-white">${optionsEstablecimientos('000005481')}</select>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div><label class="block text-xs font-semibold text-slate-700 mb-1">Nueva contraseña</label><input id="rec-pass" type="password" required minlength="8" placeholder="Mínimo 8 caracteres" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm" /></div>
            <div><label class="block text-xs font-semibold text-slate-700 mb-1">Confirmar contraseña</label><input id="rec-pass2" type="password" required minlength="8" placeholder="Repita la contraseña" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm" /></div>
          </div>
          <button type="submit" class="w-full min-h-[48px] rounded-xl bg-amber-700 hover:bg-amber-800 text-white text-sm font-bold">Restablecer Contraseña</button>
          <button type="button" onclick="setAuthStep('CREDENTIALS')" class="w-full min-h-[42px] rounded-xl border border-slate-300 bg-white text-slate-700 text-xs font-semibold">Volver al Inicio de Sesión</button>
        </form>
      </div>`;
    }

    function renderApp() {
      const s = state.session;
      return `
        <div class="sticky top-0 z-30 bg-white/95 backdrop-blur-md border-b border-slate-200 px-3 py-2.5 flex items-center justify-between gap-2">
          <div class="flex items-center gap-2 min-w-0 flex-1">
            <div class="w-9 h-9 shrink-0">${HOSPITAL_LOGO_HTML}</div>
            <div class="min-w-0 flex-1">
              <div class="text-xs font-bold text-slate-900 truncate">${esc(s.nombreCompleto || 'Hospital SJB Huaral')}</div>
              ${s.isAdmin ? `<select aria-label="Establecimiento activo" onchange="cambiarEstablecimiento(this.value)" ${state.changingEstab ? 'disabled' : ''} class="mt-0.5 w-full max-w-[250px] min-h-[30px] px-2 py-0.5 rounded-lg border border-sky-200 bg-sky-50 text-[10px] text-sky-950 font-medium truncate">
                ${optionsEstablecimientos(s.cod_estab || '000005481')}
              </select>` : `<div class="mt-0.5 w-full max-w-[250px] min-h-[30px] px-2 py-1 rounded-lg border border-slate-200 bg-slate-50 text-[10px] text-slate-700 font-medium truncate" title="Establecimiento fijo asignado a su cuenta">🏥 ${esc(s.estab_nombre || establishName(s.cod_estab))}</div>`}

            </div>
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <span data-pending class="hidden px-2 py-1 rounded-lg bg-amber-100 text-amber-900 text-[10px] font-bold"></span>
            <button type="button" onclick="verAlertaManana()" aria-label="Alertas de seguimiento" class="relative min-h-[40px] min-w-[40px] flex items-center justify-center rounded-xl text-amber-700 hover:bg-amber-50">
              🔔${Number(state.alertas.total || 0) > 0 ? '<span class="absolute -top-0.5 -right-0.5 min-w-[18px] h-[18px] px-1 rounded-full bg-red-600 text-white text-[9px] font-extrabold flex items-center justify-center">' + Number(state.alertas.total || 0) + '</span>' : ''}
            </button>
            <button type="button" onclick="logout()" aria-label="Cerrar sesión" class="min-h-[40px] min-w-[40px] flex items-center justify-center rounded-xl text-slate-500 hover:text-red-600 hover:bg-slate-100">Salir</button>
          </div>
        </div>
        ${!navigator.onLine ? '<div class="mx-4 mt-3 p-2.5 rounded-xl bg-amber-50 border border-amber-200 text-[11px] text-amber-900 font-medium">Sin conexión. Las captaciones se guardarán cifradas en este dispositivo y se sincronizarán automáticamente.</div>' : ''}
        <main class="flex-1 p-4 pb-[calc(5rem+env(safe-area-inset-bottom))] space-y-4">
          ${renderAlertaBanner()}
          ${state.activeTab === 'CAPTAR' ? renderCaptar() : ''}
          ${state.activeTab === 'PACIENTES' ? renderPacientes() : ''}
          ${state.activeTab === 'REPORTES' ? renderReportes() : ''}
          ${state.activeTab === 'AGENDA' ? renderAgenda() : ''}
          ${state.activeTab === 'PERFIL' ? renderPerfil() : ''}
        </main>
        <nav class="fixed bottom-0 left-1/2 -translate-x-1/2 w-full max-w-[480px] md:max-w-3xl lg:max-w-5xl z-40 bg-white/95 backdrop-blur-md border-t border-slate-200 grid grid-cols-5 items-center h-16 safe-bottom">
          ${navButton('CAPTAR', 'Captar')}
          ${navButton('PACIENTES', 'Pacientes')}
          ${navButton('REPORTES', 'Reportes')}
          ${navButton('AGENDA', 'Agenda')}
          ${navButton('PERFIL', 'Perfil')}
        </nav>`;
    }

    function navButton(tab, label) {
      const active = state.activeTab === tab;
      return '<button type="button" onclick="setTab(\'' + tab + '\')" class="min-h-[44px] flex flex-col items-center justify-center ' +
        (active ? 'text-sky-700 font-bold' : 'text-slate-400') + '"><span class="text-[11px]">' + label + '</span></button>';
    }

    function renderAlertaBanner() {
      const a = state.alertas || {};
      const total = Number(a.total || 0);
      const manana = Number(a.manana || 0);
      const hoy = Number(a.hoy || 0);
      const vencidas = Number(a.vencidas || 0);
      if (total <= 0) {
        return `<div class="rounded-2xl border border-emerald-200 bg-emerald-50 p-3 flex items-center justify-between gap-2">
          <div class="text-[11px] font-semibold text-emerald-950">🔔 Alertas de Seguimiento Programático</div>
          <div class="text-[10px] font-bold text-emerald-800">Sin pacientes pendientes</div>
        </div>`;
      }
      return `<div class="rounded-2xl border-2 border-amber-300 bg-amber-50 p-3 space-y-2.5">
        <div class="flex items-start justify-between gap-2">
          <div>
            <div class="text-xs font-extrabold text-amber-950">🔔 Alertas de Seguimiento Programático</div>
            <div class="text-[10px] text-amber-900">Pacientes que requieren llamada de seguimiento al abrir la aplicación.</div>
          </div>
          <span class="px-2 py-1 rounded-lg bg-amber-700 text-white text-[10px] font-extrabold shrink-0">${total}</span>
        </div>
        <div class="grid grid-cols-3 gap-1.5 text-center">
          <div class="p-2 rounded-xl bg-white border border-sky-200"><div class="text-[9px] font-bold text-sky-700">MAÑANA (+1)</div><div class="text-lg font-extrabold font-mono text-sky-900">${manana}</div></div>
          <div class="p-2 rounded-xl bg-white border border-amber-300"><div class="text-[9px] font-bold text-amber-800">HOY</div><div class="text-lg font-extrabold font-mono text-amber-900">${hoy}</div></div>
          <div class="p-2 rounded-xl bg-white border border-red-300"><div class="text-[9px] font-bold text-red-700">VENCIDAS</div><div class="text-lg font-extrabold font-mono text-red-900">${vencidas}</div></div>
        </div>
        <div class="grid grid-cols-2 gap-2">
          <button type="button" onclick="verAlertaManana()" class="min-h-[42px] rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-[10px] font-bold leading-tight px-2">Ver Pacientes a Llamar Mañana</button>
          <button type="button" onclick="descargarExcelAlerta()" class="min-h-[42px] rounded-xl bg-emerald-700 hover:bg-emerald-800 text-white text-[10px] font-bold leading-tight px-2">Descargar Excel de Alerta</button>
        </div>
      </div>`;
    }

    function renderProgramacionCard(prog) {
      if (!prog) return '';
      const mapa = {
        AL_DIA: { card: 'bg-emerald-50 border-emerald-300 text-emerald-950', badge: 'bg-emerald-700 text-white', label: 'AL DÍA' },
        TOCA_HOY: { card: 'bg-amber-50 border-amber-400 text-amber-950', badge: 'bg-amber-600 text-white', label: 'TOCA HOY' },
        PROXIMO_7_DIAS: { card: 'bg-sky-50 border-sky-300 text-sky-950', badge: 'bg-sky-700 text-white', label: 'PRÓXIMOS 7 DÍAS' },
        VENCIDO_ABANDONO: { card: 'bg-red-50 border-red-400 text-red-950', badge: 'bg-red-700 text-white', label: 'VENCIDA / ABANDONO' },
        SIN_METODO: { card: 'bg-slate-50 border-slate-300 text-slate-800', badge: 'bg-slate-600 text-white', label: 'SIN MÉTODO' }
      };
      const meta = mapa[prog.estadoProgramacion] || mapa.SIN_METODO;
      const dias = prog.diasParaProximo;
      const diasTexto = (dias === null || dias === undefined)
        ? 'Sin fecha de próximo método'
        : (Number(dias) === 0 ? 'Le toca HOY' : (Number(dias) > 0 ? 'Faltan ' + Number(dias) + ' días' : 'Vencida hace ' + Math.abs(Number(dias)) + ' días'));
      const origen = prog.establecimientoUltimoMetodo || {};
      return `<div class="p-4 rounded-2xl border-2 ${meta.card} space-y-2.5">
        <div class="flex items-center justify-between gap-2">
          <div class="text-xs font-extrabold">Estado de Programación · Planificación Familiar</div>
          <span class="px-2 py-1 rounded-lg text-[10px] font-extrabold shrink-0 ${meta.badge}">${meta.label}</span>
        </div>
        ${prog.tieneMetodoRegistrado ? `<div class="rounded-xl bg-white/80 border border-white px-3 py-2 space-y-1">
          <div class="text-[11px] font-bold text-slate-900">${esc(prog.nombreMetodo)} <span class="font-mono">(${esc(prog.codigoMetodo)})</span></div>
          <div class="grid grid-cols-2 gap-x-2 gap-y-1 text-[11px] font-mono">
            <div>Aplicado: <b>${esc(prog.fechaUltimaAplicacion || '—')}</b></div>
            <div>Ciclo: <b>${Number(prog.diasCiclo || 0)} días</b></div>
            <div>Próximo: <b>${esc(prog.fechaProximoMetodo || '—')}</b></div>
            <div class="font-semibold">${esc(diasTexto)}</div>
          </div>
          ${prog.dosis ? '<div class="text-[10px] text-slate-600">Dosis registrada: <b>' + esc(prog.dosis) + '</b></div>' : ''}
        </div>` : '<div class="rounded-xl bg-white/80 border border-white px-3 py-2 text-[11px]">No registra método anticonceptivo vigente en la Red Huaral-Chancay.</div>'}
        ${origen.nombre ? '<div class="text-[10px] leading-relaxed">Última atención PF: <b>' + esc(origen.nombre) + '</b>' + (origen.esMismoEstablecimiento ? ' (su establecimiento)' : '') + '</div>' : ''}
        <div class="rounded-xl bg-white/70 border border-white px-3 py-2 text-[11px] leading-relaxed"><b>Recomendación:</b> ${esc(prog.recomendacionClinica || '')}</div>
      </div>`;
    }

    function renderCaptar() {
      const lookup = state.hisLookup;
      const draft = state.formDraft || {};
      const ups = lookup && lookup.upsPlanificacionFamiliar;
      const alerta99208 = lookup && lookup.atencion99208;
      const prog = lookup && lookup.programacionPaciente;
      const caso = lookup ? (lookup.casoFlujo || 'NUEVA') : 'NUEVA';
      const esCaso1 = caso === 'MISMO_ESTABLECIMIENTO';
      const esCaso2 = caso === 'OTRO_ESTABLECIMIENTO';
      const paseDirecto = Boolean(ups && ups.paseDirectoHabilitado);
      const formVisible = Boolean(lookup && state.formVisible);
      const bloqueoNombres = Boolean(lookup && (esCaso1 || esCaso2) && !state.nombresDesbloqueados);
      const nombreReadonly = bloqueoNombres ? 'readonly' : '';
      const nombreClase = bloqueoNombres
        ? 'w-full min-h-[44px] px-3 rounded-xl border border-slate-200 bg-slate-100 text-slate-600 text-sm'
        : 'w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm';
      const nombreActual = (lookup && lookup.establecimiento && lookup.establecimiento.nombre) || state.session.estab_nombre || establishName(state.session.cod_estab);
      const distritoActual = (lookup && lookup.establecimiento && lookup.establecimiento.distrito) || 'HUARAL';
      return `
        <div class="grid grid-cols-3 gap-2">
          <div class="p-3 rounded-2xl bg-white border border-slate-200"><div class="text-[10px] text-slate-500 leading-tight">Sin Método Captadas</div><div class="text-lg font-bold text-amber-700 font-mono mt-0.5">${Number(state.stats.insatisfechasSinMetodo || 0)}</div></div>
          <div class="p-3 rounded-2xl bg-white border border-slate-200"><div class="text-[10px] text-slate-500 leading-tight">Citas Ampolla Hoy/Mañana</div><div class="text-lg font-bold text-sky-700 font-mono mt-0.5">${Number(state.stats.citasAmpollaHoyManana || 0)}</div></div>
          <div class="p-3 rounded-2xl ${Number(state.stats.atenciones99208 || 0) > 0 ? 'bg-red-50 border-red-300' : 'bg-white border-slate-200'} border"><div class="text-[10px] text-slate-500 leading-tight">Atenciones 99208</div><div class="text-lg font-bold text-red-700 font-mono mt-0.5">${Number(state.stats.atenciones99208 || 0)}</div></div>
        </div>

        <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
          <div class="text-xs font-bold text-slate-900">1. Validar DNI de la Paciente</div>
          <div class="rounded-xl bg-sky-50 border border-sky-200 px-3 py-2 text-[11px] text-sky-950">
            <div class="font-semibold">Búsqueda en toda la Red con establecimiento activo:</div>
            <div class="mt-0.5">${esc(state.session.estab_nombre || establishName(state.session.cod_estab))}</div>
            <div class="text-sky-700 mt-0.5">UPS Planificación Familiar (COD_SERVSA 302304 / catálogo de métodos y administraciones)</div>
          </div>
          <div class="flex gap-2">
            <input id="f-dni" type="text" inputmode="numeric" maxlength="15" value="${esc(draft.dni || '')}" placeholder="Ingrese DNI (8 dígitos)" class="flex-1 min-h-[46px] px-3.5 rounded-xl border border-slate-300 text-sm font-mono" />
            <button type="button" onclick="validarDni()" class="min-h-[46px] px-4 rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-xs font-semibold shrink-0">Validar</button>
          </div>

          ${lookup ? `<div class="p-3.5 rounded-xl border text-xs space-y-1 ${prog && prog.tieneMetodoRegistrado ? 'bg-emerald-50 border-emerald-300 text-emerald-950' : 'bg-amber-50 border-amber-300 text-amber-950'}">
            ${prog && prog.tieneMetodoRegistrado
              ? '<div class="font-bold">Método registrado en la Red: ' + esc(prog.nombreMetodo) + ' (' + esc(prog.codigoMetodo) + ')</div><p>' + esc((lookup.hisRecord && (lookup.hisRecord.Apellido_p + ' ' + lookup.hisRecord.Apellido_m + ', ' + (lookup.hisRecord.Dnombres || lookup.hisRecord.Pnombre))) || '') + '.</p>'
              : '<div class="font-bold">' + (lookup.foundInHis ? 'Paciente en base del hospital pero SIN método vigente' : 'Paciente nueva sin método registrado') + '</div><p>Complete sus datos abajo para registrarla en seguimiento.</p>'}
          </div>` : ''}
        </div>

        ${alerta99208 && alerta99208.tieneCodigo99208 ? `<div class="p-4 rounded-2xl bg-red-950 border-2 border-red-500 text-white shadow-lg space-y-2">
          <div class="flex items-center gap-2 text-sm font-extrabold text-red-100">ALERTA CLÍNICA · CÓDIGO 99208</div>
          <p class="text-xs leading-relaxed text-red-50">${esc(alerta99208.mensajeOficial99208)}</p>
          ${(alerta99208.historial99208 || []).slice(0, 3).map(function (item) {
            return '<div class="rounded-xl bg-red-900/60 border border-red-700 px-3 py-2 text-[11px] font-mono">' + esc(item.fecha) + ' · ' + esc(item.establecimiento) + ' · DX ' + esc(item.dx) + (item.tdx ? ' (' + esc(item.tdx) + ')' : '') + '</div>';
          }).join('')}
        </div>` : ''}

        ${esCaso2 ? `<div class="p-4 rounded-2xl bg-amber-50 border-2 border-amber-400 text-amber-950 space-y-2">
          <div class="text-xs font-extrabold">Cambio de establecimiento / actualización de domicilio</div>
          <p class="text-xs leading-relaxed font-semibold">${esc(lookup.mensajeCambioEstablecimiento || 'Paciente atendida previamente en otro establecimiento de la Red. Verifique y actualice Distrito, Dirección, Sector y Celular.')}</p>
          <div class="rounded-xl bg-white/70 border border-amber-200 px-3 py-2 text-[11px]">
            Establecimiento actual para el registro: <b>${esc(nombreActual)}</b> · Distrito sugerido: <b>${esc(distritoActual)}</b>
          </div>
        </div>` : ''}

        ${prog ? renderProgramacionCard(prog) : ''}

        ${lookup && esCaso1 ? `<div class="p-4 rounded-2xl border-2 bg-emerald-50 border-emerald-400 text-emerald-950 space-y-2.5">
          <div class="flex items-center justify-between gap-2">
            <div class="text-xs font-extrabold">UPS Planificación Familiar · ${esc(nombreActual)}</div>
            <span class="px-2 py-1 rounded-lg bg-emerald-700 text-white text-[10px] font-extrabold shrink-0">CONTROL</span>
          </div>
          <p class="text-xs leading-relaxed font-semibold">${esc(ups.mensaje)}</p>
          ${paseDirecto ? `<div class="space-y-1">${(ups.atenciones || []).filter(function (a) { return a.es_planificacion_familiar; }).slice(0, 3).map(function (a) {
            return '<div class="rounded-lg bg-white/70 border border-emerald-200 px-2.5 py-1.5 text-[11px] font-mono">' + esc(a.fecha) + ' · Cód. ' + esc(a.dx || a.cod_servsa) + ' · Dosis ' + esc(a.id_dosis || '—') + '</div>';
          }).join('')}</div>
          <div class="rounded-xl bg-white/70 border border-emerald-200 px-3 py-2 text-[11px] text-emerald-900">
            <strong>Pase directo / control habilitado.</strong> Puede confirmarlo en un clic o actualizar los datos de contacto con el botón inferior.
          </div>
          <button type="button" onclick="confirmarPaseUps()" class="w-full min-h-[48px] rounded-xl bg-emerald-700 hover:bg-emerald-800 text-white text-sm font-bold">Confirmar Pase Directo / Control en UPS</button>` : ''}
          <button type="button" onclick="toggleFormularioEdicion()" class="w-full min-h-[44px] rounded-xl border-2 border-emerald-600 bg-white text-emerald-800 text-xs font-bold">${state.formVisible ? 'Ocultar formulario de actualización' : '✏️ Actualizar Teléfono / Dirección / Estado de la Paciente'}</button>
        </div>` : ''}

        ${lookup && !esCaso1 && !esCaso2 && ups ? `<div class="p-4 rounded-2xl border-2 bg-amber-50 border-amber-400 text-amber-950 space-y-2">
          <div class="flex items-center justify-between gap-2">
            <div class="text-xs font-extrabold">UPS Planificación Familiar · ${esc(ups.establecimiento.nombre)}</div>
            <span class="px-2 py-1 rounded-lg bg-amber-600 text-white text-[10px] font-extrabold shrink-0">CAPTACIÓN</span>
          </div>
          <p class="text-xs leading-relaxed font-semibold">${esc(ups.mensaje)}</p>
          <div class="rounded-xl bg-white/70 border border-amber-200 px-3 py-2 text-[11px] text-amber-900">
            <strong>Formulario precargado desde HIS.</strong> Nombres, apellidos y edad ya vienen del HIS. Complete celular, dirección, sector y guarde para registrar la captación en esta IPRESS.
          </div>
        </div>` : ''}

        ${state.feedback ? `<div class="p-3.5 rounded-xl border text-xs ${state.feedback.type === 'error' ? 'bg-red-50 border-red-200 text-red-800' : 'bg-emerald-50 border-emerald-200 text-emerald-900'}">${esc(state.feedback.text)}</div>` : ''}

        ${formVisible ? `<form onsubmit="guardarPaciente(event)" class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3.5">
          <div class="text-xs font-bold text-slate-900">${esCaso1 ? 'Actualizar Teléfono / Dirección / Estado de la Paciente' : (esCaso2 ? 'Datos para registrar en ' + esc(nombreActual) : '2. Datos de la Paciente a Captar')}</div>
          ${esCaso1 ? '<div class="rounded-xl bg-emerald-50 border border-emerald-200 px-3 py-2 text-[11px] text-emerald-950">Los nombres y apellidos están bloqueados porque provienen del HIS. Use <b>Desbloquear edición de nombres</b> solo si detecta un error de digitación.</div>' : ''}
          ${esCaso2 ? '<div class="rounded-xl bg-amber-50 border border-amber-300 px-3 py-2 text-[11px] text-amber-950">Identidad autorrellenada desde HIS. Confirme el distrito, la dirección y el sector correspondientes a <b>' + esc(nombreActual) + '</b>.</div>' : ''}
          ${!esCaso1 && !esCaso2 && ups && ups.requiereFormularioCompleto ? '<div class="rounded-xl bg-sky-50 border border-sky-200 px-3 py-2 text-[11px] text-sky-950">Datos personales precargados desde <code class="font-mono">his_dl</code>. Verifique y complete los campos de contacto.</div>' : ''}
          <div class="grid grid-cols-2 gap-2.5">
            <div><label class="block text-xs text-slate-700 mb-1">Apellido Paterno</label><input id="f-app" type="text" required ${nombreReadonly} value="${esc(draft.apellido_paterno || '')}" class="${nombreClase}" /></div>
            <div><label class="block text-xs text-slate-700 mb-1">Apellido Materno</label><input id="f-apm" type="text" required ${nombreReadonly} value="${esc(draft.apellido_materno || '')}" class="${nombreClase}" /></div>
          </div>
          <div class="grid grid-cols-3 gap-2.5">
            <div class="col-span-2"><label class="block text-xs text-slate-700 mb-1">Nombres</label><input id="f-nom" type="text" required ${nombreReadonly} value="${esc(draft.nombres || '')}" class="${nombreClase}" /></div>
            <div><label class="block text-xs text-slate-700 mb-1">Edad</label><input id="f-edad" type="number" min="10" max="65" required value="${esc(draft.edad || '')}" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm font-mono" /></div>
          </div>
          ${bloqueoNombres ? '<button type="button" onclick="desbloquearNombres()" class="min-h-[34px] px-3 rounded-xl border border-slate-300 text-[10px] font-semibold text-slate-600">🔓 Desbloquear edición de nombres</button>' : ''}
          <div class="grid grid-cols-2 gap-2.5">
            <div><label class="block text-xs text-slate-700 mb-1">Celular</label><input id="f-cel" type="tel" value="${esc(draft.celular || '')}" placeholder="987654321" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm font-mono" /></div>
            <div><label class="block text-xs text-slate-700 mb-1">Correo</label><input id="f-cor" type="email" value="${esc(draft.correo || '')}" placeholder="Opcional" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm" /></div>
          </div>
          <div class="${esCaso2 ? 'p-3 rounded-xl border-2 border-amber-300 bg-amber-50/70 space-y-2.5' : 'space-y-2.5'}">
            ${esCaso2 ? '<div class="text-[10px] font-bold text-amber-900">📍 Confirme el domicilio en ' + esc(nombreActual) + '</div>' : ''}
            <div>
              <label class="block text-xs text-slate-700 mb-1">Distrito (Provincia de Huaral)</label>
              <select id="f-dist" onchange="onChangeDistrito(this.value)" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm bg-white">${optionsDistritos(draft.distrito || state.distritoSelect)}</select>
            </div>
            <div id="otros-box" class="${(draft.distrito || state.distritoSelect) === 'OTROS' ? '' : 'hidden'}">
              <label class="block text-xs font-semibold text-amber-800 mb-1">Especifique otro Distrito / Procedencia</label>
              <input id="f-dist-otros" type="text" value="${esc(draft.distritoOtros || state.distritoOtros || '')}" placeholder="Ej. Huacho, Lima..." class="w-full min-h-[44px] px-3 rounded-xl border border-amber-400 bg-amber-50/40 text-sm" />
            </div>
            <div><label class="block text-xs text-slate-700 mb-1">Dirección Domiciliaria</label><input id="f-dir" type="text" required value="${esc(draft.direccion || '')}" placeholder="Calle / Av. / Urb. / Referencia" class="w-full min-h-[44px] px-3 rounded-xl border ${esCaso2 ? 'border-amber-400 bg-white' : 'border-slate-300'} text-sm" /></div>
            <div class="grid grid-cols-2 gap-2.5">
              <div><label class="block text-xs text-slate-700 mb-1">Sector</label><input id="f-sec" type="text" required value="${esc(draft.sector || '')}" placeholder="Ej. Sector 28" class="w-full min-h-[44px] px-3 rounded-xl border ${esCaso2 ? 'border-amber-400 bg-white' : 'border-slate-300'} text-sm" /></div>
              <div><label class="block text-xs text-slate-700 mb-1">Estado</label><select id="f-est" class="w-full min-h-[44px] px-2 rounded-xl border border-slate-300 text-xs bg-white">${Object.keys(ESTADOS).map(function (e) { return '<option value="' + e + '"' + ((draft.estado_paciente || 'INSATISFECHA_SIN_METODO') === e ? ' selected' : '') + '>' + esc(ESTADOS[e]) + '</option>'; }).join('')}</select></div>
            </div>
          </div>
          <button type="submit" class="w-full min-h-[48px] rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-sm font-semibold">${esCaso1 ? 'Guardar Actualización de la Paciente' : (esCaso2 ? 'Registrar Paciente en mi Establecimiento' : 'Guardar Paciente')}</button>
        </form>` : ''}`;
    }

    function renderPacientes() {
      if (!state.pacientes.length) {
        return '<div class="p-8 rounded-2xl bg-white border border-slate-200 text-center text-xs text-slate-500">Aún no hay pacientes registradas en pacientes_sin_metodo.</div>';
      }
      return '<div class="space-y-2.5">' + state.pacientes.map(function (p) {
        return `<div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-2 text-xs">
          <div class="flex items-start justify-between gap-2">
            <div><div class="text-sm font-bold text-slate-900">${esc(p.apellido_paterno)} ${esc(p.apellido_materno)}, ${esc(p.nombres)}</div>
            <div class="text-slate-500 mt-0.5">DNI <span class="font-mono font-semibold text-slate-800">${esc(p.dni)}</span> · ${esc(p.edad)} años · ${esc(p.distrito)}</div></div>
            ${p.atencion_99208 ? '<span class="px-2 py-1 rounded-lg bg-red-100 text-red-800 text-[10px] font-bold shrink-0">99208</span>' : ''}
          </div>
          <div class="text-slate-600">${esc(p.direccion)} · ${esc(p.sector)}</div>
          <div class="flex items-center justify-between pt-2 border-t border-slate-100">
            <span class="font-mono text-slate-700">${esc(p.celular || 'Sin teléfono')}</span>
            <span class="font-semibold text-sky-800">${esc(statusLabel(p.estado_paciente))}</span>
          </div>
          <div class="grid grid-cols-2 gap-1.5 pt-1">${['INSATISFECHA_SIN_METODO', 'SEGUIMIENTO_DOMICILIARIO', 'CONSEJERIA_REALIZADA', 'CAPTADA_CON_METODO'].map(function (e) {
            return '<button type="button" onclick="cambiarEstado(' + Number(p.id) + ',\'' + e + '\')" class="min-h-[36px] rounded-xl border px-2 text-left text-[10px] ' + (p.estado_paciente === e ? 'border-sky-700 bg-sky-50 font-semibold' : 'border-slate-200') + '">' + esc(ESTADOS[e]) + '</button>';
          }).join('')}</div>
        </div>`;
      }).join('') + '</div>';
    }

    const REPORTE_ESTADOS = {
      TOCA_EN_FECHA: { label: 'TOCA EN FECHA', chip: 'bg-amber-100 text-amber-900 border-amber-300', card: 'border-l-4 border-l-amber-500 bg-amber-50/60' },
      PROXIMO_7_DIAS: { label: 'PRÓXIMOS 7 DÍAS', chip: 'bg-sky-100 text-sky-900 border-sky-300', card: 'border-l-4 border-l-sky-500 bg-sky-50/60' },
      VENCIDO_ABANDONO: { label: 'VENCIDA / ABANDONO', chip: 'bg-red-100 text-red-900 border-red-300', card: 'border-l-4 border-l-red-600 bg-red-50/60' },
      AL_DIA: { label: 'AL DÍA', chip: 'bg-emerald-100 text-emerald-900 border-emerald-300', card: 'border-l-4 border-l-emerald-500 bg-emerald-50/60' }
    };

    function reporteMeta(estado) {
      return REPORTE_ESTADOS[estado] || { label: String(estado || 'SIN ESTADO'), chip: 'bg-slate-100 text-slate-700 border-slate-300', card: 'border-l-4 border-l-slate-400 bg-slate-50' };
    }

    function estadoReporteLabel(estado) {
      const meta = REPORTE_ESTADOS[estado];
      return meta ? meta.label : String(estado || '—');
    }

    function soloDigitos(value) {
      return String(value === null || value === undefined ? '' : value).replace(/\D/g, '');
    }

    function celularInternacional(celular) {
      const digitos = soloDigitos(celular);
      if (!digitos) return '';
      if (digitos.length === 9) return '51' + digitos;
      if (digitos.length === 11 && digitos.indexOf('51') === 0) return digitos;
      return digitos;
    }

    function telefonoHref(celular) {
      const numero = celularInternacional(celular);
      return numero ? 'tel:+' + numero : '';
    }

    function whatsappHref(celular) {
      const numero = celularInternacional(celular);
      return numero ? 'https://wa.me/' + numero : '';
    }

    function celularVisible(celular) {
      const digitos = soloDigitos(celular);
      return digitos || 'Sin celular';
    }

    function diasProgramacionTexto(dias) {
      const n = Number(dias);
      if (!Number.isFinite(n)) return 'Sin fecha';
      if (n === 0) return 'Toca hoy';
      return n > 0 ? 'Faltan ' + n + ' días' : 'Vencida hace ' + Math.abs(n) + ' días';
    }

    function descripcionRangoReporte(r) {
      const fecha = r.fecha_objetivo_ddmmyyyy || formatIsoToDdMmYyyy(r.fecha_objetivo);
      if (r.rango_modo === 'ventana_7d') return 'Del ' + fecha + ' a los próximos 7 días';
      if (r.rango_modo === 'vencidas') return 'Vencidas al ' + fecha;
      if (r.rango_modo === 'todos') return 'Día + 7 días + vencidas recientes al ' + fecha;
      return 'Exactamente el ' + fecha;
    }

    function etiquetaFiltroMetodo(r) {
      if (!r.codigo_metodo || r.codigo_metodo === 'TODOS') return 'Todos los métodos';
      const codigos = String(r.codigo_metodo).split(',').map(function (c) { return c.trim(); });
      const nombres = (r.catalogo || []).filter(function (c) { return codigos.indexOf(String(c.codigo_dx)) !== -1; }).map(function (c) { return c.nombre_metodo; });
      return nombres.length ? nombres.join(' / ') : String(r.codigo_metodo);
    }

    function renderReporteCard(fila) {
      const meta = reporteMeta(fila.estado_programacion);
      const tel = telefonoHref(fila.celular);
      return `<div class="p-3 rounded-xl border border-slate-200 ${meta.card} text-xs space-y-1.5">
        <div class="flex items-start justify-between gap-2">
          <div class="font-bold text-slate-900 leading-tight">${esc(fila.paciente_nombre)}</div>
          <span class="px-2 py-0.5 rounded-lg border text-[9px] font-extrabold shrink-0 ${meta.chip}">${esc(meta.label)}</span>
        </div>
        <div class="font-mono text-[10px] text-slate-600">DNI ${esc(fila.dni)} · ${Number(fila.edad || 0)} años · HCL ${esc(fila.historia_clinica || '—')}</div>
        <div class="text-slate-800">💊 <b>${esc(fila.nombre_metodo)}</b> <span class="font-mono">(${esc(fila.codigo_metodo)})</span></div>
        <div class="font-mono text-[10px] leading-relaxed">Aplicado: <b>${esc(fila.fecha_aplicacion)}</b> · Ciclo: ${Number(fila.dias_ciclo || 0)}d<br/>Toca: <b>${esc(fila.fecha_proximo_metodo)}</b> · ${esc(diasProgramacionTexto(fila.dias_restantes))}</div>
        <div class="text-[10px] text-slate-600 leading-relaxed">📍 ${esc(fila.direccion || 'Sin dirección')} · ${esc(fila.sector || 'Sin sector')} · ${esc(fila.distrito || '')}</div>
        <div class="flex items-center justify-between gap-2 pt-1.5 border-t border-slate-200/70">
          <span class="font-mono text-[10px] text-slate-700">📞 ${esc(celularVisible(fila.celular))}</span>
          ${tel ? '<a href="' + esc(tel) + '" class="px-2 py-1 rounded-lg bg-slate-900 text-white text-[10px] font-bold">📞 Llamar</a>' : ''}
        </div>
        <div class="text-[9px] text-slate-500 font-mono">${esc(fila.establecimiento)} · Obstetra ${esc(fila.obstetra_dni || '—')}</div>
      </div>`;
    }

    function catalogoReportes() {
      const lista = (state.catalogoMetodos && state.catalogoMetodos.length)
        ? state.catalogoMetodos
        : ((state.reporteProgramacion && state.reporteProgramacion.catalogo) || []);
      return lista.slice().sort(function (a, b) {
        return Number(a.orden || 0) - Number(b.orden || 0) || String(a.nombre_metodo).localeCompare(String(b.nombre_metodo));
      });
    }

    function renderReporteProgramacion() {
      const r = state.reporteProgramacion;
      const hoy = localIsoDate(0);
      const manana = localIsoDate(1);
      const catalogo = catalogoReportes();
      const filas = (r && r.filas) || [];
      const visibles = filas.slice(0, 120);
      const resumen = (r && r.resumen) || {};
      const puedeEditar = Boolean(state.session && (state.session.isAdmin || state.session.isJefa));
      return `
        ${membreteOficialHtml({
          titulo: 'REPORTE 03 · PROGRAMACIÓN Y SEGUIMIENTO POR MÉTODO',
          subtitulo: 'Próximo control calculado desde la última atención HIS + días de ciclo del método',
          periodo: r ? descripcionRangoReporte(r) : ('Consulta al ' + fechaDdMmYyyy(state.reporteFecha)),
          establecimiento: r && r.establecimiento && r.establecimiento.nombre,
          obstetra: (r && r.obstetra_nombre) || (state.session && state.session.rol === 'OBSTETRA' ? state.session.nombreCompleto : 'TODAS LAS OBSTETRAS DEL ESTABLECIMIENTO')
        })}
        ${renderBotonesOficiales('PROGRAMACION')}
        <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
          <h3 class="text-sm font-bold text-slate-900">Filtros de programación</h3>
          <p class="text-[10px] text-slate-500 leading-relaxed">Los accesos rápidos <b>“Le toca Mañana +1”</b> y <b>“Hoy”</b> calculan automáticamente las pacientes que cumplen su próximo control en esa fecha, usando los 14 métodos oficiales del HIS.</p>
          <div class="grid grid-cols-4 gap-1.5">
            <button type="button" onclick="aplicarRapidoReporte('manana')" class="min-h-[40px] rounded-xl text-[9px] font-bold leading-tight ${state.reporteModo === 'exacto' && state.reporteFecha === manana ? 'bg-sky-700 text-white' : 'bg-slate-100 text-slate-700'}">Le toca<br/>Mañana +1</button>
            <button type="button" onclick="aplicarRapidoReporte('hoy')" class="min-h-[40px] rounded-xl text-[9px] font-bold leading-tight ${state.reporteModo === 'exacto' && state.reporteFecha === hoy ? 'bg-sky-700 text-white' : 'bg-slate-100 text-slate-700'}">Hoy</button>
            <button type="button" onclick="aplicarRapidoReporte('7d')" class="min-h-[40px] rounded-xl text-[9px] font-bold leading-tight ${state.reporteModo === 'ventana_7d' ? 'bg-sky-700 text-white' : 'bg-slate-100 text-slate-700'}">Próximos<br/>7 días</button>
            <button type="button" onclick="aplicarRapidoReporte('vencidas')" class="min-h-[40px] rounded-xl text-[9px] font-bold leading-tight ${state.reporteModo === 'vencidas' ? 'bg-red-700 text-white' : 'bg-slate-100 text-slate-700'}">Vencidas</button>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Fecha en que le toca su control / aplicación</label><input id="rep-fecha" type="date" value="${esc(state.reporteFecha)}" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs font-mono" /></div>
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Método oficial (14 HIS)</label><select id="rep-metodo" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-[10px] bg-white"><option value="TODOS">Todos los métodos</option>${catalogo.map(function (m) { return '<option value="' + esc(m.codigo_dx) + '"' + (state.reporteMetodo === m.codigo_dx ? ' selected' : '') + '>' + esc(m.nombre_metodo) + ' (' + Number(m.dias_ciclo) + 'd)</option>'; }).join('')}</select></div>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Rango</label><select id="rep-rango" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-[10px] bg-white">
              <option value="exacto" ${state.reporteModo === 'exacto' ? 'selected' : ''}>Fecha exacta</option>
              <option value="ventana_7d" ${state.reporteModo === 'ventana_7d' ? 'selected' : ''}>Próximos 7 días</option>
              <option value="vencidas" ${state.reporteModo === 'vencidas' ? 'selected' : ''}>Vencidas</option>
              <option value="todos" ${state.reporteModo === 'todos' ? 'selected' : ''}>Todos</option>
            </select></div>
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Alcance</label><select id="rep-alcance" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-[10px] bg-white">
              <option value="establecimiento" ${state.reporteAlcance === 'establecimiento' ? 'selected' : ''}>Mi establecimiento</option>
              ${state.session && state.session.isAdmin ? '<option value="red" ' + (state.reporteAlcance === 'red' ? 'selected' : '') + '>Toda la Red</option>' : ''}
            </select></div>
          </div>
          ${state.session && !state.session.isAdmin ? `<div><label class="block text-[10px] font-bold text-slate-600 mb-1">Pacientes a programar</label><select id="rep-ambito" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-[10px] bg-white">
            ${state.session.rol === 'OBSTETRA' ? '<option value="mis_atenciones" ' + (state.reporteAmbito === 'mis_atenciones' ? 'selected' : '') + '>Mis atenciones (solo pacientes que atendí)</option>' : ''}
            <option value="establecimiento" ${state.reporteAmbito === 'establecimiento' ? 'selected' : ''}>Mi establecimiento (padrón histórico de mi IPRESS)</option>
          </select></div>` : ''}
          ${state.session && (state.session.isAdmin || state.session.isJefa) ? `<div><label class="block text-[10px] font-bold text-slate-600 mb-1">Obstetra (opcional, DNI o vacío = todas)</label><input id="rep-obstetra" type="text" inputmode="numeric" maxlength="11" value="${esc(state.reporteObstetra)}" placeholder="DNI de la obstetra" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs font-mono" /></div>` : ''}
          <button type="button" onclick="buscarProgramacion()" ${state.reporteLoading ? 'disabled' : ''} class="w-full min-h-[46px] rounded-xl bg-slate-900 hover:bg-slate-800 disabled:opacity-60 text-white text-xs font-bold">${state.reporteLoading ? 'Calculando programación...' : 'Buscar Programación'}</button>
          ${state.reporteError ? '<div class="p-3 rounded-xl bg-red-50 border border-red-200 text-[11px] text-red-800">' + esc(state.reporteError) + '</div>' : ''}
        </div>
        ${puedeEditar ? `<div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-2">
          <h3 class="text-xs font-bold text-slate-900">Editor de días de ciclo · 14 métodos oficiales HIS</h3>
          <p class="text-[10px] text-slate-500">Estadística/Jefatura puede ajustar el ciclo; el cambio recalcula las alertas y la programación.</p>
          <div class="overflow-x-auto -mx-1">
            <table class="w-full text-[10px] border-collapse min-w-[420px]">
              <thead><tr class="bg-slate-100 text-slate-700"><th class="p-2 text-left">Código</th><th class="p-2 text-left">Método</th><th class="p-2 text-center">Días</th><th class="p-2 text-center">Acción</th></tr></thead>
              <tbody>${catalogo.map(function (m) { return '<tr class="border-b border-slate-100"><td class="p-2 font-mono font-bold">' + esc(m.codigo_dx) + '</td><td class="p-2">' + esc(m.nombre_metodo) + '</td><td class="p-2 text-center"><input id="cfg-dias-' + esc(m.codigo_dx) + '" type="number" min="1" max="3650" value="' + Number(m.dias_ciclo || 0) + '" class="w-16 min-h-[34px] px-1 rounded-lg border border-slate-300 text-center font-mono" /></td><td class="p-2 text-center"><button type="button" onclick="guardarDiasCicloOficial(\'' + esc(m.codigo_dx) + '\')" ' + (state.guardandoMetodo ? 'disabled' : '') + ' class="min-h-[32px] px-2 rounded-lg bg-slate-900 text-white text-[9px] font-bold">Guardar</button></td></tr>'; }).join('') || '<tr><td colspan="4" class="p-3 text-center text-slate-500">Catálogo no disponible.</td></tr>'}</tbody>
            </table>
          </div>
        </div>` : ''}
        ${r ? `<div class="p-4 rounded-2xl bg-white border-2 border-sky-200 space-y-3">
          <div class="flex items-start justify-between gap-2">
            <div>
              <h3 class="text-sm font-bold text-slate-900">Programación calculada</h3>
              <p class="text-[10px] text-slate-500">${esc(descripcionRangoReporte(r))} · ${esc(r.alcance === 'red' ? 'Toda la Red Huaral-Chancay' : ((r.establecimiento && r.establecimiento.nombre) || 'Mi establecimiento'))}</p>
              <p class="text-[10px] text-slate-500">Método: ${esc(etiquetaFiltroMetodo(r))}</p>
            </div>
            <span class="px-2.5 py-1 rounded-xl bg-sky-700 text-white text-xs font-extrabold shrink-0">${Number(resumen.total || 0)}</span>
          </div>
          <div class="grid grid-cols-4 gap-1.5 text-center">
            <div class="p-2 rounded-xl bg-red-50 border border-red-200"><div class="text-[8px] font-bold text-red-800">Vencidas</div><div class="text-base font-extrabold font-mono text-red-700">${Number(resumen.vencido_abandono || 0)}</div></div>
            <div class="p-2 rounded-xl bg-amber-50 border border-amber-200"><div class="text-[8px] font-bold text-amber-800">Toca fecha</div><div class="text-base font-extrabold font-mono text-amber-700">${Number(resumen.toca_en_fecha || 0)}</div></div>
            <div class="p-2 rounded-xl bg-sky-50 border border-sky-200"><div class="text-[8px] font-bold text-sky-800">Próx. 7d</div><div class="text-base font-extrabold font-mono text-sky-700">${Number(resumen.proximo_7_dias || 0)}</div></div>
            <div class="p-2 rounded-xl bg-emerald-50 border border-emerald-200"><div class="text-[8px] font-bold text-emerald-800">Al día</div><div class="text-base font-extrabold font-mono text-emerald-700">${Number(resumen.al_dia || 0)}</div></div>
          </div>
          <div class="space-y-2">
            ${visibles.length ? visibles.map(renderReporteCard).join('') : '<div class="p-4 rounded-xl bg-slate-50 border border-slate-200 text-center text-xs text-slate-500">No hay pacientes programadas para los filtros seleccionados.</div>'}
          </div>
          ${filas.length > visibles.length ? '<div class="text-[10px] text-center text-slate-500">Mostrando ' + visibles.length + ' de ' + filas.length + '. El Excel y el PDF oficial incluyen todas las filas.</div>' : ''}
        </div>` : '<div class="p-4 rounded-2xl bg-slate-100 border border-slate-200 text-center text-xs text-slate-600">Seleccione los filtros y presione “Buscar Programación”. También puede usar los accesos rápidos: Mañana +1, Hoy, 7 días o Vencidas.</div>'}`;
    }

    function renderAlertaCard(fila, grupo) {
      const tel = telefonoHref(fila.celular);
      const colores = {
        manana: 'border-l-4 border-l-sky-500 bg-sky-50/70',
        hoy: 'border-l-4 border-l-amber-500 bg-amber-50/70',
        vencidas: 'border-l-4 border-l-red-600 bg-red-50/70'
      };
      const etiquetas = { manana: 'MAÑANA (+1)', hoy: 'HOY', vencidas: 'VENCIDA' };
      return `<div class="p-3 rounded-xl border border-slate-200 ${colores[grupo] || ''} text-xs space-y-1.5">
        <div class="flex items-start justify-between gap-2">
          <div class="font-bold text-slate-900 leading-tight">${esc(fila.paciente_nombre || 'PACIENTE SIN NOMBRE')}</div>
          <div class="flex flex-col items-end gap-1 shrink-0">
            <span class="px-2 py-0.5 rounded-lg bg-slate-900 text-white text-[9px] font-extrabold">${esc(etiquetas[grupo] || grupo)}</span>
            <span class="text-[9px] font-bold text-slate-600">${esc(fila.prioridad_llamada || '')}</span>
          </div>
        </div>
        <div class="font-mono text-[10px] text-slate-600">DNI ${esc(fila.dni)} · ${Number(fila.edad || 0)} años · HCL ${esc(fila.historia_clinica || '—')}</div>
        <div class="text-slate-800">💊 <b>${esc(fila.nombre_metodo || '')}</b> <span class="font-mono">(${esc(fila.codigo_his || fila.codigo_metodo || '')})</span></div>
        <div class="font-mono text-[10px] leading-relaxed">Aplicado: <b>${esc(fila.fecha_aplicacion || '—')}</b> · Ciclo: ${Number(fila.dias_ciclo || 0)}d<br/>Próximo control: <b>${esc(fila.fecha_proximo_metodo || '—')}</b> · ${esc(diasProgramacionTexto(fila.dias_restantes))}</div>
        <div class="text-[10px] text-slate-600 leading-relaxed">📍 ${esc(fila.direccion || 'Sin dirección')} · ${esc(fila.sector || 'Sin sector')} · ${esc(fila.distrito || '')}</div>
        <div class="text-[10px] text-slate-600">🏥 ${esc(fila.establecimiento || '')}</div>
        <div class="flex items-center justify-between gap-2 pt-1.5 border-t border-slate-200/70">
          <span class="font-mono text-[10px] text-slate-700">📞 ${esc(celularVisible(fila.celular))}</span>
          ${tel ? '<a href="' + esc(tel) + '" class="px-3 py-1.5 rounded-lg bg-slate-900 text-white text-[10px] font-bold">📞 Llamar</a>' : '<span class="text-[9px] text-slate-400">Sin teléfono</span>'}
        </div>
      </div>`;
    }

    function renderAgenda() {
      const a = state.alertas || {};
      const gruposDisponibles = [
        { id: 'manana', label: 'Mañana (+1)', total: Number(a.manana || 0) },
        { id: 'hoy', label: 'Hoy', total: Number(a.hoy || 0) },
        { id: 'vencidas', label: 'Vencidas', total: Number(a.vencidas || 0) }
      ];
      const grupos = state.agendaGrupo === 'TODAS' ? gruposDisponibles : gruposDisponibles.filter(function (g) { return g.id === state.agendaGrupo; });
      return `<div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
        <div class="flex items-start justify-between gap-2">
          <div>
            <h3 class="text-sm font-bold text-slate-900">🔔 Agenda de Seguimiento Programático</h3>
            <p class="text-[10px] text-slate-500 leading-relaxed">Pacientes a llamar mañana, hoy y vencidas, calculadas con los 14 métodos oficiales del HIS.</p>
          </div>
          <span class="px-2.5 py-1 rounded-xl bg-amber-700 text-white text-xs font-extrabold shrink-0">${Number(a.total || 0)}</span>
        </div>
        <div class="grid grid-cols-4 gap-1.5">
          <button type="button" onclick="filtrarAgenda('TODAS')" class="min-h-[38px] rounded-xl text-[9px] font-bold ${state.agendaGrupo === 'TODAS' ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-700'}">Todas</button>
          ${gruposDisponibles.map(function (g) { return '<button type="button" onclick="filtrarAgenda(\'' + g.id + '\')" class="min-h-[38px] rounded-xl text-[9px] font-bold ' + (state.agendaGrupo === g.id ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-700') + '">' + esc(g.label) + ' (' + g.total + ')</button>'; }).join('')}
        </div>
        <button type="button" onclick="descargarExcelAlerta()" class="w-full min-h-[42px] rounded-xl bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-bold">📊 Descargar Excel Oficial de la Agenda</button>
      </div>
      ${grupos.map(function (g) {
        const lista = (a.listas && a.listas[g.id]) || [];
        return `<div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-2">
          <div class="flex items-center justify-between"><h3 class="text-xs font-bold text-slate-900">${esc(g.label)}</h3><span class="px-2 py-0.5 rounded-lg bg-slate-100 text-slate-700 text-[10px] font-extrabold">${lista.length}</span></div>
          ${lista.length ? lista.map(function (f) { return renderAlertaCard(f, g.id); }).join('') : '<div class="p-3 text-xs text-slate-500 text-center">Sin pacientes en este grupo.</div>'}
        </div>`;
      }).join('')}`;
    }

    function aplicarRapidoReporte(tipo) {
      if (tipo === 'manana') {
        state.reporteFecha = localIsoDate(1);
        state.reporteModo = 'exacto';
      } else if (tipo === '7d') {
        state.reporteFecha = localIsoDate(0);
        state.reporteModo = 'ventana_7d';
      } else if (tipo === 'vencidas') {
        state.reporteFecha = localIsoDate(0);
        state.reporteModo = 'vencidas';
      } else {
        state.reporteFecha = localIsoDate(0);
        state.reporteModo = 'exacto';
      }
      state.feedback = null;
      state.reporteError = '';
      render();
      buscarProgramacion();
    }

    async function buscarProgramacion() {
      if (!state.token) return;
      const fechaInput = document.getElementById('rep-fecha');
      const metodoInput = document.getElementById('rep-metodo');
      const alcanceInput = document.getElementById('rep-alcance');
      const rangoInput = document.getElementById('rep-rango');
      const ambitoInput = document.getElementById('rep-ambito');
      const obstetraInput = document.getElementById('rep-obstetra');
      if (fechaInput && fechaInput.value) state.reporteFecha = fechaInput.value;
      if (metodoInput) state.reporteMetodo = metodoInput.value || 'TODOS';
      if (alcanceInput) state.reporteAlcance = alcanceInput.value || 'establecimiento';
      if (rangoInput) state.reporteModo = rangoInput.value || 'exacto';
      if (ambitoInput) state.reporteAmbito = ambitoInput.value || 'establecimiento';
      if (obstetraInput) state.reporteObstetra = obstetraInput.value.replace(/[^0-9]/g, '');
      if (!state.reporteFecha) {
        state.reporteError = 'Seleccione una fecha válida para consultar la programación.';
        render();
        return;
      }
      state.reporteLoading = true;
      state.reporteError = '';
      state.feedback = null;
      render();
      try {
        const data = await apiGet('reporte_programacion', {
          fecha_objetivo: state.reporteFecha,
          rango_modo: state.reporteModo,
          alcance: state.reporteAlcance,
          ambito: state.reporteAmbito,
          obstetra: state.reporteObstetra || '',
          codigo_metodo: state.reporteMetodo || 'TODOS'
        });
        state.reporteProgramacion = data;
      } catch (error) {
        state.reporteError = error.message;
        state.reporteProgramacion = null;
      } finally {
        state.reporteLoading = false;
        render();
      }
    }

    function construirExcelReporte(r) {
      const filas = r.filas || [];
      const logoDiresa = DIRESA_LOGO_DATA_URI;
      const logoHospital = HOSPITAL_LOGO_DATA_URI;
      const fechaReporte = r.fecha_objetivo_ddmmyyyy || formatIsoToDdMmYyyy(r.fecha_objetivo);
      const alcance = r.alcance === 'red' ? 'Toda la Red Huaral-Chancay' : ((r.establecimiento && r.establecimiento.nombre) || 'Mi establecimiento');
      const rango = descripcionRangoReporte(r);
      const metodo = etiquetaFiltroMetodo(r);
      const filasHtml = filas.map(function (f) {
        return '<tr>' +
          '<td class="center">' + esc(fechaReporte) + '</td>' +
          '<td>' + esc(f.establecimiento || '') + '</td>' +
          '<td class="mono" style="mso-number-format:\'\\@\'">' + esc(f.dni) + '</td>' +
          '<td>' + esc(f.paciente_nombre) + '</td>' +
          '<td class="center">' + Number(f.edad || 0) + '</td>' +
          '<td class="mono" style="mso-number-format:\'\\@\'">' + esc(f.historia_clinica || '') + '</td>' +
          '<td>' + esc((f.nombre_metodo || '') + ' (' + (f.codigo_metodo || '') + ')') + '</td>' +
          '<td class="center">' + esc(f.fecha_aplicacion || '') + '</td>' +
          '<td class="center">' + Number(f.dias_ciclo || 0) + '</td>' +
          '<td class="center">' + esc(f.fecha_proximo_metodo || '') + '</td>' +
          '<td class="center">' + esc(estadoReporteLabel(f.estado_programacion)) + '</td>' +
          '<td class="mono" style="mso-number-format:\'\\@\'">' + esc(celularVisible(f.celular)) + '</td>' +
          '<td>' + esc(f.direccion || '') + '</td>' +
          '<td>' + esc(f.sector || '') + '</td>' +
          '<td>' + esc(f.distrito || '') + '</td>' +
          '</tr>';
      }).join('');
      return '\ufeff<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">' +
        '<head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />' +
        '<meta name="ProgId" content="Excel.Sheet" />' +
        '<style>' +
        'table { border-collapse: collapse; font-family: Arial, sans-serif; }' +
        'td, th { border: 1px solid #94a3b8; padding: 5px 7px; vertical-align: top; }' +
        'th { background: #0082C8; color: #ffffff; font-weight: bold; font-size: 11pt; text-align: center; }' +
        '.title { background: #0F172A; color: #ffffff; font-size: 16pt; font-weight: bold; text-align: center; border: 1px solid #0F172A; }' +
        '.sub { background: #E0F2FE; color: #0C4A6E; font-size: 11pt; font-weight: bold; text-align: center; }' +
        '.sub2 { background: #F8FAFC; color: #0F172A; font-size: 12pt; font-weight: bold; text-align: center; }' +
        '.label { background: #F1F5F9; font-weight: bold; color: #334155; }' +
        '.meta { color: #334155; font-size: 10pt; }' +
        '.center { text-align: center; }' +
        '.mono { font-family: Consolas, monospace; mso-number-format: "\@"; }' +
        '.total { background: #FEF3C7; font-weight: bold; color: #78350F; text-align: center; }' +
        '</style></head><body>' +
        '<table style="width:100%">' +
        '<tr>' +
        '<td width="240" align="center" valign="middle"><img src="' + logoDiresa + '" width="220" height="75" alt="DIRESA Lima" /></td>' +
        '<td align="center" valign="middle"><div class="title">HOSPITAL SAN JUAN BAUTISTA HUARAL</div><div class="sub">RED DE SALUD HUARAL-CHANCAY · PLANIFICACIÓN FAMILIAR</div><div class="sub2">REPORTE DE PROGRAMACIÓN DE MÉTODOS POR FECHA</div></td>' +
        '<td width="110" align="center" valign="middle"><img src="' + logoHospital + '" width="80" height="85" alt="Hospital San Juan Bautista Huaral" /></td>' +
        '</tr>' +
        '</table>' +
        '<table>' +
        '<tr><td class="label">Fecha de reporte:</td><td colspan="14" class="meta">' + esc(fechaReporte) + '</td></tr>' +
        '<tr><td class="label">Alcance:</td><td colspan="14" class="meta">' + esc(alcance) + '</td></tr>' +
        '<tr><td class="label">Rango consultado:</td><td colspan="14" class="meta">' + esc(rango) + '</td></tr>' +
        '<tr><td class="label">Método:</td><td colspan="14" class="meta">' + esc(metodo) + '</td></tr>' +
        '<tr><td class="label">Total de pacientes:</td><td colspan="14" class="meta">' + Number((r.resumen && r.resumen.total) || filas.length) + '</td></tr>' +
        '<tr><td colspan="15"></td></tr>' +
        '</table>' +
        '<table>' +
        '<thead><tr>' +
        '<th>Fecha de reporte</th><th>Establecimiento</th><th>DNI</th><th>Paciente</th><th>Edad</th>' +
        '<th>HCL</th><th>Método Aplicado</th><th>Fecha de Aplicación</th><th>Ciclo (Días)</th>' +
        '<th>Fecha de Próximo Método</th><th>Estado</th><th>Celular</th><th>Dirección</th><th>Sector</th><th>Distrito</th>' +
        '</tr></thead><tbody>' + filasHtml +
        '<tr><td colspan="15" class="total">Total de registros: ' + filas.length + '</td></tr>' +
        '</tbody></table></body></html>';
    }

    function construirVistaCelularReporte(r) {
      const filas = r.filas || [];
      const fecha = r.fecha_objetivo_ddmmyyyy || formatIsoToDdMmYyyy(r.fecha_objetivo);
      const alcance = r.alcance === 'red' ? 'Toda la Red Huaral-Chancay' : ((r.establecimiento && r.establecimiento.nombre) || 'Mi establecimiento');
      const resumen = r.resumen || {};
      const clases = { TOCA_EN_FECHA: 'toca', PROXIMO_7_DIAS: 'prox', VENCIDO_ABANDONO: 'ven', AL_DIA: 'dia' };
      const tarjetas = filas.map(function (f) {
        const clase = clases[f.estado_programacion] || '';
        const tel = telefonoHref(f.celular);
        const wa = whatsappHref(f.celular);
        return '<div class="card ' + clase + '">' +
          '<div class="top"><strong>' + esc(f.paciente_nombre) + '</strong><span class="badge">' + esc(estadoReporteLabel(f.estado_programacion)) + '</span></div>' +
          '<div class="meta">DNI ' + esc(f.dni) + ' · ' + Number(f.edad || 0) + ' años · HCL ' + esc(f.historia_clinica || '—') + '</div>' +
          '<div class="metodo">💊 ' + esc(f.nombre_metodo) + ' <span class="code">(' + esc(f.codigo_metodo) + ')</span></div>' +
          '<div class="fechas">Aplicado: <strong>' + esc(f.fecha_aplicacion || '—') + '</strong> · Ciclo: ' + Number(f.dias_ciclo || 0) + ' días<br/>Toca: <strong>' + esc(f.fecha_proximo_metodo || '—') + '</strong> · ' + esc(diasProgramacionTexto(f.dias_restantes)) + '</div>' +
          '<div class="dir">📍 ' + esc(f.direccion || 'Sin dirección') + ' · ' + esc(f.sector || 'Sin sector') + ' · ' + esc(f.distrito || '') + '</div>' +
          '<div class="phone">📞 ' + esc(celularVisible(f.celular)) + '</div>' +
          '<div class="actions">' +
          (tel ? '<a class="call" href="' + esc(tel) + '">📞 Llamar</a>' : '') +
          (wa ? '<a class="wa" href="' + esc(wa) + '">WhatsApp</a>' : '') +
          '</div>' +
          '<div class="foot">' + esc(f.establecimiento) + ' · Obstetra ' + esc(f.obstetra_dni || '—') + '</div>' +
          '</div>';
      }).join('');
      return '<!doctype html><html lang="es"><head><meta charset="utf-8" />' +
        '<meta name="viewport" content="width=device-width, initial-scale=1.0" />' +
        '<title>Programación PF · ' + esc(fecha) + '</title><style>' +
        '*{box-sizing:border-box}body{margin:0;background:#eef2f7;color:#0f172a;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif}' +
        '.wrap{max-width:640px;margin:0 auto;padding:12px 10px 24px}.head{background:#0f172a;color:#fff;border-radius:16px;padding:15px;margin-bottom:12px}' +
        '.head h1{font-size:16px;line-height:1.3;margin:0 0 4px}.head p{margin:2px 0;font-size:12px;color:#cbd5e1}' +
        '.chips{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-top:10px}' +
        '.chip{background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.2);border-radius:10px;padding:6px 4px;text-align:center;font-size:10px}' +
        '.chip b{display:block;font-size:17px;margin-top:2px}' +
        '.card{background:#fff;border-radius:14px;padding:13px;margin:11px 0;border-left:8px solid #94a3b8;box-shadow:0 1px 5px rgba(15,23,42,.12)}' +
        '.card.ven{border-left-color:#b91c1c;background:#fef2f2}.card.toca{border-left-color:#d97706;background:#fffbeb}' +
        '.card.prox{border-left-color:#0284c7;background:#f0f9ff}.card.dia{border-left-color:#059669;background:#ecfdf5}' +
        '.top{display:flex;align-items:flex-start;justify-content:space-between;gap:8px;font-size:14px;line-height:1.3}' +
        '.badge{font-size:9px;font-weight:800;padding:3px 7px;border-radius:8px;background:#0f172a;color:#fff;white-space:nowrap;margin-top:1px}' +
        '.meta{font-size:11px;color:#475569;margin:5px 0 0;font-family:Consolas,monospace}' +
        '.metodo{font-size:13px;font-weight:700;margin:7px 0 3px;line-height:1.35}.code{font-weight:400;color:#475569;font-family:Consolas,monospace}' +
        '.fechas{font-size:12px;line-height:1.55;margin-top:3px}.dir{font-size:12px;color:#334155;margin-top:6px;line-height:1.4}' +
        '.phone{font-size:12px;font-family:Consolas,monospace;margin-top:5px}' +
        '.actions{display:flex;gap:7px;margin-top:9px}.actions a{flex:1;text-align:center;padding:10px 6px;border-radius:10px;color:#fff;text-decoration:none;font-weight:800;font-size:13px}' +
        '.call{background:#0f172a}.wa{background:#059669}.foot{font-size:9px;color:#64748b;margin-top:8px;font-family:Consolas,monospace}' +
        '.empty{background:#fff;border-radius:14px;padding:22px;text-align:center;color:#64748b;font-size:12px}' +
        '.end{text-align:center;font-size:10px;color:#64748b;margin-top:16px}' +
        '</style></head><body><div class="wrap">' +
        '<div class="head"><h1>HOSPITAL SAN JUAN BAUTISTA HUARAL</h1><p>Red de Salud Huaral-Chancay · Planificación Familiar</p>' +
        '<p><b>Programación del ' + esc(fecha) + '</b></p><p>' + esc(descripcionRangoReporte(r)) + '</p><p>' + esc(alcance) + '</p>' +
        '<div class="chips"><div class="chip">Total<b>' + Number(resumen.total || 0) + '</b></div><div class="chip">Vencidas<b>' + Number(resumen.vencido_abandono || 0) + '</b></div><div class="chip">Próx. 7d<b>' + Number(resumen.proximo_7_dias || 0) + '</b></div></div></div>' +
        (tarjetas || '<div class="empty">No hay pacientes programadas para los filtros seleccionados.</div>') +
        '<div class="end">Vista autónoma para celular · Generada ' + esc(new Date().toLocaleString('es-PE')) + '</div>' +
        '</div></body></html>';
    }

    function resumenWhatsappReporte(r) {
      const filas = r.filas || [];
      const resumen = r.resumen || {};
      const fecha = r.fecha_objetivo_ddmmyyyy || formatIsoToDdMmYyyy(r.fecha_objetivo);
      const alcance = r.alcance === 'red' ? 'Toda la Red Huaral-Chancay' : ((r.establecimiento && r.establecimiento.nombre) || 'Mi establecimiento');
      const lineas = [];
      lineas.push('📅 PROGRAMACIÓN PLANIFICACIÓN FAMILIAR - ' + fecha);
      lineas.push('🏥 ' + alcance);
      lineas.push('🔎 ' + descripcionRangoReporte(r) + ' · ' + etiquetaFiltroMetodo(r));
      lineas.push('');
      if (!filas.length) {
        lineas.push('Sin pacientes programadas para los filtros seleccionados.');
      } else {
        filas.forEach(function (f) {
          let linea = '• DNI ' + f.dni + ' - ' + f.paciente_nombre +
            ' | Método: ' + f.codigo_metodo + ' (' + Number(f.dias_ciclo || 0) + 'd)' +
            ' | Aplicado: ' + (f.fecha_aplicacion || '—') +
            ' -> Toca: ' + (f.fecha_proximo_metodo || '—');
          if (soloDigitos(f.celular)) linea += ' | Cel: ' + soloDigitos(f.celular);
          lineas.push(linea);
        });
      }
      lineas.push('');
      lineas.push('Total: ' + Number(resumen.total || filas.length) +
        ' · Vencidas: ' + Number(resumen.vencido_abandono || 0) +
        ' · Toca hoy: ' + Number(resumen.toca_en_fecha || 0) +
        ' · Próx. 7d: ' + Number(resumen.proximo_7_dias || 0));
      return lineas.join('\n');
    }

    function exportarReporteExcel() {
      const r = state.reporteProgramacion;
      if (!r) {
        state.feedback = { type: 'error', text: 'Primero busque la programación que desea exportar.' };
        render();
        return;
      }
      const fecha = r.fecha_objetivo || localIsoDate(0);
      descargarArchivo('programacion_pf_' + fecha + '.xls', construirExcelReporte(r), 'application/vnd.ms-excel;charset=utf-8');
      state.feedback = { type: 'success', text: 'Excel generado con ' + Number((r.resumen && r.resumen.total) || (r.filas || []).length) + ' pacientes. Compatible con Excel de PC, WPS y celular.' };
      render();
    }

    function descargarVistaCelular() {
      const r = state.reporteProgramacion;
      if (!r) {
        state.feedback = { type: 'error', text: 'Primero busque la programación que desea descargar.' };
        render();
        return;
      }
      const fecha = r.fecha_objetivo || localIsoDate(0);
      descargarArchivo('programacion_pf_celular_' + fecha + '.html', construirVistaCelularReporte(r), 'text/html;charset=utf-8');
      state.feedback = { type: 'success', text: 'Vista celular descargada. Ábrala sin internet o compártala por WhatsApp.' };
      render();
    }

    async function copiarResumenWhatsapp() {
      const r = state.reporteProgramacion;
      if (!r) {
        state.feedback = { type: 'error', text: 'Primero busque la programación que desea copiar.' };
        render();
        return;
      }
      const texto = resumenWhatsappReporte(r);
      let copiado = false;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(texto);
          copiado = true;
        }
      } catch (error) {
        copiado = false;
      }
      if (!copiado) {
        const area = document.createElement('textarea');
        area.value = texto;
        area.setAttribute('readonly', 'readonly');
        area.style.position = 'fixed';
        area.style.left = '-9999px';
        document.body.appendChild(area);
        area.focus();
        area.select();
        try {
          copiado = document.execCommand('copy');
        } catch (error) {
          copiado = false;
        }
        document.body.removeChild(area);
      }
      state.feedback = {
        type: copiado ? 'success' : 'error',
        text: copiado ? 'Resumen copiado al portapapeles. Péguelo directamente en WhatsApp.' : 'No se pudo copiar automáticamente. Descargue la vista celular y compártala.'
      };
      render();
    }

    function renderPerfil() {
      const s = state.session;
      const esAdmin = Boolean(s.isAdmin);
      const esJefa = Boolean(s.isJefa);
      const puedeReset = Boolean(s.puedeResetearObstetra);
      return `<div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
        <div class="flex items-center gap-3"><div class="w-12 h-12 shrink-0">${HOSPITAL_LOGO_HTML}</div><div class="min-w-0"><div class="text-sm font-bold text-slate-900">${esc(s.nombreCompleto)}</div><div class="text-xs text-slate-500 font-mono">DNI / CODPSAL: ${esc(s.dni)}</div><div class="text-xs text-sky-700">${esc(s.estab_nombre || establishName(s.cod_estab))}</div><div class="text-[10px] font-bold text-slate-600 mt-0.5">Rol: ${esc(s.rol_etiqueta || s.rol || 'OBSTETRA')}</div></div></div>
        <div class="pt-3 border-t border-slate-100 flex items-center justify-between text-xs"><span class="text-slate-600">Instalación en celular</span><button type="button" onclick="installPwa()" class="min-h-[38px] px-3 rounded-xl bg-slate-900 text-white text-xs font-semibold">Instalar App</button></div>
      </div>
      <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-2.5">
        <div class="text-xs font-bold text-slate-900">Instalación Android / iPhone</div>
        <div class="rounded-xl bg-sky-50 border border-sky-200 px-3 py-2 text-[11px] text-sky-950 leading-relaxed">
          <strong>Android (Chrome):</strong> menú ⋮ → “Instalar aplicación” o “Agregar a pantalla de inicio”.<br />
          <strong>iPhone (Safari):</strong> Compartir → “Agregar a pantalla de inicio”.
        </div>
        ${APK_URL ? `<a href="${APK_URL}" download class="block text-center w-full min-h-[44px] leading-[44px] rounded-xl bg-emerald-700 text-white text-xs font-bold">Descargar APK Android</a>` : ''}
        <div class="flex items-center justify-between text-[11px] text-slate-600"><span>${state.offlinePending > 0 ? state.offlinePending + ' captación(es) cifradas pendientes' : 'Cola offline vacía'}</span><button type="button" onclick="sincronizarOffline()" ${state.syncingOffline ? 'disabled' : ''} class="px-2.5 py-1.5 rounded-lg bg-slate-900 text-white font-semibold">${state.syncingOffline ? 'Sincronizando...' : 'Sincronizar'}</button></div>
      </div>
      ${esJefa ? renderEquipoJefatura() : ''}
      <div class="p-4 rounded-2xl bg-white border-2 border-sky-200 space-y-3">
        <div>
          <h3 class="text-sm font-bold text-slate-900">Mis Datos Personales y Seguridad</h3>
          <p class="text-[10px] text-slate-500">Actualice sus nombres y apellidos, celular, correo, establecimiento (53 IPRESS), PIN de recuperación de 4 dígitos y contraseña. Deje vacío lo que no desea cambiar.</p>
        </div>
        <form onsubmit="handlePerfil(event)" class="space-y-2.5">
          <div class="grid grid-cols-2 gap-2">
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Nombres</label><input id="per-nombres" type="text" value="${esc(s.nombres || '')}" placeholder="NOMBRES" class="w-full min-h-[42px] px-3 rounded-xl border border-slate-300 text-xs" /></div>
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Apellido paterno</label><input id="per-ap" type="text" value="${esc(s.apellido_paterno || '')}" placeholder="APELLIDO PATERNO" class="w-full min-h-[42px] px-3 rounded-xl border border-slate-300 text-xs" /></div>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Apellido materno</label><input id="per-am" type="text" value="${esc(s.apellido_materno || '')}" placeholder="APELLIDO MATERNO" class="w-full min-h-[42px] px-3 rounded-xl border border-slate-300 text-xs" /></div>
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Celular</label><input id="per-cel" type="tel" inputmode="numeric" value="${esc(s.celular || '')}" placeholder="987654321" class="w-full min-h-[42px] px-3 rounded-xl border border-slate-300 text-xs font-mono" /></div>
          </div>
          <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Correo electrónico</label><input id="per-email" type="email" value="${esc(s.email || '')}" placeholder="obstetra@hospitalhuaral.gob.pe" class="w-full min-h-[42px] px-3 rounded-xl border border-slate-300 text-xs" /></div>
          <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Establecimiento (53 IPRESS)</label><select id="per-estab" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs bg-white">${optionsEstablecimientos(s.cod_estab || '000005481')}</select></div>
          <div class="grid grid-cols-2 gap-2">
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">PIN recuperación (4 dígitos)</label><input id="per-pin" type="password" inputmode="numeric" maxlength="4" placeholder="Solo si desea cambiarlo" class="w-full min-h-[42px] px-3 rounded-xl border border-slate-300 text-xs font-mono" /></div>
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Nueva contraseña</label><input id="per-pass" type="password" minlength="8" placeholder="Mínimo 8 caracteres" class="w-full min-h-[42px] px-3 rounded-xl border border-slate-300 text-xs" /></div>
          </div>
          <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Confirmar nueva contraseña</label><input id="per-pass2" type="password" minlength="8" placeholder="Repita la contraseña" class="w-full min-h-[42px] px-3 rounded-xl border border-slate-300 text-xs" /></div>
          <button type="submit" class="w-full min-h-[46px] rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-xs font-bold">Guardar Mis Datos y Seguridad</button>
        </form>
      </div>
      ${puedeReset ? `<div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-2.5">
        <h3 class="text-sm font-bold text-slate-900">Restablecer clave de una obstetra</h3>
        <p class="text-[10px] text-slate-500">${esAdmin ? 'Administrador de Estadística' : 'Jefatura de Obstetras'}: la contraseña temporal será el propio DNI de la obstetra y se limpiará su PIN.</p>
        <div class="flex gap-2">
          <input id="reset-dni" type="text" inputmode="numeric" maxlength="11" value="${esc(state.resetDni || '')}" placeholder="DNI de la obstetra" class="flex-1 min-h-[42px] px-3 rounded-xl border border-slate-300 text-xs font-mono" />
          <button type="button" onclick="resetearClaveManual()" class="min-h-[42px] px-3 rounded-xl bg-amber-700 text-white text-xs font-bold shrink-0">Restablecer</button>
        </div>
      </div>` : ''}
      ${esAdmin ? renderAdminPanel() : ''}
      <button type="button" onclick="logout()" class="w-full min-h-[48px] rounded-2xl border border-red-200 bg-red-50 text-red-700 text-sm font-semibold">Cerrar Sesión</button>`;
    }

    function renderEquipoJefatura() {
      const d = state.equipoData;
      const obstetras = (d && d.obstetras) || [];
      return `<div class="p-4 rounded-2xl bg-white border-2 border-emerald-200 space-y-3">
        <div class="flex items-start justify-between gap-2">
          <div>
            <h3 class="text-sm font-bold text-slate-900">👩‍⚕️ Equipo de Obstetras de mi Establecimiento</h3>
            <p class="text-[10px] text-slate-500">${esc((d && d.establecimiento && d.establecimiento.nombre) || state.session.estab_nombre || '')}</p>
          </div>
          <span class="px-2.5 py-1 rounded-xl bg-emerald-700 text-white text-xs font-extrabold shrink-0">${obstetras.length}</span>
        </div>
        <button type="button" onclick="cargarEquipoJefatura(true)" ${state.equipoLoading ? 'disabled' : ''} class="w-full min-h-[38px] rounded-xl bg-emerald-700 text-white text-[10px] font-bold disabled:opacity-60">${state.equipoLoading ? 'Cargando equipo...' : 'Actualizar equipo de obstetras'}</button>
        <div class="space-y-2">
          ${obstetras.length ? obstetras.map(function (o) { return `<div class="p-2.5 rounded-xl border ${Number(o.activo) === 1 ? 'border-emerald-200 bg-emerald-50/50' : 'border-red-200 bg-red-50/50'} space-y-1">
            <div class="flex items-start justify-between gap-2"><div class="min-w-0"><div class="text-[11px] font-bold text-slate-900 truncate">${esc(o.nombre_completo || (o.nombres + ' ' + o.apellido_paterno + ' ' + o.apellido_materno))}</div><div class="font-mono text-[9px] text-slate-600">DNI ${esc(o.dni)} · ${Number(o.activo) === 1 ? 'ACTIVA' : 'INACTIVA'}</div></div><span class="px-2 py-0.5 rounded-lg bg-slate-900 text-white text-[8px] font-extrabold">${Number(o.captadas_mes || 0)} este mes</span></div>
            <div class="grid grid-cols-4 gap-1 text-center text-[9px] font-mono">
              <div class="p-1 rounded-lg bg-white border border-slate-200"><div class="text-slate-500">Hoy</div><b>${Number(o.captadas_hoy || 0)}</b></div>
              <div class="p-1 rounded-lg bg-white border border-slate-200"><div class="text-slate-500">Mes</div><b>${Number(o.captadas_mes || 0)}</b></div>
              <div class="p-1 rounded-lg bg-white border border-slate-200"><div class="text-slate-500">Total</div><b>${Number(o.total_captadas || 0)}</b></div>
              <div class="p-1 rounded-lg bg-white border border-slate-200"><div class="text-slate-500">Últ. act.</div><b>${esc((o.ultima_actividad || '—').slice(0, 10))}</b></div>
            </div>
            <div class="flex items-center justify-between gap-2 text-[9px] text-slate-500"><span>Último login: ${esc(o.ultimo_login || '—')}</span><button type="button" onclick="resetearClaveUsuario('${esc(o.dni)}','${esc(String(o.nombre_completo || o.dni).replace(/'/g, ' '))}')" class="min-h-[28px] px-2 rounded-lg bg-amber-700 text-white text-[8px] font-bold">Restablecer clave</button></div>
          </div>`; }).join('') : '<div class="p-3 text-[10px] text-slate-500 text-center">No hay obstetras registradas en su establecimiento.</div>'}
        </div>
      </div>`;
    }

    function renderAdminPanel() {
      const tabs = [
        { id: 'DIRECTORIO', label: 'Directorio / Control' },
        { id: 'MOVIMIENTOS', label: 'Movimientos' },
        { id: 'SYNC_LOGO', label: 'Sync y Logo' }
      ];
      return `<div class="p-4 rounded-2xl bg-white border-2 border-slate-300 space-y-3">
        <div>
          <h3 class="text-sm font-bold text-slate-900">Panel del Administrador de Estadística</h3>
          <p class="text-[10px] text-slate-500">Control total de las 53 IPRESS: usuarios, roles, establecimientos, movimientos y personalización del logo.</p>
        </div>
        <div class="grid grid-cols-3 gap-1 p-1 bg-slate-100 rounded-xl">
          ${tabs.map(function (t) { return '<button type="button" onclick="setAdminTab(\'' + t.id + '\')" class="min-h-[38px] rounded-lg text-[9px] font-bold ' + (state.adminTab === t.id ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600') + '">' + esc(t.label) + '</button>'; }).join('')}
        </div>
        ${state.adminTab === 'DIRECTORIO' ? renderAdminDirectorio() : ''}
        ${state.adminTab === 'MOVIMIENTOS' ? renderAdminMovimientos() : ''}
        ${state.adminTab === 'SYNC_LOGO' ? renderAdminSyncLogo() : ''}
      </div>`;
    }

    function renderAdminDirectorio() {
      const roles = (state.accesosData && state.accesosData.roles) || [
        { codigo: 'OBSTETRA', etiqueta: 'Obstetra' },
        { codigo: 'JEFA_OBSTETRAS', etiqueta: 'Jefa de Obstetras' },
        { codigo: 'ADMIN_ESTADISTICA', etiqueta: 'Administrador de Estadística' }
      ];
      const accesos = (state.accesosData && state.accesosData.accesos) || [];
      const filtros = state.accesosFiltros || {};
      return `<div class="space-y-3">
        <div class="grid grid-cols-2 gap-2">
          <input id="acc-q" type="search" value="${esc(filtros.q || '')}" oninput="state.accesosFiltros.q=this.value" placeholder="DNI o nombre" class="col-span-2 min-h-[38px] px-2 rounded-xl border border-slate-300 text-[10px]" />
          <select onchange="state.accesosFiltros.rol=this.value" class="min-h-[38px] px-1 rounded-xl border border-slate-300 text-[9px] bg-white">
            <option value="TODOS" ${filtros.rol === 'TODOS' ? 'selected' : ''}>Todos los roles</option>
            ${roles.map(function (r) { return '<option value="' + esc(r.codigo) + '"' + (filtros.rol === r.codigo ? ' selected' : '') + '>' + esc(r.etiqueta) + '</option>'; }).join('')}
          </select>
          <select onchange="state.accesosFiltros.cod_estab=this.value" class="min-h-[38px] px-1 rounded-xl border border-slate-300 text-[9px] bg-white"><option value="TODOS" ${filtros.cod_estab === 'TODOS' ? 'selected' : ''}>Todos los establecimientos</option>${optionsEstablecimientos(filtros.cod_estab && filtros.cod_estab !== 'TODOS' ? filtros.cod_estab : '')}</select>
          <select onchange="state.accesosFiltros.activo=this.value" class="min-h-[38px] px-1 rounded-xl border border-slate-300 text-[9px] bg-white">
            <option value="TODOS" ${filtros.activo === 'TODOS' ? 'selected' : ''}>Activos e inactivos</option>
            <option value="1" ${filtros.activo === '1' ? 'selected' : ''}>Solo activos</option>
            <option value="0" ${filtros.activo === '0' ? 'selected' : ''}>Solo inactivos</option>
          </select>
          <button type="button" onclick="cargarAccesos(true)" ${state.accesosLoading ? 'disabled' : ''} class="min-h-[38px] rounded-xl bg-slate-900 text-white text-[10px] font-bold disabled:opacity-60">${state.accesosLoading ? 'Buscando...' : 'Buscar / Actualizar'}</button>
        </div>
        <button type="button" onclick="abrirAccesoModal()" class="w-full min-h-[42px] rounded-xl bg-emerald-700 text-white text-xs font-bold">+ Agregar / Activar Usuario o Jefa</button>
        ${state.accesosError ? '<div class="p-2 rounded-xl bg-red-50 border border-red-200 text-[10px] text-red-800">' + esc(state.accesosError) + '</div>' : ''}
        <div class="space-y-2">
          ${accesos.length ? accesos.map(function (a) { return `<div class="p-2.5 rounded-xl border ${Number(a.activo) === 1 ? 'border-emerald-200 bg-emerald-50/50' : 'border-red-200 bg-red-50/50'} space-y-1.5">
            <div class="flex items-start justify-between gap-2"><div class="min-w-0"><div class="text-[11px] font-bold text-slate-900 truncate">${esc(a.nombre_completo)}</div><div class="font-mono text-[9px] text-slate-600">DNI ${esc(a.dni)} · ${esc(a.rol_etiqueta || a.rol)}</div><div class="text-[9px] text-slate-500">${esc(a.estab_nombre || '')}</div></div><span class="px-2 py-0.5 rounded-lg text-[8px] font-extrabold ${Number(a.activo) === 1 ? 'bg-emerald-700 text-white' : 'bg-red-700 text-white'}">${Number(a.activo) === 1 ? 'ACTIVO' : 'INACTIVO'}</span></div>
            <div class="grid grid-cols-3 gap-1 text-center text-[9px] font-mono">
              <div class="p-1 rounded-lg bg-white border border-slate-200"><div class="text-slate-500">Captadas</div><b>${Number(a.total_captadas || 0)}</b></div>
              <div class="p-1 rounded-lg bg-white border border-slate-200"><div class="text-slate-500">Últ. captura</div><b>${esc((a.ultima_captura || '—').slice(0, 10))}</b></div>
              <div class="p-1 rounded-lg bg-white border border-slate-200"><div class="text-slate-500">Últ. login</div><b>${esc((a.ultimo_login || '—').slice(0, 10))}</b></div>
            </div>
            <div class="grid grid-cols-2 gap-1">
              <select onchange="cambiarRolUsuario('${esc(a.dni)}', this.value)" class="min-h-[30px] px-1 rounded-lg border border-slate-300 bg-white text-[8px] font-bold">${roles.map(function (r) { return '<option value="' + esc(r.codigo) + '"' + (a.rol === r.codigo ? ' selected' : '') + '>' + esc(r.etiqueta) + '</option>'; }).join('')}</select>
              <button type="button" onclick="editarAcceso('${esc(a.dni)}')" class="min-h-[30px] rounded-lg border border-slate-300 bg-white text-[8px] font-bold">Editar datos</button>
              <button type="button" onclick="cambiarEstadoAcceso('${esc(a.dni)}',${Number(a.activo) === 1 ? 0 : 1})" class="min-h-[30px] rounded-lg ${Number(a.activo) === 1 ? 'bg-red-700' : 'bg-emerald-700'} text-white text-[8px] font-bold">${Number(a.activo) === 1 ? 'Desactivar' : 'Activar'}</button>
              <button type="button" onclick="resetearClaveUsuario('${esc(a.dni)}','${esc(String(a.nombre_completo).replace(/'/g, ' '))}')" class="min-h-[30px] rounded-lg bg-amber-700 text-white text-[8px] font-bold">Clave = DNI</button>
            </div>
            <div class="text-[9px] text-slate-500 truncate">✉️ ${esc(a.email || '—')} · 📞 ${esc(a.celular || '—')}</div>
          </div>`; }).join('') : '<div class="p-3 text-[10px] text-slate-500 text-center">Presione “Buscar / Actualizar” para listar usuarios.</div>'}
        </div>
        ${state.showAccesoModal ? renderAccesoModal() : ''}
      </div>`;
    }

    function renderAccesoModal() {
      const roles = (state.accesosData && state.accesosData.roles) || [
        { codigo: 'OBSTETRA', etiqueta: 'Obstetra' },
        { codigo: 'JEFA_OBSTETRAS', etiqueta: 'Jefa de Obstetras' },
        { codigo: 'ADMIN_ESTADISTICA', etiqueta: 'Administrador de Estadística' }
      ];
      const form = state.accesoForm || {};
      return `<div class="fixed inset-0 z-50 bg-slate-900/60 flex items-end sm:items-center justify-center p-3">
        <div class="w-full max-w-[420px] max-h-[88vh] overflow-y-auto rounded-2xl bg-white border border-slate-300 p-4 space-y-3">
          <div class="flex items-center justify-between"><h3 class="text-sm font-bold text-slate-900">Agregar / Activar Usuario o Jefa</h3><button type="button" onclick="cerrarAccesoModal()" class="min-h-[34px] min-w-[34px] rounded-lg bg-slate-100 text-slate-700 font-bold">×</button></div>
          <div class="grid grid-cols-2 gap-2">
            <input id="acc-dni" type="text" inputmode="numeric" maxlength="11" value="${esc(form.dni || '')}" oninput="buscarPersonaDebounce(this.value)" placeholder="DNI" class="min-h-[38px] px-2 rounded-xl border border-slate-300 text-[10px] font-mono" />
            <input id="acc-email" type="email" value="${esc(form.email || '')}" placeholder="Correo" class="min-h-[38px] px-2 rounded-xl border border-slate-300 text-[10px]" />
          </div>
          <div class="grid grid-cols-2 gap-2">
            <input id="acc-nombres" type="text" value="${esc(form.nombres || '')}" placeholder="Nombres" class="min-h-[38px] px-2 rounded-xl border border-slate-300 text-[10px]" />
            <input id="acc-ap" type="text" value="${esc(form.apellido_paterno || '')}" placeholder="Apellido paterno" class="min-h-[38px] px-2 rounded-xl border border-slate-300 text-[10px]" />
            <input id="acc-am" type="text" value="${esc(form.apellido_materno || '')}" placeholder="Apellido materno" class="min-h-[38px] px-2 rounded-xl border border-slate-300 text-[10px]" />
            <input id="acc-cel" type="tel" inputmode="numeric" value="${esc(form.celular || '')}" placeholder="Celular" class="min-h-[38px] px-2 rounded-xl border border-slate-300 text-[10px] font-mono" />
          </div>
          ${state.personasSugeridas.length ? `<div class="space-y-1 max-h-32 overflow-y-auto">${state.personasSugeridas.map(function (p) { return '<button type="button" onclick="seleccionarPersona(\'' + esc(p.dni) + '\',\'' + esc(String(p.nombre).replace(/'/g, ' ')) + '\')" class="block w-full text-left px-2 py-1.5 rounded-lg bg-white border border-slate-200 text-[10px]"><b>' + esc(p.dni) + '</b> · ' + esc(p.nombre) + ' <span class="text-slate-400">(' + esc(p.origen) + ')</span></button>'; }).join('')}</div>` : ''}
          <div class="grid grid-cols-2 gap-2">
            <select onchange="state.accesoForm.rol=this.value" class="min-h-[38px] px-1 rounded-xl border border-slate-300 text-[9px] bg-white">${roles.map(function (r) { return '<option value="' + esc(r.codigo) + '"' + (form.rol === r.codigo ? ' selected' : '') + '>' + esc(r.etiqueta) + '</option>'; }).join('')}</select>
            <input id="acc-pin" type="password" inputmode="numeric" maxlength="4" value="${esc(form.pin || '')}" placeholder="PIN 4 dígitos (opcional)" class="min-h-[38px] px-2 rounded-xl border border-slate-300 text-[10px] font-mono" />
          </div>
          <select onchange="state.accesoForm.cod_estab=this.value" class="w-full min-h-[38px] px-1 rounded-xl border border-slate-300 text-[9px] bg-white">${optionsEstablecimientos(form.cod_estab || state.session.cod_estab || '000005481')}</select>
          <input id="acc-pass" type="password" minlength="8" value="${esc(form.password || '')}" placeholder="Contraseña inicial (opcional, mínimo 8)" class="w-full min-h-[38px] px-2 rounded-xl border border-slate-300 text-[10px]" />
          <label class="flex items-center gap-2 text-[10px] font-semibold text-slate-700"><input type="checkbox" ${Number(form.activo || 0) === 1 ? 'checked' : ''} onchange="state.accesoForm.activo=this.checked?1:0" /> Acceso activo</label>
          <button type="button" onclick="guardarAcceso()" class="w-full min-h-[42px] rounded-xl bg-emerald-700 text-white text-[11px] font-bold">Guardar en app_usuarios</button>
        </div>
      </div>`;
    }

    function renderAdminMovimientos() {
      const f = state.movimientosFiltros || {};
      const d = state.movimientosData;
      const movimientos = (d && d.movimientos) || [];
      const acciones = (d && d.acciones) || [];
      return `<div class="space-y-3">
        <div class="grid grid-cols-2 gap-2">
          <input id="mov-q" type="search" value="${esc(f.q || '')}" oninput="state.movimientosFiltros.q=this.value" placeholder="DNI o nombre del obstetra" class="col-span-2 min-h-[38px] px-2 rounded-xl border border-slate-300 text-[10px]" />
          <select onchange="state.movimientosFiltros.accion=this.value" class="min-h-[38px] px-1 rounded-xl border border-slate-300 text-[9px] bg-white"><option value="TODAS" ${f.accion === 'TODAS' ? 'selected' : ''}>Todos los movimientos</option>${acciones.map(function (a) { return '<option value="' + esc(a) + '"' + (f.accion === a ? ' selected' : '') + '>' + esc(a) + '</option>'; }).join('')}</select>
          <select onchange="state.movimientosFiltros.cod_estab=this.value" class="min-h-[38px] px-1 rounded-xl border border-slate-300 text-[9px] bg-white"><option value="TODOS" ${f.cod_estab === 'TODOS' ? 'selected' : ''}>Todos los establecimientos</option>${optionsEstablecimientos(f.cod_estab && f.cod_estab !== 'TODOS' ? f.cod_estab : '')}</select>
          <input id="mov-desde" type="date" value="${esc(f.fecha_desde || '')}" onchange="state.movimientosFiltros.fecha_desde=this.value" class="min-h-[38px] px-2 rounded-xl border border-slate-300 text-[10px] font-mono" />
          <input id="mov-hasta" type="date" value="${esc(f.fecha_hasta || '')}" onchange="state.movimientosFiltros.fecha_hasta=this.value" class="min-h-[38px] px-2 rounded-xl border border-slate-300 text-[10px] font-mono" />
          <button type="button" onclick="cargarMovimientos(true)" ${state.movimientosLoading ? 'disabled' : ''} class="col-span-2 min-h-[40px] rounded-xl bg-slate-900 text-white text-[10px] font-bold disabled:opacity-60">${state.movimientosLoading ? 'Consultando movimientos...' : 'Buscar movimientos'}</button>
        </div>
        ${state.movimientosError ? '<div class="p-2 rounded-xl bg-red-50 border border-red-200 text-[10px] text-red-800">' + esc(state.movimientosError) + '</div>' : ''}
        <div class="text-[10px] text-slate-500">${d ? (Number(d.total || 0) + ' movimientos encontrados · página ' + Number(d.pagina || 1)) : 'Seleccione filtros y presione Buscar.'}</div>
        <div class="divide-y divide-slate-100 max-h-[420px] overflow-y-auto">
          ${movimientos.length ? movimientos.map(function (m) { return '<div class="py-2 text-[10px] space-y-0.5"><div class="flex items-center justify-between gap-2 font-mono text-slate-500"><span class="font-bold text-slate-800">' + esc(m.accion) + '</span><span>' + esc(m.fecha_hora) + '</span></div><div class="text-slate-700">' + esc(m.detalle) + '</div><div class="text-slate-500 font-mono">' + esc(m.actor_nombre || m.actor_dni) + ' · DNI ' + esc(m.actor_dni) + ' · ' + esc(m.estab_nombre || m.actor_estab) + ' · ' + esc(m.plataforma || '') + '</div></div>'; }).join('') : '<div class="py-3 text-[10px] text-slate-500 text-center">Sin movimientos para los filtros seleccionados.</div>'}
        </div>
      </div>`;
    }

    function renderAdminSyncLogo() {
      return `<div class="space-y-3">
        <div class="rounded-xl border border-slate-200 p-3 space-y-2">
          <h4 class="text-xs font-bold text-slate-900">Exportación Nube → Local (5 GB)</h4>
          <p class="text-[10px] text-slate-500">Solo INSERT ... ON DUPLICATE KEY UPDATE, sin DROP/DELETE. Las tablas app_* nunca se exportan.</p>
          <select id="sync-mode" class="w-full min-h-[38px] px-2 rounded-xl border border-slate-300 text-[10px] bg-white">
            <option value="directo" ${state.syncMode === 'directo' ? 'selected' : ''}>Directo · ON DUPLICATE KEY UPDATE</option>
            <option value="puente" ${state.syncMode === 'puente' ? 'selected' : ''}>Puente · r_his_dl + sp_get_recepcion()</option>
          </select>
          <button type="button" onclick="generarExportacion()" class="w-full min-h-[40px] rounded-xl bg-slate-900 text-white text-[10px] font-bold">${state.loadingSync ? 'Generando...' : 'Generar exportación SQL'}</button>
          ${state.syncExport ? `<div class="p-2 rounded-xl bg-slate-50 border border-slate-200 text-[10px] space-y-1"><div class="font-semibold">${esc(state.syncExport.filename)} · ${state.syncExport.rows} filas</div><div class="text-slate-600">${esc((state.syncExport.tables || []).join(', ') || 'Sin tablas locales')}</div><div class="flex gap-2 pt-1"><button type="button" onclick="descargarExportacion()" class="px-2 py-1.5 rounded-lg bg-teal-700 text-white font-semibold">Descargar SQL</button><button type="button" onclick="descargarIndices()" class="px-2 py-1.5 rounded-lg bg-slate-800 text-white font-semibold">Descargar índices</button></div></div>` : ''}
        </div>
        <div class="rounded-xl border border-slate-200 p-3 space-y-2">
          <h4 class="text-xs font-bold text-slate-900">Membrete institucional oficial</h4>
          <p class="text-[10px] text-slate-500">Los reportes usan siempre los logos originales e intactos: DIRESA Lima (public/logo-diresa-lima.jpg) a la izquierda y Hospital San Juan Bautista Huaral (public/logo.png) a la derecha. No se aplican recortes, filtros ni SVG inventados.</p>
          <div class="flex items-center gap-3">
            <div class="h-12 w-40 rounded-lg border border-slate-300 bg-white overflow-hidden flex items-center justify-center">${logoReportesHtml()}</div>
            <div class="w-12 h-14 rounded-lg border border-slate-300 bg-white overflow-hidden flex items-center justify-center">${HOSPITAL_LOGO_HTML}</div>
          </div>
        </div>
      </div>`;
    }

    // ---------------------------------------------------------------------
    // Reportes y Seguimiento (Campo/Captación + Indicadores por Método)
    // ---------------------------------------------------------------------
    function estadoPacienteBadge(estado) {
      const mapa = {
        CAPTADA_CON_METODO: 'bg-emerald-100 text-emerald-900 border-emerald-300',
        INSATISFECHA_SIN_METODO: 'bg-red-100 text-red-900 border-red-300',
        SEGUIMIENTO_DOMICILIARIO: 'bg-amber-100 text-amber-900 border-amber-300',
        CONSEJERIA_REALIZADA: 'bg-sky-100 text-sky-900 border-sky-300',
        RECHAZA_METODO: 'bg-slate-200 text-slate-800 border-slate-400'
      };
      return mapa[estado] || 'bg-slate-100 text-slate-700 border-slate-300';
    }

    function estadoIndicadorBadge(estado) {
      const mapa = {
        VIGENTE: 'bg-emerald-100 text-emerald-900 border-emerald-300',
        PROXIMA: 'bg-amber-100 text-amber-900 border-amber-300',
        VENCIDA: 'bg-red-100 text-red-900 border-red-300',
        SIN_METODO: 'bg-slate-200 text-slate-800 border-slate-400'
      };
      return mapa[estado] || 'bg-slate-100 text-slate-700 border-slate-300';
    }

    function estadoPacienteTexto(estado) {
      return ESTADOS[estado] || estado || 'Sin estado';
    }

    function fechaDdMmYyyy(iso) {
      const valor = String(iso || '').slice(0, 10);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(valor)) return valor;
      return formatIsoToDdMmYyyy(valor);
    }

    function horaDeFecha(valor) {
      const texto = String(valor || '');
      return texto.length >= 19 ? texto.slice(11, 19) : texto;
    }

    function renderReportes() {
      const vistas = [
        { id: 'CAMPO', label: '01 · Campo' },
        { id: 'PRODUCTIVIDAD', label: '02 · Productividad' },
        { id: 'PROGRAMACION', label: '03 · Programación' },
        { id: 'PADRON', label: '04 · Padrón' }
      ];
      return `
        <div class="space-y-3">
          ${state.feedback ? `<div class="p-3 rounded-xl border text-[11px] ${state.feedback.type === 'error' ? 'bg-red-50 border-red-200 text-red-800' : 'bg-emerald-50 border-emerald-200 text-emerald-900'}">${esc(state.feedback.text)}</div>` : ''}
          <div class="p-4 rounded-2xl bg-slate-900 text-white">
            <div class="text-[10px] font-bold uppercase tracking-wider text-sky-300">Reportes Oficiales · Planificación Familiar</div>
            <h2 class="text-base font-bold">4 reportes con membrete institucional</h2>
            <p class="text-[11px] text-slate-300 mt-0.5">Hospital San Juan Bautista de Huaral · Red de Salud Huaral-Chancay</p>
          </div>
          ${state.session && state.session.isJefa ? renderEquipoJefatura() : ''}
          <div class="grid grid-cols-2 gap-1 p-1 bg-slate-100 rounded-xl">
            ${vistas.map(function (v) {
              return '<button type="button" onclick="setVistaReporte(\'' + v.id + '\')" class="min-h-[44px] rounded-lg text-[10px] font-bold ' + (state.reporteVista === v.id ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600') + '">' + esc(v.label) + '</button>';
            }).join('')}
          </div>
          ${state.reporteVista === 'CAMPO' ? renderReporteCampo() : ''}
          ${state.reporteVista === 'PRODUCTIVIDAD' ? renderReporteProductividad() : ''}
          ${state.reporteVista === 'PROGRAMACION' ? renderReporteProgramacion() : ''}
          ${state.reporteVista === 'PADRON' ? renderReportePadron() : ''}
        </div>`;
    }

    function renderReporteCampo() {
      const f = state.campoFiltros;
      const d = state.campoData;
      const resumen = (d && d.resumen) || { total_pacientes: 0, satisfechas: 0, insatisfechas: 0, con_99208: 0 };
      const sectores = (d && d.sectores) || [];
      const obstetras = (d && d.obstetras) || [];
      const pag = (d && d.paginacion) || { page: 1, pages: 1, total: 0 };
      const filas = (d && d.filas) || [];
      const productividad = (d && d.productividad) || [];
      return `
        ${membreteOficialHtml({
          titulo: 'REPORTE 01 · PACIENTES CAPTADAS EN CAMPO / BARRIDO',
          subtitulo: 'Captación domiciliaria y barrido de Planificación Familiar',
          periodo: fechaDdMmYyyy(f.fecha_desde) + ' al ' + fechaDdMmYyyy(f.fecha_hasta),
          establecimiento: (d && d.establecimiento && d.establecimiento.nombre) || '',
          obstetra: (d && d.obstetra_nombre) || (f.obstetra !== 'TODOS' ? f.obstetra : '')
        })}
        ${renderBotonesOficiales('CAMPO')}
        <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
          <div class="flex items-center justify-between">
            <h3 class="text-sm font-bold text-slate-900">1. Reporte de Campo y Captación</h3>
            <span class="text-[10px] text-slate-500">${esc((d && d.establecimiento && d.establecimiento.nombre) || '')}</span>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Desde</label><input type="date" value="${esc(f.fecha_desde)}" onchange="actualizarFiltroCampo('fecha_desde', this.value)" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs font-mono" /></div>
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Hasta</label><input type="date" value="${esc(f.fecha_hasta)}" onchange="actualizarFiltroCampo('fecha_hasta', this.value)" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs font-mono" /></div>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Mes / Año rápido</label><input type="month" onchange="aplicarMesCampo(this.value)" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs font-mono" /></div>
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Estado</label><select onchange="actualizarFiltroCampo('estado_paciente', this.value)" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs bg-white">
              <option value="TODOS" ${f.estado_paciente === 'TODOS' ? 'selected' : ''}>Todos</option>
              <option value="CAPTADA_CON_METODO" ${f.estado_paciente === 'CAPTADA_CON_METODO' ? 'selected' : ''}>Satisfecha (con método)</option>
              <option value="INSATISFECHA_SIN_METODO" ${f.estado_paciente === 'INSATISFECHA_SIN_METODO' ? 'selected' : ''}>Insatisfecha (sin método)</option>
              <option value="SEGUIMIENTO_DOMICILIARIO" ${f.estado_paciente === 'SEGUIMIENTO_DOMICILIARIO' ? 'selected' : ''}>Pendiente / seguimiento</option>
              <option value="CONSEJERIA_REALIZADA" ${f.estado_paciente === 'CONSEJERIA_REALIZADA' ? 'selected' : ''}>Consejería realizada</option>
              <option value="RECHAZA_METODO" ${f.estado_paciente === 'RECHAZA_METODO' ? 'selected' : ''}>Rechaza método</option>
            </select></div>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Sector</label><select onchange="actualizarFiltroCampo('sector', this.value)" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs bg-white"><option value="TODOS">Todos los sectores</option>${sectores.map(function (s) { return '<option value="' + esc(s) + '"' + (f.sector === s ? ' selected' : '') + '>' + esc(s) + '</option>'; }).join('')}</select></div>
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Obstetra</label><select onchange="actualizarFiltroCampo('obstetra', this.value)" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs bg-white"><option value="TODOS">Todas las obstetras</option>${obstetras.map(function (o) { return '<option value="' + esc(o.codpsal_obstetra) + '"' + (f.obstetra === o.codpsal_obstetra ? ' selected' : '') + '>' + esc(o.nombre_obstetra || o.codpsal_obstetra) + '</option>'; }).join('')}</select></div>
          </div>
          <input type="search" value="${esc(f.q)}" oninput="buscarCampoDebounce(this.value)" placeholder="Buscar por DNI o nombres de la paciente..." class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-xs" />
          <button type="button" onclick="cargarReporteCampo(true)" ${state.campoLoading ? 'disabled' : ''} class="w-full min-h-[46px] rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-xs font-bold disabled:opacity-60">${state.campoLoading ? 'Consultando reporte...' : 'Aplicar filtros y actualizar'}</button>
          ${state.campoError ? '<div class="p-3 rounded-xl bg-red-50 border border-red-200 text-[11px] text-red-800">' + esc(state.campoError) + '</div>' : ''}
        </div>

        <div class="grid grid-cols-2 gap-2">
          <div class="p-3 rounded-2xl bg-sky-50 border border-sky-200"><div class="text-[10px] font-bold text-sky-700 uppercase">Pacientes registradas</div><div class="text-2xl font-extrabold text-sky-950">${Number(resumen.total_pacientes || 0)}</div></div>
          <div class="p-3 rounded-2xl bg-emerald-50 border border-emerald-200"><div class="text-[10px] font-bold text-emerald-700 uppercase">Satisfechas</div><div class="text-2xl font-extrabold text-emerald-950">${Number(resumen.satisfechas || 0)}</div></div>
          <div class="p-3 rounded-2xl bg-red-50 border border-red-200"><div class="text-[10px] font-bold text-red-700 uppercase">Insatisfechas</div><div class="text-2xl font-extrabold text-red-950">${Number(resumen.insatisfechas || 0)}</div></div>
          <div class="p-3 rounded-2xl bg-amber-50 border border-amber-200"><div class="text-[10px] font-bold text-amber-700 uppercase">Con Consejería 99208</div><div class="text-2xl font-extrabold text-amber-950">${Number(resumen.con_99208 || 0)}</div></div>
        </div>

        ${state.campoLoading && !d ? '<div class="space-y-2"><div class="h-16 rounded-2xl bg-slate-200 animate-pulse"></div><div class="h-16 rounded-2xl bg-slate-200 animate-pulse"></div><div class="h-24 rounded-2xl bg-slate-200 animate-pulse"></div></div>' : ''}

        <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-2">
          <div class="flex items-center justify-between gap-2">
            <h3 class="text-xs font-bold text-slate-900">Productividad de Salidas a Campo por Obstetra y Día</h3>
          </div>
          <div class="overflow-x-auto -mx-1">
            <table class="w-full text-[10px] border-collapse min-w-[560px]">
              <thead><tr class="bg-slate-100 text-slate-700"><th class="p-2 text-left">Fecha</th><th class="p-2 text-left">Obstetra</th><th class="p-2 text-left">Sectores</th><th class="p-2 text-right">Pacientes</th><th class="p-2 text-center">Primera</th><th class="p-2 text-center">Última</th></tr></thead>
              <tbody>${productividad.map(function (p) { return '<tr class="border-b border-slate-100"><td class="p-2 font-mono">' + esc(fechaDdMmYyyy(p.fecha_salida)) + '</td><td class="p-2"><div class="font-bold">' + esc(p.nombre_obstetra) + '</div><div class="font-mono text-slate-500">' + esc(p.codpsal_obstetra) + '</div></td><td class="p-2">' + esc(p.sectores || '—') + '</td><td class="p-2 text-right font-extrabold">' + Number(p.total_pacientes || 0) + '</td><td class="p-2 text-center font-mono">' + esc(horaDeFecha(p.primera_hora)) + '</td><td class="p-2 text-center font-mono">' + esc(horaDeFecha(p.ultima_hora)) + '</td></tr>'; }).join('') || '<tr><td colspan="6" class="p-4 text-center text-slate-500">Sin salidas registradas para los filtros seleccionados.</td></tr>'}</tbody>
            </table>
          </div>
        </div>

        <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-2">
          <div class="flex items-center justify-between gap-2">
            <div><h3 class="text-xs font-bold text-slate-900">Pacientes Registradas en el Periodo</h3><p class="text-[10px] text-slate-500">${Number(pag.total || 0)} registros · página ${Number(pag.page || 1)} de ${Number(pag.pages || 1)}</p></div>
          </div>
          <div class="overflow-x-auto -mx-1">
            <table class="w-full text-[10px] border-collapse min-w-[980px]">
              <thead><tr class="bg-slate-100 text-slate-700"><th class="p-2 text-left">Fecha y hora</th><th class="p-2 text-left">Sector</th><th class="p-2 text-left">DNI</th><th class="p-2 text-left">Paciente</th><th class="p-2 text-center">Edad</th><th class="p-2 text-left">Celular</th><th class="p-2 text-left">Dirección / Distrito</th><th class="p-2 text-center">Estado</th><th class="p-2 text-center">99208</th><th class="p-2 text-left">Último método / Próxima cita</th><th class="p-2 text-left">Obstetra / Establecimiento</th></tr></thead>
              <tbody>${filas.map(function (p) { return '<tr class="border-b border-slate-100 align-top"><td class="p-2 font-mono whitespace-nowrap">' + esc(p.fecha_registro_ddmmyyyy_hhmmss || p.fecha_registro) + '</td><td class="p-2">' + esc(p.sector) + '</td><td class="p-2 font-mono font-bold">' + esc(p.dni) + '</td><td class="p-2"><div class="font-bold">' + esc(p.paciente_nombre) + '</div></td><td class="p-2 text-center">' + Number(p.edad || 0) + '</td><td class="p-2 font-mono">' + esc(p.celular || '—') + '</td><td class="p-2">' + esc(p.direccion || '—') + '<div class="text-slate-500">' + esc(p.distrito || '') + '</div></td><td class="p-2 text-center"><span class="inline-block px-2 py-1 rounded-lg border text-[9px] font-bold ' + estadoPacienteBadge(p.estado_paciente) + '">' + esc(estadoPacienteTexto(p.estado_paciente)) + '</span></td><td class="p-2 text-center font-bold ' + (p.atencion_99208 ? 'text-emerald-700' : 'text-slate-400') + '">' + (p.atencion_99208 ? 'SÍ' : 'NO') + '</td><td class="p-2">' + esc(p.ultimo_metodo_nombre || 'Sin método') + '<div class="text-slate-500 font-mono">' + esc(p.fecha_proxima_cita || '—') + '</div></td><td class="p-2">' + esc(p.nombre_obstetra) + '<div class="text-slate-500">' + esc(p.estab_nombre) + '</div></td></tr>'; }).join('') || '<tr><td colspan="11" class="p-4 text-center text-slate-500">No hay pacientes para los filtros seleccionados.</td></tr>'}</tbody>
            </table>
          </div>
          <div class="flex items-center justify-between pt-1">
            <button type="button" onclick="paginaCampo(-1)" ${Number(pag.page || 1) <= 1 || state.campoLoading ? 'disabled' : ''} class="min-h-[38px] px-3 rounded-xl border border-slate-300 text-[10px] font-bold disabled:opacity-40">Anterior</button>
            <span class="text-[10px] text-slate-500">${Number(pag.total || 0)} pacientes</span>
            <button type="button" onclick="paginaCampo(1)" ${Number(pag.page || 1) >= Number(pag.pages || 1) || state.campoLoading ? 'disabled' : ''} class="min-h-[38px] px-3 rounded-xl border border-slate-300 text-[10px] font-bold disabled:opacity-40">Siguiente</button>
          </div>
        </div>`;
    }

    function renderReporteMetodos() {
      const f = state.metodosFiltros;
      const d = state.metodosData;
      const resumen = (d && d.resumen) || { vigente: 0, proxima: 0, vencida: 0, sin_metodo: 0, total: 0 };
      const catalogo = (d && d.catalogo) || [];
      const sectores = (d && d.sectores) || [];
      const pag = (d && d.paginacion) || { page: 1, pages: 1, total: 0 };
      const filas = (d && d.filas) || [];
      return `
        <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
          <h3 class="text-sm font-bold text-slate-900">2. Indicadores y Seguimiento por Método</h3>
          <p class="text-[11px] text-slate-500">Configure los días de ciclo del manual y controle los vencimientos por método anticonceptivo.</p>
          <div class="grid grid-cols-2 gap-2">
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Desde</label><input type="date" value="${esc(f.fecha_desde)}" onchange="actualizarFiltroMetodos('fecha_desde', this.value)" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs font-mono" /></div>
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Hasta</label><input type="date" value="${esc(f.fecha_hasta)}" onchange="actualizarFiltroMetodos('fecha_hasta', this.value)" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs font-mono" /></div>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Mes / Año rápido</label><input type="month" onchange="aplicarMesMetodos(this.value)" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs font-mono" /></div>
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Método</label><select onchange="actualizarFiltroMetodos('codigo_metodo', this.value)" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs bg-white"><option value="TODOS">Todos los métodos</option>${catalogo.map(function (m) { return '<option value="' + esc(m.codigo_dx) + '"' + (f.codigo_metodo === m.codigo_dx ? ' selected' : '') + '>' + esc(m.nombre_metodo) + ' (' + Number(m.dias_ciclo) + 'd)</option>'; }).join('')}</select></div>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Estado de vencimiento</label><select onchange="actualizarFiltroMetodos('estado_vencimiento', this.value)" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs bg-white">
              <option value="TODOS" ${f.estado_vencimiento === 'TODOS' ? 'selected' : ''}>Todos</option>
              <option value="VIGENTE" ${f.estado_vencimiento === 'VIGENTE' ? 'selected' : ''}>Vigente / al día</option>
              <option value="PROXIMA" ${f.estado_vencimiento === 'PROXIMA' ? 'selected' : ''}>Próxima a vencer ≤ 7 días</option>
              <option value="VENCIDA" ${f.estado_vencimiento === 'VENCIDA' ? 'selected' : ''}>Vencida</option>
              <option value="SIN_METODO" ${f.estado_vencimiento === 'SIN_METODO' ? 'selected' : ''}>Sin método</option>
            </select></div>
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Sector</label><select onchange="actualizarFiltroMetodos('sector', this.value)" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs bg-white"><option value="TODOS">Todos</option>${sectores.map(function (s) { return '<option value="' + esc(s) + '"' + (f.sector === s ? ' selected' : '') + '>' + esc(s) + '</option>'; }).join('')}</select></div>
          </div>
          <button type="button" onclick="cargarReporteMetodos(true)" ${state.metodosLoading ? 'disabled' : ''} class="w-full min-h-[46px] rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-xs font-bold disabled:opacity-60">${state.metodosLoading ? 'Consultando indicadores...' : 'Aplicar filtros y actualizar'}</button>
          ${state.metodosError ? '<div class="p-3 rounded-xl bg-red-50 border border-red-200 text-[11px] text-red-800">' + esc(state.metodosError) + '</div>' : ''}
        </div>

        <div class="grid grid-cols-2 gap-2">
          <div class="p-3 rounded-2xl bg-emerald-50 border border-emerald-200"><div class="text-[10px] font-bold text-emerald-700 uppercase">Vigentes</div><div class="text-2xl font-extrabold text-emerald-950">${Number(resumen.vigente || 0)}</div></div>
          <div class="p-3 rounded-2xl bg-amber-50 border border-amber-200"><div class="text-[10px] font-bold text-amber-700 uppercase">Próximas ≤ 7 días</div><div class="text-2xl font-extrabold text-amber-950">${Number(resumen.proxima || 0)}</div></div>
          <div class="p-3 rounded-2xl bg-red-50 border border-red-200"><div class="text-[10px] font-bold text-red-700 uppercase">Vencidas</div><div class="text-2xl font-extrabold text-red-950">${Number(resumen.vencida || 0)}</div></div>
          <div class="p-3 rounded-2xl bg-slate-100 border border-slate-300"><div class="text-[10px] font-bold text-slate-700 uppercase">Sin método</div><div class="text-2xl font-extrabold text-slate-900">${Number(resumen.sin_metodo || 0)}</div></div>
        </div>

        <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-2">
          <h3 class="text-xs font-bold text-slate-900">Configuración de Tiempos por Método (manual MINSA)</h3>
          <p class="text-[10px] text-slate-500">Edite los días de ciclo y guarde: el reporte se recalcula en el siguiente clic.</p>
          <div class="overflow-x-auto -mx-1">
            <table class="w-full text-[10px] border-collapse min-w-[520px]">
              <thead><tr class="bg-slate-100 text-slate-700"><th class="p-2 text-left">Código</th><th class="p-2 text-left">Método</th><th class="p-2 text-center">Días</th><th class="p-2 text-center">Activo</th><th class="p-2 text-center">Acción</th></tr></thead>
              <tbody>${catalogo.map(function (m) { return '<tr class="border-b border-slate-100"><td class="p-2 font-mono font-bold">' + esc(m.codigo_dx) + '</td><td class="p-2">' + esc(m.nombre_metodo) + '</td><td class="p-2 text-center"><input id="metodo-dias-' + esc(m.codigo_dx) + '" type="number" min="0" max="3650" value="' + Number(m.dias_ciclo) + '" class="w-20 min-h-[36px] px-2 rounded-lg border border-slate-300 text-center font-mono" /></td><td class="p-2 text-center"><input id="metodo-activo-' + esc(m.codigo_dx) + '" type="checkbox" ' + (Number(m.activo) === 1 ? 'checked' : '') + ' /></td><td class="p-2 text-center"><button type="button" onclick="guardarTiempoMetodo(\'' + esc(m.codigo_dx) + '\')" ' + (state.guardandoMetodo ? 'disabled' : '') + ' class="min-h-[34px] px-2 rounded-lg bg-slate-900 text-white text-[9px] font-bold">Guardar</button></td></tr>'; }).join('') || '<tr><td colspan="5" class="p-3 text-center text-slate-500">Cargue el reporte para ver el catálogo.</td></tr>'}</tbody>
            </table>
          </div>
          <div class="pt-2 border-t border-slate-100 space-y-2">
            <div class="text-[10px] font-bold text-slate-700">Agregar / actualizar código HIS-CPT</div>
            <div class="grid grid-cols-2 gap-2">
              <input id="nuevo-metodo-codigo" placeholder="Código (ej. 90782)" class="min-h-[40px] px-2 rounded-xl border border-slate-300 text-xs font-mono uppercase" />
              <input id="nuevo-metodo-dias" type="number" min="0" max="3650" placeholder="Días ciclo" class="min-h-[40px] px-2 rounded-xl border border-slate-300 text-xs font-mono" />
            </div>
            <input id="nuevo-metodo-nombre" placeholder="Nombre del método" class="w-full min-h-[40px] px-2 rounded-xl border border-slate-300 text-xs" />
            <button type="button" onclick="agregarMetodoCatalogo()" ${state.guardandoMetodo ? 'disabled' : ''} class="w-full min-h-[42px] rounded-xl bg-emerald-700 text-white text-xs font-bold disabled:opacity-60">${state.guardandoMetodo ? 'Guardando...' : 'Guardar método y recalcular'}</button>
          </div>
        </div>

        <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-2">
          <div class="flex items-center justify-between gap-2">
            <div><h3 class="text-xs font-bold text-slate-900">Seguimiento por Método</h3><p class="text-[10px] text-slate-500">${Number(pag.total || 0)} pacientes · página ${Number(pag.page || 1)} de ${Number(pag.pages || 1)}</p></div>
            <button type="button" onclick="exportarReporteMetodos()" class="min-h-[38px] px-3 rounded-xl bg-emerald-700 text-white text-[10px] font-bold">Exportar Excel</button>
          </div>
          <div class="overflow-x-auto -mx-1">
            <table class="w-full text-[10px] border-collapse min-w-[980px]">
              <thead><tr class="bg-slate-100 text-slate-700"><th class="p-2 text-left">Paciente</th><th class="p-2 text-left">Sector</th><th class="p-2 text-left">Método actual</th><th class="p-2 text-center">Ciclo</th><th class="p-2 text-left">Última atención</th><th class="p-2 text-left">Próxima atención</th><th class="p-2 text-center">Indicador</th><th class="p-2 text-left">Obstetra / Establecimiento</th></tr></thead>
              <tbody>${filas.map(function (p) { return '<tr class="border-b border-slate-100 align-top"><td class="p-2"><div class="font-bold">' + esc(p.paciente_nombre) + '</div><div class="font-mono text-slate-500">' + esc(p.dni) + ' · ' + Number(p.edad || 0) + ' años</div><div class="font-mono text-slate-500">' + esc(p.celular || '—') + '</div></td><td class="p-2">' + esc(p.sector || '—') + '</td><td class="p-2">' + esc(p.nombre_metodo || 'Sin método') + '<div class="font-mono text-slate-500">' + esc(p.codigo_metodo || '—') + '</div></td><td class="p-2 text-center font-bold">' + Number(p.dias_ciclo || 0) + ' d</td><td class="p-2 font-mono">' + esc(fechaDdMmYyyy(p.fecha_ultima_atencion) || '—') + '</td><td class="p-2 font-mono"><div>' + esc(fechaDdMmYyyy(p.fecha_proxima_cita) || '—') + '</div><div class="text-[9px] text-slate-500">' + (p.dias_restantes === null ? '' : (Number(p.dias_restantes) < 0 ? 'Vencida hace ' + Math.abs(Number(p.dias_restantes)) + ' d' : 'Faltan ' + Number(p.dias_restantes) + ' d')) + '</div></td><td class="p-2 text-center"><span class="inline-block px-2 py-1 rounded-lg border text-[9px] font-bold ' + estadoIndicadorBadge(p.estado_indicador) + '">' + esc(p.estado_indicador_etiqueta) + '</span></td><td class="p-2">' + esc(p.nombre_obstetra) + '<div class="text-slate-500">' + esc(p.estab_nombre) + '</div></td></tr>'; }).join('') || '<tr><td colspan="8" class="p-4 text-center text-slate-500">No hay pacientes para los filtros seleccionados.</td></tr>'}</tbody>
            </table>
          </div>
          <div class="flex items-center justify-between pt-1">
            <button type="button" onclick="paginaMetodos(-1)" ${Number(pag.page || 1) <= 1 || state.metodosLoading ? 'disabled' : ''} class="min-h-[38px] px-3 rounded-xl border border-slate-300 text-[10px] font-bold disabled:opacity-40">Anterior</button>
            <span class="text-[10px] text-slate-500">${Number(pag.total || 0)} pacientes</span>
            <button type="button" onclick="paginaMetodos(1)" ${Number(pag.page || 1) >= Number(pag.pages || 1) || state.metodosLoading ? 'disabled' : ''} class="min-h-[38px] px-3 rounded-xl border border-slate-300 text-[10px] font-bold disabled:opacity-40">Siguiente</button>
          </div>
        </div>`;
    }

    function svgDataUri(svg) {
      try {
        return 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(String(svg || ''))));
      } catch (e) { return ''; }
    }

    function logoReportesHtml() {
      // SIEMPRE el logo oficial DIRESA Lima (JPG original), sin SVG inventados
      // ni recortes. Se mantiene la proporción con object-fit: contain.
      return '<img src="' + DIRESA_LOGO_DATA_URI + '" alt="Gobierno Regional de Lima - Dirección Regional de Salud" style="max-width:100%;max-height:100%;object-fit:contain" />';
    }

    function logoReportesDataUri() {
      return DIRESA_LOGO_DATA_URI;
    }

    function guardarLogoPersonalizado(input) {
      const file = input && input.files && input.files[0];
      if (!file) return;
      if (file.size > 2 * 1024 * 1024) {
        showFeedback('error', 'El logo no debe superar 2 MB.');
        return;
      }
      const reader = new FileReader();
      reader.onload = function () {
        state.logoPersonalizadoData = String(reader.result || '');
        try { localStorage.setItem(LOGO_REPORTES_KEY, state.logoPersonalizadoData); } catch (e) {}
        showFeedback('success', 'Logo personalizado aplicado a los reportes de este navegador.');
      };
      reader.readAsDataURL(file);
    }

    function restablecerLogoPersonalizado() {
      state.logoPersonalizadoData = '';
      try { localStorage.removeItem(LOGO_REPORTES_KEY); } catch (e) {}
      showFeedback('success', 'Se restauró el logo oficial DIRESA Lima.');
    }

    function metaOficial(titulo, subtitulo, periodo, establecimiento, obstetra) {
      const s = state.session || {};
      return {
        titulo: titulo || 'REPORTE OFICIAL',
        subtitulo: subtitulo || 'Planificación Familiar',
        establecimiento: establecimiento || s.estab_nombre || establishName(s.cod_estab),
        periodo: periodo || '',
        obstetra: obstetra || s.nombreCompleto || '',
        emisorNombre: s.nombreCompleto || '',
        emisorRol: s.rol_etiqueta || s.rol || 'Obstetra',
        emisorDni: s.dni || '',
        generadoEn: new Date().toLocaleString('es-PE')
      };
    }

    function membreteOficialHtml(meta) {
      const m = meta || metaOficial();
      return `<div style="border:2px solid #0f172a;border-radius:14px;background:#ffffff;overflow:hidden">
        <div style="display:grid;grid-template-columns:150px 1fr 82px;gap:6px;padding:9px;align-items:start;border-bottom:2px solid #0f172a">
          <div style="text-align:center">
            <div style="width:140px;height:50px;margin:0 auto 3px">${logoReportesHtml()}</div>
            <div style="font-size:6.5px;line-height:1.3;font-weight:800;color:#7f1d1d;text-transform:uppercase">Gobierno Regional de Lima</div>
            <div style="font-size:6px;line-height:1.25;color:#334155;text-transform:uppercase">Dirección Regional de Salud</div>
          </div>
          <div style="text-align:center;min-width:0">
            <div style="font-size:10.5px;line-height:1.2;font-weight:900;color:#0f172a;text-transform:uppercase">${esc(m.titulo)}</div>
            <div style="font-size:8px;line-height:1.25;font-weight:700;color:#075985;margin-top:2px">${esc(m.subtitulo)}</div>
            <div style="font-size:7.5px;line-height:1.4;color:#334155;margin-top:3px">
              <div><b>Establecimiento:</b> ${esc(m.establecimiento)}</div>
              <div><b>Periodo:</b> ${esc(m.periodo || '—')}</div>
              <div><b>Obstetra:</b> ${esc(m.obstetra || '—')}</div>
              <div><b>Emisión:</b> ${esc(m.generadoEn)}</div>
              <div><b>Emisor:</b> ${esc(m.emisorNombre || '—')} · ${esc(m.emisorRol || '—')} · DNI ${esc(m.emisorDni || '—')}</div>
            </div>
          </div>
          <div style="text-align:center">
            <div style="width:44px;height:50px;margin:0 auto 3px">${HOSPITAL_LOGO_HTML}</div>
            <div style="font-size:6.5px;line-height:1.3;font-weight:800;color:#075985;text-transform:uppercase">Red de Salud Huaral Chancay</div>
            <div style="font-size:6px;line-height:1.25;color:#334155;text-transform:uppercase">Hospital San Juan Bautista de Huaral</div>
          </div>
        </div>
        <div style="padding:3px 8px;background:#f1f5f9;font-size:6.5px;color:#475569;text-align:center">Sistema PlanificaHIS · Documento oficial de Planificación Familiar · Gobierno Regional de Lima</div>
      </div>`;
    }

    function renderBotonesOficiales(tipo) {
      return `<div class="grid grid-cols-1 gap-2">
        <button type="button" onclick="descargarExcelOficialReporte('${tipo}')" class="min-h-[44px] rounded-xl bg-emerald-700 hover:bg-emerald-800 text-white text-[11px] font-bold px-2">📊 Descargar Excel Oficial (.xls con membrete y bordes)</button>
        <button type="button" onclick="imprimirReporteOficial('${tipo}')" class="min-h-[44px] rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-[11px] font-bold px-2">🖨️ Imprimir / Guardar PDF Oficial</button>
      </div>`;
    }

    function construirExcelOficial(meta, columnas, filas, resumenLineas) {
      const m = meta || metaOficial();
      const totalCols = Math.max(1, columnas.length);
      const escudo = logoReportesDataUri();
      const logo = HOSPITAL_LOGO_DATA_URI;
      const filasHtml = (filas || []).map(function (fila, indice) {
        return '<tr>' + columnas.map(function (col, i) {
          const valor = fila[i] === null || fila[i] === undefined ? '' : fila[i];
          const estilo = 'text-align:' + (col.align || 'left') + ';' + (col.text ? "mso-number-format:'\\@';" : '');
          return '<td style="' + estilo + '">' + esc(valor) + '</td>';
        }).join('') + '</tr>';
      }).join('');
      return '\ufeff<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">' +
        '<head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />' +
        '<meta name="ProgId" content="Excel.Sheet" />' +
        '<style>' +
        'table { border-collapse: collapse; font-family: Arial, sans-serif; }' +
        '.membrete td { border: 1px solid #94a3b8; padding: 4px 6px; vertical-align: middle; }' +
        '.inst { font-size: 9pt; font-weight: bold; color: #7f1d1d; text-align: center; line-height: 1.35; }' +
        '.inst2 { font-size: 9pt; font-weight: bold; color: #075985; text-align: center; line-height: 1.35; }' +
        '.titulo { font-size: 13pt; font-weight: bold; color: #0f172a; text-align: center; background: #f8fafc; }' +
        '.subtitulo { font-size: 9pt; font-weight: bold; color: #075985; text-align: center; }' +
        '.dato { font-size: 8pt; color: #334155; }' +
        '.data th { border: 1px solid #64748b; background: #0082C8; color: #ffffff; font-weight: bold; font-size: 9pt; padding: 5px 6px; text-align: center; }' +
        '.data td { border: 1px solid #94a3b8; font-size: 8.5pt; padding: 4px 6px; vertical-align: top; }' +
        '.resumen td { border: 1px solid #94a3b8; background: #f1f5f9; font-size: 9pt; font-weight: bold; color: #334155; padding: 4px 6px; }' +
        '.pie { font-size: 8pt; color: #64748b; text-align: center; }' +
        '</style></head><body>' +
        '<table class="membrete" style="width:100%">' +
        '<tr>' +
        '<td rowspan="5" width="240" align="center">' + (escudo ? '<img src="' + escudo + '" width="220" height="75" />' : '') + '</td>' +
        '<td width="210" class="inst">GOBIERNO REGIONAL DE LIMA<br/>DIRECCIÓN REGIONAL DE SALUD LIMA</td>' +
        '<td rowspan="5" class="titulo">' + esc(m.titulo) + '<br/><span class="subtitulo">' + esc(m.subtitulo) + '</span></td>' +
        '<td width="210" class="inst2">RED DE SALUD HUARAL CHANCAY<br/>HOSPITAL SAN JUAN BAUTISTA DE HUARAL</td>' +
        '<td rowspan="5" width="110" align="center">' + (logo ? '<img src="' + logo + '" width="80" height="85" />' : '') + '</td>' +
        '</tr>' +
        '<tr><td class="dato"><b>Establecimiento:</b> ' + esc(m.establecimiento) + '</td><td class="dato"><b>Periodo:</b> ' + esc(m.periodo || '—') + '</td></tr>' +
        '<tr><td class="dato"><b>Obstetra:</b> ' + esc(m.obstetra || '—') + '</td><td class="dato"><b>Emisión:</b> ' + esc(m.generadoEn) + '</td></tr>' +
        '<tr><td class="dato" colspan="2"><b>Emisor:</b> ' + esc(m.emisorNombre || '—') + ' · ' + esc(m.emisorRol || '—') + ' · DNI ' + esc(m.emisorDni || '—') + '</td></tr>' +
        '<tr><td class="pie" colspan="2">PlanificaHIS · Documento oficial de Planificación Familiar · Gobierno Regional de Lima</td></tr>' +
        '</table><br/>' +
        '<table class="data" style="width:100%"><thead><tr>' +
        columnas.map(function (col) { return '<th>' + esc(col.label) + '</th>'; }).join('') +
        '</tr></thead><tbody>' + filasHtml +
        '<tr><td colspan="' + totalCols + '" style="background:#fef3c7;color:#78350f;font-weight:bold;text-align:center">Total de registros: ' + (filas || []).length + '</td></tr>' +
        '</tbody></table><br/>' +
        (resumenLineas && resumenLineas.length ? '<table class="resumen" style="width:100%">' + resumenLineas.map(function (linea) { return '<tr><td>' + esc(linea) + '</td></tr>'; }).join('') + '</table>' : '') +
        '<p class="pie">Generado por PlanificaHIS el ' + esc(m.generadoEn) + ' · Emisor: ' + esc(m.emisorNombre || '') + ' (' + esc(m.emisorRol || '') + ')</p>' +
        '</body></html>';
    }

    function construirDocumentoOficial(meta, columnas, filas, resumenLineas) {
      const m = meta || metaOficial();
      const escudo = logoReportesDataUri();
      const logo = HOSPITAL_LOGO_DATA_URI;
      const filasHtml = (filas || []).map(function (fila) {
        return '<tr>' + columnas.map(function (col, i) {
          const valor = fila[i] === null || fila[i] === undefined ? '' : fila[i];
          return '<td style="text-align:' + (col.align || 'left') + '">' + esc(valor) + '</td>';
        }).join('') + '</tr>';
      }).join('');
      return '<!doctype html><html lang="es"><head><meta charset="utf-8" /><title>' + esc(m.titulo) + '</title><style>' +
        '@page { size: A4 landscape; margin: 9mm; }' +
        '* { box-sizing: border-box; }' +
        'body { margin: 0; font-family: Arial, Helvetica, sans-serif; color: #0f172a; font-size: 10px; }' +
        '.membrete { width: 100%; border-collapse: collapse; border: 2px solid #0f172a; }' +
        '.membrete td { border: 1px solid #94a3b8; padding: 4px 6px; vertical-align: middle; }' +
        '.inst { font-size: 9px; font-weight: 800; color: #7f1d1d; text-align: center; line-height: 1.35; text-transform: uppercase; }' +
        '.inst2 { font-size: 9px; font-weight: 800; color: #075985; text-align: center; line-height: 1.35; text-transform: uppercase; }' +
        '.titulo { font-size: 13px; font-weight: 900; text-align: center; background: #f8fafc; line-height: 1.25; }' +
        '.subtitulo { font-size: 9px; font-weight: 700; color: #075985; }' +
        '.dato { font-size: 8.5px; color: #334155; }' +
        '.data { width: 100%; border-collapse: collapse; margin-top: 8px; }' +
        '.data th { border: 1px solid #475569; background: #0082C8; color: #fff; font-size: 8px; padding: 4px 4px; text-align: center; }' +
        '.data td { border: 1px solid #94a3b8; font-size: 7.5px; padding: 3px 4px; vertical-align: top; }' +
        '.data tr:nth-child(even) td { background: #f8fafc; }' +
        '.resumen { width: 100%; border-collapse: collapse; margin-top: 8px; }' +
        '.resumen td { border: 1px solid #94a3b8; background: #f1f5f9; font-size: 9px; font-weight: bold; padding: 4px 6px; }' +
        '.firmas { width: 100%; margin-top: 26px; display: flex; justify-content: space-around; }' +
        '.firma { width: 32%; text-align: center; font-size: 9px; color: #334155; }' +
        '.firma .linea { border-top: 1px solid #334155; margin-bottom: 3px; padding-top: 3px; }' +
        '.pie { margin-top: 12px; text-align: center; font-size: 8px; color: #64748b; }' +
        '</style></head><body>' +
        '<table class="membrete"><tr>' +
        '<td rowspan="5" width="22%" align="center">' + (escudo ? '<img src="' + escudo + '" width="200" height="68" />' : '') + '</td>' +
        '<td width="24%" class="inst">GOBIERNO REGIONAL DE LIMA<br/>DIRECCIÓN REGIONAL DE SALUD LIMA</td>' +
        '<td rowspan="5" width="32%" class="titulo">' + esc(m.titulo) + '<br/><span class="subtitulo">' + esc(m.subtitulo) + '</span></td>' +
        '<td width="24%" class="inst2">RED DE SALUD HUARAL CHANCAY<br/>HOSPITAL SAN JUAN BAUTISTA DE HUARAL</td>' +
        '<td rowspan="5" width="10%" align="center">' + (logo ? '<img src="' + logo + '" width="80" height="85" />' : '') + '</td>' +
        '</tr>' +
        '<tr><td class="dato"><b>Establecimiento:</b> ' + esc(m.establecimiento) + '</td><td class="dato"><b>Periodo:</b> ' + esc(m.periodo || '—') + '</td></tr>' +
        '<tr><td class="dato"><b>Obstetra:</b> ' + esc(m.obstetra || '—') + '</td><td class="dato"><b>Emisión:</b> ' + esc(m.generadoEn) + '</td></tr>' +
        '<tr><td class="dato" colspan="2"><b>Emisor:</b> ' + esc(m.emisorNombre || '—') + ' · ' + esc(m.emisorRol || '—') + ' · DNI ' + esc(m.emisorDni || '—') + '</td></tr>' +
        '<tr><td class="dato" colspan="2">Sistema PlanificaHIS · Documento oficial de Planificación Familiar</td></tr>' +
        '</table>' +
        '<table class="data"><thead><tr>' + columnas.map(function (col) { return '<th>' + esc(col.label) + '</th>'; }).join('') + '</tr></thead><tbody>' + filasHtml + '</tbody></table>' +
        '<div style="margin-top:5px;font-size:8px;color:#475569">Total de registros: <b>' + (filas || []).length + '</b></div>' +
        (resumenLineas && resumenLineas.length ? '<table class="resumen">' + resumenLineas.map(function (linea) { return '<tr><td>' + esc(linea) + '</td></tr>'; }).join('') + '</table>' : '') +
        '<div class="firmas">' +
        '<div class="firma"><div class="linea">' + esc(m.emisorNombre || '') + '</div>' + esc(m.emisorRol || '') + '<br/>DNI ' + esc(m.emisorDni || '') + '</div>' +
        '<div class="firma"><div class="linea">Jefatura de Obstetras</div>Vo.Bo. / Supervisión</div>' +
        '<div class="firma"><div class="linea">Estadística e Informática</div>Revisado y conforme</div>' +
        '</div>' +
        '<div class="pie">Generado por PlanificaHIS el ' + esc(m.generadoEn) + ' · Impresión oficial con membrete institucional</div>' +
        '<script>window.addEventListener("load",function(){setTimeout(function(){window.focus();window.print();},450);});<\/script>' +
        '</body></html>';
    }

    function abrirDocumentoOficial(html) {
      const win = window.open('', '_blank', 'width=1120,height=800');
      if (!win) {
        showFeedback('error', 'Permita las ventanas emergentes para imprimir o guardar el PDF oficial.');
        return;
      }
      win.document.open();
      win.document.write(html);
      win.document.close();
    }

    async function descargarExcelOficialReporte(tipo) {
      try {
        const datos = await datosOficialesReporte(tipo);
        const html = construirExcelOficial(datos.meta, datos.columnas, datos.filas, datos.resumen);
        descargarArchivo(datos.archivo, html, 'application/vnd.ms-excel;charset=utf-8');
        showFeedback('success', 'Excel oficial generado: ' + datos.archivo + ' (' + datos.filas.length + ' registros).');
      } catch (error) {
        showFeedback('error', error.message);
      }
    }

    async function imprimirReporteOficial(tipo) {
      try {
        const datos = await datosOficialesReporte(tipo);
        abrirDocumentoOficial(construirDocumentoOficial(datos.meta, datos.columnas, datos.filas, datos.resumen));
      } catch (error) {
        showFeedback('error', error.message);
      }
    }

    async function cargarTodasFilasCampo() {
      const filtros = Object.assign({}, state.campoFiltros, { page: 1, per_page: 100 });
      const primera = await apiGet('reporte_campo', filtros);
      const filas = (primera.filas || []).slice();
      const pages = Math.min(50, Number((primera.paginacion && primera.paginacion.pages) || 1));
      for (let p = 2; p <= pages; p++) {
        const data = await apiGet('reporte_campo', Object.assign({}, filtros, { page: p }));
        Array.prototype.push.apply(filas, data.filas || []);
      }
      return Object.assign({}, primera, { filas: filas });
    }

    function filaReporteCampo(p, i) {
      return [
        i + 1,
        p.fecha_registro_ddmmyyyy_hhmmss || p.fecha_registro,
        p.sector || '',
        p.dni || '',
        p.paciente_nombre || '',
        Number(p.edad || 0),
        p.celular || '',
        p.direccion || '',
        p.distrito || '',
        estadoPacienteTexto(p.estado_paciente),
        p.atencion_99208 ? 'SÍ' : 'NO',
        p.ultimo_metodo_nombre || 'Sin método',
        p.fecha_proxima_cita || '—',
        p.nombre_obstetra || '',
        p.estab_nombre || ''
      ];
    }

    function columnasReporteCampo() {
      return [
        { label: 'N°', align: 'center', width: 28 },
        { label: 'Fecha y hora de registro', align: 'center', width: 105 },
        { label: 'Sector', width: 70 },
        { label: 'DNI', align: 'center', text: true, width: 60 },
        { label: 'Apellidos y nombres', width: 150 },
        { label: 'Edad', align: 'center', width: 32 },
        { label: 'Celular', align: 'center', text: true, width: 68 },
        { label: 'Dirección', width: 140 },
        { label: 'Distrito', width: 70 },
        { label: 'Estado', width: 85 },
        { label: '99208', align: 'center', width: 38 },
        { label: 'Último método', width: 100 },
        { label: 'Próxima cita', align: 'center', width: 70 },
        { label: 'Obstetra', width: 110 },
        { label: 'Establecimiento', width: 120 }
      ];
    }

    function filaReporteProgramacion(f, i) {
      return [
        i + 1,
        f.establecimiento || '',
        f.dni || '',
        f.paciente_nombre || '',
        Number(f.edad || 0),
        f.historia_clinica || '',
        f.nombre_metodo || '',
        f.codigo_his || f.codigo_metodo || '',
        f.fecha_aplicacion || '',
        Number(f.dias_ciclo || 0),
        f.fecha_proximo_metodo || '',
        Number(f.dias_restantes || 0),
        estadoReporteLabel(f.estado_programacion),
        f.celular || '',
        f.direccion || '',
        f.sector || '',
        f.distrito || '',
        f.obstetra_dni || ''
      ];
    }

    function columnasReporteProgramacion() {
      return [
        { label: 'N°', align: 'center', width: 28 },
        { label: 'Establecimiento', width: 105 },
        { label: 'DNI', align: 'center', text: true, width: 58 },
        { label: 'Paciente', width: 135 },
        { label: 'Edad', align: 'center', width: 32 },
        { label: 'HCL', align: 'center', text: true, width: 55 },
        { label: 'Método', width: 100 },
        { label: 'Código HIS', align: 'center', text: true, width: 55 },
        { label: 'Fecha aplicación', align: 'center', width: 68 },
        { label: 'Ciclo (d)', align: 'center', width: 38 },
        { label: 'Próximo control', align: 'center', width: 68 },
        { label: 'Días', align: 'center', width: 32 },
        { label: 'Estado', width: 72 },
        { label: 'Celular', align: 'center', text: true, width: 64 },
        { label: 'Dirección', width: 115 },
        { label: 'Sector', width: 60 },
        { label: 'Distrito', width: 60 },
        { label: 'Obstetra (DNI)', align: 'center', text: true, width: 62 }
      ];
    }

    function filaReportePadron(f, i, grupo) {
      const mapaGrupo = { manana: 'MAÑANA (+1)', hoy: 'HOY', vencidas: 'VENCIDA' };
      return [
        i + 1,
        f.prioridad_llamada || '',
        grupo ? (mapaGrupo[grupo] || grupo.toUpperCase()) : (mapaGrupo[f.grupo_alerta] || (f.grupo_alerta || '')),
        f.dni || '',
        f.paciente_nombre || '',
        Number(f.edad || 0),
        f.historia_clinica || '',
        f.nombre_metodo || '',
        f.codigo_his || f.codigo_metodo || '',
        f.fecha_aplicacion || '',
        f.fecha_proximo_metodo || '',
        Number(f.dias_restantes || 0),
        estadoReporteLabel(f.estado_programacion),
        f.celular || '',
        f.direccion || '',
        f.sector || '',
        f.distrito || '',
        f.establecimiento || '',
        f.obstetra_dni || ''
      ];
    }

    function columnasReportePadron() {
      return [
        { label: 'N°', align: 'center', width: 28 },
        { label: 'Prioridad', width: 65 },
        { label: 'Grupo', width: 60 },
        { label: 'DNI', align: 'center', text: true, width: 58 },
        { label: 'Paciente', width: 130 },
        { label: 'Edad', align: 'center', width: 30 },
        { label: 'HCL', align: 'center', text: true, width: 50 },
        { label: 'Método', width: 95 },
        { label: 'Código HIS', align: 'center', text: true, width: 52 },
        { label: 'Fecha aplicación', align: 'center', width: 64 },
        { label: 'Próximo control', align: 'center', width: 64 },
        { label: 'Días', align: 'center', width: 30 },
        { label: 'Estado', width: 68 },
        { label: 'Celular', align: 'center', text: true, width: 62 },
        { label: 'Dirección', width: 110 },
        { label: 'Sector', width: 55 },
        { label: 'Distrito', width: 55 },
        { label: 'Establecimiento', width: 105 },
        { label: 'Obstetra (DNI)', align: 'center', text: true, width: 60 }
      ];
    }

    function datosOficialesAlerta() {
      const a = state.alertas || {};
      const filas = [];
      ['manana', 'hoy', 'vencidas'].forEach(function (grupo) {
        ((a.listas && a.listas[grupo]) || []).forEach(function (f) {
          filas.push(filaReportePadron(f, filas.length, grupo));
        });
      });
      if (!filas.length) throw new Error('No hay pacientes en las alertas de seguimiento programático.');
      const hoy = localIsoDate(0);
      const meta = metaOficial(
        'ALERTA DE SEGUIMIENTO PROGRAMÁTICO',
        'Pacientes que tocan mañana (+1), hoy y vencidas para llamada telefónica',
        'Corte al ' + fechaDdMmYyyy(hoy)
      );
      return {
        meta: meta,
        columnas: columnasReportePadron(),
        filas: filas,
        resumen: [
          'Mañana (+1): ' + Number(a.manana || 0) + ' pacientes',
          'Hoy: ' + Number(a.hoy || 0) + ' pacientes',
          'Vencidas: ' + Number(a.vencidas || 0) + ' pacientes',
          'Total de alertas: ' + Number(a.total || 0) + ' pacientes'
        ],
        archivo: 'alerta_seguimiento_programatico_' + hoy + '.xls'
      };
    }

    async function descargarExcelAlerta() {
      try {
        const datos = datosOficialesAlerta();
        descargarArchivo(datos.archivo, construirExcelOficial(datos.meta, datos.columnas, datos.filas, datos.resumen), 'application/vnd.ms-excel;charset=utf-8');
        showFeedback('success', 'Excel oficial de alerta generado: ' + datos.archivo + ' (' + datos.filas.length + ' pacientes).');
      } catch (error) {
        showFeedback('error', error.message);
      }
    }

    async function datosOficialesReporte(tipo) {
      if (tipo === 'CAMPO') {
        const base = await cargarTodasFilasCampo();
        const f = base.filtros || state.campoFiltros;
        const periodo = fechaDdMmYyyy(f.fecha_desde) + ' al ' + fechaDdMmYyyy(f.fecha_hasta);
        const obstetraNombre = (f.obstetra && f.obstetra !== 'TODOS')
          ? ((base.obstetras || []).filter(function (o) { return o.codpsal_obstetra === f.obstetra; }).map(function (o) { return o.nombre_obstetra; })[0] || base.obstetra_nombre || f.obstetra)
          : (base.obstetra_nombre || '');
        const meta = metaOficial(
          'REPORTE 01 · PACIENTES CAPTADAS EN CAMPO / BARRIDO',
          'Captación domiciliaria y barrido de Planificación Familiar',
          periodo,
          (base.establecimiento && base.establecimiento.nombre) || '',
          obstetraNombre
        );
        return {
          meta: meta,
          columnas: columnasReporteCampo(),
          filas: (base.filas || []).map(filaReporteCampo),
          resumen: [
            'Total de pacientes registradas: ' + Number((base.resumen && base.resumen.total_pacientes) || 0),
            'Satisfechas con método: ' + Number((base.resumen && base.resumen.satisfechas) || 0),
            'Insatisfechas sin método: ' + Number((base.resumen && base.resumen.insatisfechas) || 0),
            'Con consejería 99208: ' + Number((base.resumen && base.resumen.con_99208) || 0),
            'Pendientes / seguimiento: ' + Number((base.resumen && base.resumen.pendientes) || 0)
          ],
          archivo: 'reporte_01_campo_barrido_' + (f.fecha_desde || localIsoDate(0)) + '.xls'
        };
      }
      if (tipo === 'PRODUCTIVIDAD') {
        if (!state.productividadData) await cargarReporteProductividad(true);
        const d = state.productividadData;
        if (!d) throw new Error('Primero cargue el Reporte 02 de Productividad.');
        const periodo = fechaDdMmYyyy(d.periodo && d.periodo.desde) + ' al ' + fechaDdMmYyyy(d.periodo && d.periodo.hasta);
        const obstetraFiltro = (state.productividadFiltros.obstetra && state.productividadFiltros.obstetra !== 'TODOS') ? state.productividadFiltros.obstetra : '';
        const meta = metaOficial(
          'REPORTE 02 · PRODUCTIVIDAD DIARIA POR OBSTETRA',
          'Salidas a campo, sectores visitados y pacientes captadas por día',
          periodo,
          (d.establecimiento && d.establecimiento.nombre) || '',
          d.obstetra_nombre || obstetraFiltro
        );
        const lista = d.productividad || [];
        return {
          meta: meta,
          columnas: [
            { label: 'N°', align: 'center', width: 28 },
            { label: 'Fecha de salida', align: 'center', width: 68 },
            { label: 'DNI obstetra', align: 'center', text: true, width: 62 },
            { label: 'Obstetra', width: 170 },
            { label: 'Sectores visitados', width: 220 },
            { label: 'Pacientes captadas', align: 'center', width: 55 },
            { label: 'Primera atención', align: 'center', width: 72 },
            { label: 'Última atención', align: 'center', width: 72 }
          ],
          filas: lista.map(function (p, i) {
            return [
              i + 1,
              fechaDdMmYyyy(p.fecha_salida),
              p.codpsal_obstetra || '',
              p.nombre_obstetra || '',
              p.sectores || '',
              Number(p.total_pacientes || 0),
              horaDeFecha(p.primera_hora),
              horaDeFecha(p.ultima_hora)
            ];
          }),
          resumen: [
            'Total de pacientes captadas en el periodo: ' + Number((d.resumen && d.resumen.total_pacientes) || 0),
            'Salidas a campo registradas: ' + lista.length,
            'Satisfechas con método: ' + Number((d.resumen && d.resumen.satisfechas) || 0),
            'Insatisfechas sin método: ' + Number((d.resumen && d.resumen.insatisfechas) || 0),
            'Con consejería 99208: ' + Number((d.resumen && d.resumen.con_99208) || 0)
          ],
          archivo: 'reporte_02_productividad_' + (d.periodo && d.periodo.desde || localIsoDate(0)) + '.xls'
        };
      }
      if (tipo === 'PROGRAMACION') {
        const r = state.reporteProgramacion;
        if (!r) throw new Error('Primero busque la programación que desea exportar.');
        const meta = metaOficial(
          'REPORTE 03 · PROGRAMACIÓN Y SEGUIMIENTO POR MÉTODO',
          'Próximo control por método anticonceptivo oficial HIS',
          descripcionRangoReporte(r),
          (r.establecimiento && r.establecimiento.nombre) || '',
          r.obstetra_nombre || ''
        );
        return {
          meta: meta,
          columnas: columnasReporteProgramacion(),
          filas: (r.filas || []).map(filaReporteProgramacion),
          resumen: [
            'Total de pacientes programadas: ' + Number((r.resumen && r.resumen.total) || 0),
            'Vencidas / abandono: ' + Number((r.resumen && r.resumen.vencido_abandono) || 0),
            'Toca en la fecha: ' + Number((r.resumen && r.resumen.toca_en_fecha) || 0),
            'Próximos 7 días: ' + Number((r.resumen && r.resumen.proximo_7_dias) || 0),
            'Al día: ' + Number((r.resumen && r.resumen.al_dia) || 0),
            'Método filtrado: ' + etiquetaFiltroMetodo(r)
          ],
          archivo: 'reporte_03_programacion_' + (r.fecha_objetivo || localIsoDate(0)) + '.xls'
        };
      }
      if (tipo === 'PADRON') {
        if (!state.padronData) await cargarReportePadron(true);
        const d = state.padronData;
        if (!d) throw new Error('Primero cargue el Reporte 04 de Padrón.');
        const meta = metaOficial(
          'REPORTE 04 · PADRÓN DE PACIENTES POR LLAMAR',
          'Listado oficial con prioridad de llamada y datos de contacto',
          'Corte al ' + (d.fecha_corte_ddmmyyyy || fechaDdMmYyyy(localIsoDate(0))),
          (d.establecimiento && d.establecimiento.nombre) || '',
          d.obstetra_nombre || ''
        );
        return {
          meta: meta,
          columnas: columnasReportePadron(),
          filas: (d.filas || []).map(function (f, i) { return filaReportePadron(f, i, f.grupo_alerta); }),
          resumen: [
            'Mañana (+1): ' + Number((d.resumen && d.resumen.manana) || 0),
            'Hoy: ' + Number((d.resumen && d.resumen.hoy) || 0),
            'Vencidas: ' + Number((d.resumen && d.resumen.vencidas) || 0),
            'Total de pacientes por llamar: ' + Number((d.resumen && d.resumen.total) || 0)
          ],
          archivo: 'reporte_04_padron_llamadas_' + (d.fecha_corte || localIsoDate(0)) + '.xls'
        };
      }
      throw new Error('Tipo de reporte oficial no reconocido.');
    }

    function renderReporteProductividad() {
      const f = state.productividadFiltros;
      const d = state.productividadData;
      const resumen = (d && d.resumen) || {};
      const filas = (d && d.productividad) || [];
      const totalPacientes = filas.reduce(function (acc, p) { return acc + Number(p.total_pacientes || 0); }, 0);
      const obstetras = {};
      filas.forEach(function (p) { obstetras[String(p.codpsal_obstetra || '')] = true; });
      const periodo = (d && d.periodo && d.periodo.desde)
        ? (fechaDdMmYyyy(d.periodo.desde) + ' al ' + fechaDdMmYyyy(d.periodo.hasta))
        : (fechaDdMmYyyy(f.fecha_desde) + ' al ' + fechaDdMmYyyy(f.fecha_hasta));
      return `
        ${membreteOficialHtml({
          titulo: 'REPORTE 02 · PRODUCTIVIDAD DIARIA POR OBSTETRA',
          subtitulo: 'Salidas a campo, sectores visitados y pacientes captadas por día',
          periodo: periodo,
          establecimiento: (d && d.establecimiento && d.establecimiento.nombre) || '',
          obstetra: (d && d.obstetra_nombre) || (f.obstetra !== 'TODOS' ? f.obstetra : '')
        })}
        ${renderBotonesOficiales('PRODUCTIVIDAD')}
        <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
          <h3 class="text-sm font-bold text-slate-900">Filtros de productividad</h3>
          <div class="grid grid-cols-2 gap-2">
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Desde</label><input id="prod-desde" type="date" value="${esc(f.fecha_desde)}" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs font-mono" /></div>
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Hasta</label><input id="prod-hasta" type="date" value="${esc(f.fecha_hasta)}" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs font-mono" /></div>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">Mes / Año rápido</label><input type="month" onchange="aplicarMesProductividad(this.value)" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs font-mono" /></div>
            <div><label class="block text-[10px] font-bold text-slate-600 mb-1">DNI obstetra (opcional)</label><input id="prod-obstetra" type="text" inputmode="numeric" value="${esc(f.obstetra !== 'TODOS' ? f.obstetra : '')}" placeholder="TODOS" class="w-full min-h-[42px] px-2 rounded-xl border border-slate-300 text-xs font-mono" /></div>
          </div>
          <button type="button" onclick="buscarProductividad()" ${state.productividadLoading ? 'disabled' : ''} class="w-full min-h-[46px] rounded-xl bg-sky-700 hover:bg-sky-800 disabled:opacity-60 text-white text-xs font-bold">${state.productividadLoading ? 'Consultando productividad...' : 'Aplicar filtros y actualizar'}</button>
          ${state.productividadError ? '<div class="p-3 rounded-xl bg-red-50 border border-red-200 text-[11px] text-red-800">' + esc(state.productividadError) + '</div>' : ''}
        </div>
        <div class="grid grid-cols-3 gap-2">
          <div class="p-3 rounded-2xl bg-sky-50 border border-sky-200"><div class="text-[9px] font-bold text-sky-700 uppercase">Salidas</div><div class="text-2xl font-extrabold text-sky-950">${filas.length}</div></div>
          <div class="p-3 rounded-2xl bg-emerald-50 border border-emerald-200"><div class="text-[9px] font-bold text-emerald-700 uppercase">Pacientes</div><div class="text-2xl font-extrabold text-emerald-950">${Number(resumen.total_pacientes || totalPacientes)}</div></div>
          <div class="p-3 rounded-2xl bg-amber-50 border border-amber-200"><div class="text-[9px] font-bold text-amber-700 uppercase">Obstetras</div><div class="text-2xl font-extrabold text-amber-950">${Object.keys(obstetras).filter(Boolean).length}</div></div>
        </div>
        <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-2">
          <h3 class="text-xs font-bold text-slate-900">Detalle diario por obstetra</h3>
          <div class="overflow-x-auto -mx-1">
            <table class="w-full text-[10px] border-collapse min-w-[640px]">
              <thead><tr class="bg-slate-100 text-slate-700"><th class="p-2 text-left">Fecha</th><th class="p-2 text-left">Obstetra</th><th class="p-2 text-left">Sectores</th><th class="p-2 text-right">Pacientes</th><th class="p-2 text-center">Primera</th><th class="p-2 text-center">Última</th></tr></thead>
              <tbody>${filas.map(function (p) { return '<tr class="border-b border-slate-100"><td class="p-2 font-mono">' + esc(fechaDdMmYyyy(p.fecha_salida)) + '</td><td class="p-2"><div class="font-bold">' + esc(p.nombre_obstetra) + '</div><div class="font-mono text-slate-500">' + esc(p.codpsal_obstetra) + '</div></td><td class="p-2">' + esc(p.sectores || '—') + '</td><td class="p-2 text-right font-extrabold">' + Number(p.total_pacientes || 0) + '</td><td class="p-2 text-center font-mono">' + esc(horaDeFecha(p.primera_hora)) + '</td><td class="p-2 text-center font-mono">' + esc(horaDeFecha(p.ultima_hora)) + '</td></tr>'; }).join('') || '<tr><td colspan="6" class="p-4 text-center text-slate-500">Sin salidas registradas para los filtros seleccionados.</td></tr>'}</tbody>
            </table>
          </div>
        </div>`;
    }

    function renderReportePadron() {
      const d = state.padronData;
      const resumen = (d && d.resumen) || { manana: 0, hoy: 0, vencidas: 0, total: 0 };
      const filas = (d && d.filas) || [];
      const grupos = [
        { id: 'todas', label: 'Todas' },
        { id: 'manana', label: 'Mañana (+1)' },
        { id: 'hoy', label: 'Hoy' },
        { id: 'vencidas', label: 'Vencidas' }
      ];
      const mapaGrupo = { manana: 'manana', hoy: 'hoy', vencidas: 'vencidas' };
      return `
        ${membreteOficialHtml({
          titulo: 'REPORTE 04 · PADRÓN DE PACIENTES POR LLAMAR',
          subtitulo: 'Listado oficial con prioridad de llamada y datos de contacto',
          periodo: 'Corte al ' + ((d && d.fecha_corte_ddmmyyyy) || fechaDdMmYyyy(localIsoDate(0))),
          establecimiento: (d && d.establecimiento && d.establecimiento.nombre) || '',
          obstetra: (d && d.obstetra_nombre) || ''
        })}
        ${renderBotonesOficiales('PADRON')}
        <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
          <h3 class="text-sm font-bold text-slate-900">Prioridad de llamadas</h3>
          <div class="grid grid-cols-4 gap-1.5">
            ${grupos.map(function (g) { return '<button type="button" onclick="setPadronGrupo(\'' + g.id + '\')" class="min-h-[40px] rounded-xl text-[9px] font-bold ' + (state.padronGrupo === g.id ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-700') + '">' + esc(g.label) + '</button>'; }).join('')}
          </div>
          <button type="button" onclick="cargarReportePadron(true)" ${state.padronLoading ? 'disabled' : ''} class="w-full min-h-[44px] rounded-xl bg-sky-700 hover:bg-sky-800 disabled:opacity-60 text-white text-xs font-bold">${state.padronLoading ? 'Consultando padrón...' : 'Actualizar padrón de llamadas'}</button>
          ${state.padronError ? '<div class="p-3 rounded-xl bg-red-50 border border-red-200 text-[11px] text-red-800">' + esc(state.padronError) + '</div>' : ''}
        </div>
        <div class="grid grid-cols-4 gap-1.5">
          <div class="p-2 rounded-xl bg-sky-50 border border-sky-200 text-center"><div class="text-[8px] font-bold text-sky-700">Mañana</div><div class="text-lg font-extrabold font-mono text-sky-900">${Number(resumen.manana || 0)}</div></div>
          <div class="p-2 rounded-xl bg-amber-50 border border-amber-200 text-center"><div class="text-[8px] font-bold text-amber-700">Hoy</div><div class="text-lg font-extrabold font-mono text-amber-900">${Number(resumen.hoy || 0)}</div></div>
          <div class="p-2 rounded-xl bg-red-50 border border-red-200 text-center"><div class="text-[8px] font-bold text-red-700">Vencidas</div><div class="text-lg font-extrabold font-mono text-red-900">${Number(resumen.vencidas || 0)}</div></div>
          <div class="p-2 rounded-xl bg-slate-100 border border-slate-300 text-center"><div class="text-[8px] font-bold text-slate-700">Total</div><div class="text-lg font-extrabold font-mono text-slate-900">${Number(resumen.total || 0)}</div></div>
        </div>
        <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-2">
          <div class="flex items-center justify-between"><h3 class="text-xs font-bold text-slate-900">Pacientes por llamar</h3><span class="text-[10px] text-slate-500">${filas.length} registros</span></div>
          ${filas.length ? filas.map(function (f) { return renderAlertaCard(f, mapaGrupo[f.grupo_alerta] || f.grupo_alerta || 'hoy'); }).join('') : '<div class="p-4 text-xs text-slate-500 text-center">No hay pacientes en el padrón para el grupo seleccionado.</div>'}
        </div>`;
    }

    function setPadronGrupo(grupo) {
      state.padronGrupo = grupo || 'todas';
      cargarReportePadron(true);
    }

    async function buscarProductividad() {
      const desde = document.getElementById('prod-desde');
      const hasta = document.getElementById('prod-hasta');
      const obstetra = document.getElementById('prod-obstetra');
      if (desde && desde.value) state.productividadFiltros.fecha_desde = desde.value;
      if (hasta && hasta.value) state.productividadFiltros.fecha_hasta = hasta.value;
      state.productividadFiltros.obstetra = obstetra && obstetra.value.trim() ? obstetra.value.replace(/\D/g, '') : 'TODOS';
      state.productividadFiltros.page = 1;
      await cargarReporteProductividad(true);
    }

    function aplicarMesProductividad(valor) {
      if (!valor || !/^\d{4}-\d{2}$/.test(valor)) return;
      const partes = valor.split('-');
      const ultimo = new Date(Number(partes[0]), Number(partes[1]), 0).getDate();
      state.productividadFiltros.fecha_desde = valor + '-01';
      state.productividadFiltros.fecha_hasta = valor + '-' + String(ultimo).padStart(2, '0');
      cargarReporteProductividad(true);
    }

    function setVistaReporte(vista) {
      state.reporteVista = vista;
      state.feedback = null;
      render();
      if (vista === 'CAMPO' && !state.campoData) cargarReporteCampo(true);
      if (vista === 'PRODUCTIVIDAD' && !state.productividadData) cargarReporteProductividad(true);
      if (vista === 'PADRON' && !state.padronData) cargarReportePadron(true);
    }

    function filtrarAgenda(grupo) {
      state.agendaGrupo = grupo || 'TODAS';
      render();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function verAlertaManana() {
      state.agendaGrupo = 'manana';
      state.activeTab = 'AGENDA';
      state.feedback = null;
      render();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    async function cargarReporteProductividad(mostrarSkeleton) {
      if (!state.token) return;
      state.productividadLoading = true;
      state.productividadError = '';
      if (mostrarSkeleton) render();
      try {
        state.productividadData = await apiGet('reporte_productividad', state.productividadFiltros);
      } catch (error) {
        state.productividadError = error.message;
      } finally {
        state.productividadLoading = false;
        render();
      }
    }

    async function cargarReportePadron(mostrarSkeleton) {
      if (!state.token) return;
      state.padronLoading = true;
      state.padronError = '';
      if (mostrarSkeleton) render();
      try {
        state.padronData = await apiGet('reporte_padron', { grupo: state.padronGrupo || 'todas' });
      } catch (error) {
        state.padronError = error.message;
      } finally {
        state.padronLoading = false;
        render();
      }
    }

    async function guardarDiasCicloOficial(codigo) {
      if (state.guardandoMetodo) return;
      const actual = catalogoReportes().find(function (m) { return m.codigo_dx === codigo; });
      if (!actual) return;
      const input = document.getElementById('cfg-dias-' + codigo);
      const dias = Number(input ? input.value : actual.dias_ciclo);
      if (!Number.isFinite(dias) || dias <= 0) {
        showFeedback('error', 'Ingrese un número de días válido mayor a cero.');
        return;
      }
      state.guardandoMetodo = true;
      try {
        const data = await apiPost('save_metodo', {
          codigo_dx: codigo,
          nombre_metodo: actual.nombre_metodo,
          dias_ciclo: dias,
          requiere_cita: actual.requiere_cita,
          activo: 1
        });
        state.catalogoMetodos = data.catalogo || state.catalogoMetodos;
        if (state.reporteProgramacion && data.catalogo) state.reporteProgramacion.catalogo = data.catalogo;
        state.feedback = { type: 'success', text: 'Ciclo actualizado: ' + codigo + ' = ' + dias + ' días. Las alertas se recalcularán al volver al panel.' };
        await loadOverview();
        if (state.reporteProgramacion) await buscarProgramacion();
      } catch (error) {
        state.feedback = { type: 'error', text: error.message };
      } finally {
        state.guardandoMetodo = false;
        render();
      }
    }

    function actualizarFiltroCampo(campo, valor) {
      state.campoFiltros[campo] = valor;
      state.campoFiltros.page = 1;
      cargarReporteCampo(false);
    }

    function actualizarFiltroMetodos(campo, valor) {
      state.metodosFiltros[campo] = valor;
      state.metodosFiltros.page = 1;
      cargarReporteMetodos(false);
    }

    function aplicarMesCampo(valor) {
      if (!valor || !/^\d{4}-\d{2}$/.test(valor)) return;
      const partes = valor.split('-');
      const ultimo = new Date(Number(partes[0]), Number(partes[1]), 0).getDate();
      state.campoFiltros.fecha_desde = valor + '-01';
      state.campoFiltros.fecha_hasta = valor + '-' + String(ultimo).padStart(2, '0');
      state.campoFiltros.page = 1;
      cargarReporteCampo(false);
    }

    function aplicarMesMetodos(valor) {
      if (!valor || !/^\d{4}-\d{2}$/.test(valor)) return;
      const partes = valor.split('-');
      const ultimo = new Date(Number(partes[0]), Number(partes[1]), 0).getDate();
      state.metodosFiltros.fecha_desde = valor + '-01';
      state.metodosFiltros.fecha_hasta = valor + '-' + String(ultimo).padStart(2, '0');
      state.metodosFiltros.page = 1;
      cargarReporteMetodos(false);
    }

    let campoBuscarTimer = null;
    function buscarCampoDebounce(valor) {
      state.campoFiltros.q = valor;
      state.campoFiltros.page = 1;
      if (campoBuscarTimer) clearTimeout(campoBuscarTimer);
      campoBuscarTimer = setTimeout(function () { cargarReporteCampo(false); }, 420);
    }

    function parametrosReporte(filtros) {
      return Object.assign({}, filtros);
    }

    async function cargarReporteCampo(mostrarSkeleton) {
      if (!state.token) return;
      state.campoLoading = true;
      state.campoError = '';
      if (mostrarSkeleton) render();
      try {
        const data = await apiGet('reporte_campo', parametrosReporte(state.campoFiltros));
        state.campoData = data;
      } catch (error) {
        state.campoError = error.message;
      } finally {
        state.campoLoading = false;
        render();
      }
    }

    async function cargarReporteMetodos(mostrarSkeleton) {
      if (!state.token) return;
      state.metodosLoading = true;
      state.metodosError = '';
      if (mostrarSkeleton) render();
      try {
        const data = await apiGet('reporte_metodos', parametrosReporte(state.metodosFiltros));
        state.metodosData = data;
      } catch (error) {
        state.metodosError = error.message;
      } finally {
        state.metodosLoading = false;
        render();
      }
    }

    function paginaCampo(delta) {
      const pag = state.campoData && state.campoData.paginacion;
      if (!pag) return;
      const nueva = Math.max(1, Math.min(Number(pag.pages || 1), Number(pag.page || 1) + Number(delta)));
      if (nueva === Number(pag.page || 1)) return;
      state.campoFiltros.page = nueva;
      cargarReporteCampo(false);
    }

    function paginaMetodos(delta) {
      const pag = state.metodosData && state.metodosData.paginacion;
      if (!pag) return;
      const nueva = Math.max(1, Math.min(Number(pag.pages || 1), Number(pag.page || 1) + Number(delta)));
      if (nueva === Number(pag.page || 1)) return;
      state.metodosFiltros.page = nueva;
      cargarReporteMetodos(false);
    }

    async function guardarTiempoMetodo(codigo) {
      if (state.guardandoMetodo || !state.metodosData) return;
      const actual = (state.metodosData.catalogo || []).find(function (m) { return m.codigo_dx === codigo; });
      if (!actual) return;
      const diasInput = document.getElementById('metodo-dias-' + codigo);
      const activoInput = document.getElementById('metodo-activo-' + codigo);
      state.guardandoMetodo = true;
      try {
        const data = await apiPost('save_metodo', {
          codigo_dx: codigo,
          nombre_metodo: actual.nombre_metodo,
          dias_ciclo: Number(diasInput ? diasInput.value : actual.dias_ciclo),
          requiere_cita: actual.requiere_cita,
          activo: activoInput && activoInput.checked ? 1 : 0
        });
        state.metodosData.catalogo = data.catalogo || state.metodosData.catalogo;
        showFeedback('success', 'Tiempo de ciclo actualizado para ' + codigo + '.');
        await cargarReporteMetodos(false);
      } catch (error) {
        showFeedback('error', error.message);
      } finally {
        state.guardandoMetodo = false;
        render();
      }
    }

    async function agregarMetodoCatalogo() {
      if (state.guardandoMetodo) return;
      const codigo = (document.getElementById('nuevo-metodo-codigo') || {}).value || '';
      const nombre = (document.getElementById('nuevo-metodo-nombre') || {}).value || '';
      const dias = (document.getElementById('nuevo-metodo-dias') || {}).value || '';
      state.guardandoMetodo = true;
      try {
        const data = await apiPost('save_metodo', {
          codigo_dx: String(codigo).toUpperCase().trim(),
          nombre_metodo: nombre,
          dias_ciclo: Number(dias),
          requiere_cita: 1,
          activo: 1
        });
        if (state.metodosData) state.metodosData.catalogo = data.catalogo || state.metodosData.catalogo;
        showFeedback('success', 'Método ' + codigo + ' guardado correctamente.');
        await cargarReporteMetodos(false);
      } catch (error) {
        showFeedback('error', error.message);
      } finally {
        state.guardandoMetodo = false;
        render();
      }
    }

    async function descargarReporteExcel(action, parametros, nombreArchivo) {
      try {
        const query = new URLSearchParams(Object.assign({ action: action }, parametros || {}));
        const res = await fetch(API + '?' + query.toString(), { headers: authHeaders(), cache: 'no-store' });
        if (res.status === 401) {
          clearSession();
          render();
          throw new Error('Sesión expirada. Inicie sesión nuevamente.');
        }
        if (!res.ok) {
          const data = await res.json().catch(function () { return {}; });
          throw new Error(data.error || 'No se pudo generar el archivo Excel.');
        }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = nombreArchivo;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
        showFeedback('success', 'Archivo Excel generado: ' + nombreArchivo);
      } catch (error) {
        showFeedback('error', error.message);
        render();
      }
    }

    function exportarReporteCampo(tipo) {
      descargarReporteExcel('export_reporte_campo', Object.assign({}, state.campoFiltros, { tipo: tipo }), 'reporte_campo_' + tipo + '_' + localIsoDate(0) + '.xls');
    }

    function exportarReporteMetodos() {
      descargarReporteExcel('export_reporte_metodos', Object.assign({}, state.metodosFiltros), 'reporte_metodos_' + localIsoDate(0) + '.xls');
    }

    // ---------------------------------------------------------------------
    // Handlers de autenticación
    // ---------------------------------------------------------------------
    function setAuthTab(tab) {
      state.authTab = tab;
      state.authStep = 'CREDENTIALS';
      state.feedback = null;
      render();
    }
    function setAuthStep(step) {
      state.authStep = step;
      state.authTab = 'LOGIN';
      state.feedback = null;
      render();
    }
    function setTab(tab) {
      state.activeTab = tab;
      state.feedback = null;
      render();
      if (tab === 'REPORTES') {
        if (state.reporteVista === 'CAMPO' && !state.campoData) cargarReporteCampo(true);
        if (state.reporteVista === 'PRODUCTIVIDAD' && !state.productividadData) cargarReporteProductividad(true);
        if (state.reporteVista === 'PADRON' && !state.padronData) cargarReportePadron(true);
        if (state.session && state.session.isJefa && !state.equipoData) cargarEquipoJefatura(true);
      }
      if (tab === 'PERFIL' && state.session) {
        if (state.session.isJefa && !state.equipoData) cargarEquipoJefatura(true);
        if (state.session.isAdmin && !state.accesosData) cargarAccesos(true);
        if (state.session.isAdmin && !state.movimientosData) cargarMovimientos(true);
      }
    }

    async function enterApp(session) {
      state.token = session.token;
      state.session = session;
      persistSession();
      state.authStep = 'CREDENTIALS';
      state.activeTab = 'CAPTAR';
      state.pendingUser = null;
      state.demoCode = '';
      state.challengeId = '';
      state.feedback = null;
      await loadOverview();
      startOfflineSync();
      render();
    }

    async function handleLogin(event) {
      event.preventDefault();
      state.feedback = null;
      const dni = document.getElementById('login-dni').value.trim();
      const password = document.getElementById('login-pass').value;
      try {
        const data = await apiPost('login', { dni: dni, password: password });
        if (!data.session || !data.session.token) {
          throw new Error('El servidor no emitió la sesión. Intente nuevamente.');
        }
        await enterApp(data.session);
      } catch (error) {
        showFeedback('error', error.message);
      }
    }

    async function handleRecover(event) {
      event.preventDefault();
      state.feedback = null;
      const dni = document.getElementById('rec-dni').value.trim();
      const pin = document.getElementById('rec-pin').value.trim();
      const codEstab = document.getElementById('rec-estab').value;
      const password = document.getElementById('rec-pass').value;
      const password2 = document.getElementById('rec-pass2').value;
      if (password !== password2) {
        showFeedback('error', 'Las contraseñas no coinciden. Verifique e intente nuevamente.');
        return;
      }
      try {
        const data = await apiPost('recuperar_clave', { dni: dni, pin: pin, cod_estab: codEstab, password: password });
        state.authStep = 'CREDENTIALS';
        state.authTab = 'LOGIN';
        state.feedback = { type: 'success', text: data.message || 'Contraseña actualizada. Inicie sesión con su nueva clave.' };
        render();
      } catch (error) {
        showFeedback('error', error.message);
      }
    }

    async function handleRegister(event) {
      event.preventDefault();
      state.feedback = null;
      const payload = {
        dni: document.getElementById('reg-dni').value.trim(),
        nombre1: document.getElementById('reg-nom').value.trim(),
        apaterno: document.getElementById('reg-ap').value.trim(),
        amaterno: document.getElementById('reg-am').value.trim(),
        email: document.getElementById('reg-email').value.trim(),
        celular: document.getElementById('reg-cel').value.trim(),
        cod_estab: document.getElementById('reg-estab').value,
        password: document.getElementById('reg-pass').value
      };
      try {
        const data = await apiPost('register_obstetra', payload);
        if (!data.session || !data.session.token) {
          throw new Error('El servidor no emitió la sesión. Intente nuevamente.');
        }
        await enterApp(data.session);
      } catch (error) {
        showFeedback('error', error.message);
      }
    }

    async function loadOverview() {
      if (!state.token) return;
      try {
        const data = await apiGet('overview');
        state.pacientes = data.pacientes || [];
        state.agendaAmpollas = data.agendaAmpollas || [];
        state.produccionObstetras = data.produccionObstetras || [];
        state.auditLogs = data.auditLogs || [];
        state.catalogoMetodos = data.catalogoMetodos || [];
        state.alertas = data.alertas || state.alertas;
        state.distritos = (data.distritos || []).map(function (d) { return d.DESC_DIST; });
        if (data.stats) state.stats = Object.assign(state.stats, data.stats);
        if (data.securityMetrics) state.securityMetrics = data.securityMetrics;
        if (data.session) {
          state.session = Object.assign(state.session || {}, data.session);
          persistSession();
        }
        state.offlinePending = readQueueRaw().length;
      } catch (error) {
        if (state.token) showFeedback('error', error.message);
      }
    }

    async function cambiarEstablecimiento(codEstab) {
      if (!state.token || !codEstab || (state.session && codEstab === state.session.cod_estab)) return;
      state.changingEstab = true;
      try {
        const data = await apiPost('change_establecimiento', { cod_estab: codEstab });
        state.session = Object.assign(state.session || {}, { cod_estab: data.session.cod_estab, estab_nombre: data.session.estab_nombre });
        persistSession();
        state.hisLookup = null;
        state.formDraft = null;
        state.formVisible = false;
        state.nombresDesbloqueados = false;
        state.reporteProgramacion = null;
        state.campoData = null;
        state.metodosData = null;
        state.feedback = { type: 'success', text: 'Establecimiento activo: ' + data.session.estab_nombre + '. Las búsquedas de DNI revisan toda la Red y registran en su establecimiento activo.' };
        await loadOverview();
      } catch (error) {
        state.feedback = { type: 'error', text: error.message };
      } finally {
        state.changingEstab = false;
        render();
      }
    }

    function logout() {
      if (state.token) {
        apiPost('logout', {}).catch(function () {});
      }
      clearSession();
      state.pacientes = [];
      state.auditLogs = [];
      state.feedback = null;
      render();
    }

    // ---------------------------------------------------------------------
    // Captación, 99208, Caso A/B y cola offline
    // ---------------------------------------------------------------------
    function fillDraftFromLookup(data) {
      const cap = data.existingCaptacion || {};
      const his = data.hisRecord || {};
      const pre = data.precargaDesdeHis || {};
      const distritoActual = (data.establecimiento && data.establecimiento.distrito) || 'HUARAL';
      const caso = data.casoFlujo || 'NUEVA';
      // Caso 2: el distrito del establecimiento actual manda sobre el histórico
      // para que la obstetra confirme la nueva dirección de la paciente.
      const distrito = caso === 'OTRO_ESTABLECIMIENTO'
        ? distritoActual
        : (cap.distrito || distritoActual || his.DESC_DIST || 'HUARAL');
      const isOtros = String(distrito).indexOf('OTROS:') === 0;
      return {
        dni: data.dni || pre.dni || his.DNI || cap.dni || '',
        apellido_paterno: cap.apellido_paterno || pre.apellido_paterno || his.Apellido_p || '',
        apellido_materno: cap.apellido_materno || pre.apellido_materno || his.Apellido_m || '',
        nombres: cap.nombres || pre.nombres || his.Dnombres || his.Pnombre || '',
        edad: cap.edad || pre.edad || his.EDAD || '',
        celular: cap.celular || '',
        correo: cap.correo || '',
        distrito: isOtros ? 'OTROS' : distrito,
        distritoOtros: isOtros ? String(distrito).replace('OTROS:', '').trim() : '',
        direccion: cap.direccion || '',
        sector: cap.sector || '',
        estado_paciente: cap.estado_paciente || 'INSATISFECHA_SIN_METODO'
      };
    }

    function currentDni() {
      const input = document.getElementById('f-dni');
      return input ? input.value.replace(/\D/g, '') : '';
    }

    async function validarDni() {
      const dni = currentDni();
      if (dni.length < 8) { state.feedback = { type: 'error', text: 'Ingrese un DNI válido de 8 dígitos.' }; render(); return; }
      state.feedback = null;
      try {
        const data = await apiGet('lookup_dni', { dni: dni, cod_estab: state.session.cod_estab });
        data.dni = dni;
        state.hisLookup = data;
        state.formDraft = fillDraftFromLookup(data);
        // Caso 1: pase directo con formulario opcional. Casos 2 y 3: el
        // formulario se abre automáticamente para verificar/actualizar datos.
        state.formVisible = data.casoFlujo !== 'MISMO_ESTABLECIMIENTO';
        state.nombresDesbloqueados = false;
        render();
      } catch (error) {
        state.feedback = { type: 'error', text: error.message };
        render();
      }
    }

    function toggleFormularioEdicion() {
      state.formVisible = !state.formVisible;
      render();
    }

    function desbloquearNombres() {
      state.nombresDesbloqueados = true;
      render();
    }

    function readPacienteForm() {
      const distSel = document.getElementById('f-dist').value;
      const otros = document.getElementById('f-dist-otros');
      const draft = {
        dni: currentDni(),
        apellido_paterno: document.getElementById('f-app').value.trim(),
        apellido_materno: document.getElementById('f-apm').value.trim(),
        nombres: document.getElementById('f-nom').value.trim(),
        edad: Number(document.getElementById('f-edad').value),
        celular: document.getElementById('f-cel').value.trim(),
        correo: document.getElementById('f-cor').value.trim(),
        distrito: distSel === 'OTROS' ? ('OTROS: ' + (otros ? otros.value.trim().toUpperCase() : '')) : distSel,
        distritoOtros: otros ? otros.value.trim() : '',
        direccion: document.getElementById('f-dir').value.trim(),
        sector: document.getElementById('f-sec').value.trim(),
        estado_paciente: document.getElementById('f-est').value
      };
      state.formDraft = draft;
      return draft;
    }

    async function guardarPaciente(event) {
      event.preventDefault();
      const draft = readPacienteForm();
      const payload = Object.assign({}, draft, {
        codpsal_obstetra: state.session.dni,
        atencion_99208: Boolean(state.hisLookup && state.hisLookup.atencion99208 && state.hisLookup.atencion99208.tieneCodigo99208),
        pase_ups: false
      });
      delete payload.distritoOtros;
      await savePayload(payload, false);
    }

    async function confirmarPaseUps() {
      const ups = state.hisLookup && state.hisLookup.upsPlanificacionFamiliar;
      if (!ups || !ups.paseDirectoHabilitado) return;
      const pre = state.hisLookup.precargaDesdeHis || {};
      const draft = state.formDraft || {};
      const payload = {
        dni: draft.dni || pre.dni || currentDni(),
        codpsal_obstetra: state.session.dni,
        atencion_99208: Boolean(state.hisLookup.atencion99208 && state.hisLookup.atencion99208.tieneCodigo99208),
        pase_ups: true,
        estado_paciente: 'CAPTADA_CON_METODO'
      };
      await savePayload(payload, true);
    }

    async function savePayload(payload, paseUps) {
      if (!navigator.onLine) {
        try {
          await queueOfflinePatient(payload);
          state.feedback = { type: 'success', text: paseUps ? 'Pase guardado CIFRADO en el dispositivo. Se sincronizará al recuperar señal.' : 'Sin conexión: la captación quedó guardada CIFRADA en el dispositivo y se sincronizará automáticamente.' };
          state.formDraft = null;
          state.hisLookup = null;
          state.formVisible = false;
          state.nombresDesbloqueados = false;
          render();
        } catch (error) {
          state.feedback = { type: 'error', text: 'No hay conexión y no se pudo guardar la cola cifrada: ' + error.message };
          render();
        }
        return;
      }
      try {
        const data = await apiPost('save_paciente', payload);
        state.feedback = { type: 'success', text: data.message || (paseUps ? 'Pase directo confirmado en la UPS de Planificación Familiar.' : 'Paciente guardada correctamente.') };
        state.formDraft = null;
        state.hisLookup = null;
        state.formVisible = false;
        state.nombresDesbloqueados = false;
        await loadOverview();
        render();
      } catch (error) {
        if (!navigator.onLine) {
          try {
            await queueOfflinePatient(payload);
            state.feedback = { type: 'success', text: 'Sin conexión: la captación quedó guardada CIFRADA y se sincronizará automáticamente.' };
            state.formDraft = null;
            state.hisLookup = null;
            state.formVisible = false;
            state.nombresDesbloqueados = false;
            render();
            return;
          } catch (queueError) {
            state.feedback = { type: 'error', text: queueError.message };
            render();
            return;
          }
        }
        state.feedback = { type: 'error', text: error.message };
        render();
      }
    }

    function onChangeDistrito(value) {
      state.distritoSelect = value;
      const box = document.getElementById('otros-box');
      if (box) box.classList.toggle('hidden', value !== 'OTROS');
    }

    async function cambiarEstado(id, estado) {
      try {
        await apiPost('update_estado', { id: id, estado_paciente: estado });
        await loadOverview();
        render();
      } catch (error) {
        showFeedback('error', error.message);
      }
    }

    async function verificarCadena() {
      try {
        const data = await apiPost('verify_chain', {});
        state.chainVerification = data;
        await loadOverview();
        render();
      } catch (error) {
        showFeedback('error', error.message);
      }
    }

    async function probarWaf() {
      const payload = document.getElementById('waf-payload').value;
      try {
        state.wafResult = await apiPost('test_waf', { payload: payload, targetField: 'dni' });
        await loadOverview();
        render();
      } catch (error) {
        showFeedback('error', error.message);
      }
    }

    async function generarExportacion() {
      const select = document.getElementById('sync-mode');
      state.syncMode = select ? select.value : 'directo';
      state.loadingSync = true;
      try {
        state.syncExport = await apiGet('sync_export_local_sql', { modo: state.syncMode });
      } catch (error) {
        state.feedback = { type: 'error', text: error.message };
      } finally {
        state.loadingSync = false;
        render();
      }
    }

    function descargarArchivo(nombre, contenido, tipo) {
      const blob = new Blob([contenido], { type: tipo || 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = nombre;
      a.click();
      URL.revokeObjectURL(url);
    }
    function descargarExportacion() {
      if (!state.syncExport) return;
      descargarArchivo(state.syncExport.filename, state.syncExport.sql);
    }
    async function descargarIndices() {
      try {
        const res = await fetch('./optimizar_indices_5gb.sql', { cache: 'no-store' });
        if (!res.ok) throw new Error('No se encontró optimizar_indices_5gb.sql.');
        descargarArchivo('optimizar_indices_5gb.sql', await res.text());
      } catch (error) {
        showFeedback('error', error.message);
      }
    }
    async function sincronizarOffline() {
      state.syncingOffline = true;
      render();
      await syncOfflineQueue(false);
      state.syncingOffline = false;
      render();
    }

    // ---------------------------------------------------------------------
    // Perfil, seguridad y gestión de accesos (RBAC por DNI)
    // ---------------------------------------------------------------------
    async function handlePerfil(event) {
      event.preventDefault();
      const password = (document.getElementById('per-pass') || {}).value || '';
      const password2 = (document.getElementById('per-pass2') || {}).value || '';
      if (password !== password2) {
        showFeedback('error', 'Las contraseñas no coinciden. Verifique e intente nuevamente.');
        return;
      }
      const payload = {
        nombres: (document.getElementById('per-nombres') || {}).value || '',
        apellido_paterno: (document.getElementById('per-ap') || {}).value || '',
        apellido_materno: (document.getElementById('per-am') || {}).value || '',
        celular: (document.getElementById('per-cel') || {}).value || '',
        email: (document.getElementById('per-email') || {}).value || '',
        cod_estab: (document.getElementById('per-estab') || {}).value || '',
        pin: (document.getElementById('per-pin') || {}).value || '',
        password: password
      };
      try {
        const data = await apiPost('actualizar_mi_perfil', payload);
        if (data.session) {
          state.session = Object.assign(state.session || {}, data.session);
          persistSession();
        }
        state.feedback = { type: 'success', text: data.message || 'Datos actualizados correctamente.' };
        await loadOverview();
        if (state.session && state.session.isJefa) await cargarEquipoJefatura(false);
        render();
      } catch (error) {
        showFeedback('error', error.message);
      }
    }

    function setAdminTab(tab) {
      state.adminTab = tab || 'DIRECTORIO';
      state.feedback = null;
      if (tab === 'DIRECTORIO' && !state.accesosData) cargarAccesos(true);
      if (tab === 'MOVIMIENTOS' && !state.movimientosData) cargarMovimientos(true);
      render();
    }

    function abrirAccesoModal() {
      state.showAccesoModal = true;
      state.personasSugeridas = [];
      state.accesoForm = {
        dni: '', nombre_completo: '', nombres: '', apellido_paterno: '', apellido_materno: '',
        rol: 'OBSTETRA', cod_estab: (state.session && state.session.cod_estab) || '000005481',
        pin: '', email: '', celular: '', password: '', activo: 1
      };
      render();
    }

    function cerrarAccesoModal() {
      state.showAccesoModal = false;
      state.personasSugeridas = [];
      render();
    }

    async function cargarAccesos(mostrarSkeleton) {
      if (!state.token || !state.session || !state.session.puedeGestionarAccesos) return;
      state.accesosLoading = true;
      state.accesosError = '';
      if (mostrarSkeleton) render();
      try {
        state.accesosData = await apiGet('listar_accesos', state.accesosFiltros);
      } catch (error) {
        state.accesosError = error.message;
      } finally {
        state.accesosLoading = false;
        render();
      }
    }

    async function cargarMovimientos(mostrarSkeleton) {
      if (!state.token || !state.session || !state.session.isAdmin) return;
      state.movimientosLoading = true;
      state.movimientosError = '';
      if (mostrarSkeleton) render();
      try {
        state.movimientosData = await apiGet('auditoria_movimientos', state.movimientosFiltros);
      } catch (error) {
        state.movimientosError = error.message;
      } finally {
        state.movimientosLoading = false;
        render();
      }
    }

    async function cargarEquipoJefatura(mostrarSkeleton) {
      if (!state.token || !state.session) return;
      state.equipoLoading = true;
      if (mostrarSkeleton) render();
      try {
        state.equipoData = await apiGet('equipo_jefatura');
      } catch (error) {
        state.equipoData = null;
      } finally {
        state.equipoLoading = false;
        render();
      }
    }

    let personaBuscarTimer = null;
    function buscarPersonaDebounce(valor) {
      state.accesoForm.dni = soloDigitos(valor).slice(0, 11);
      state.personasSugeridas = [];
      if (personaBuscarTimer) clearTimeout(personaBuscarTimer);
      const q = String(valor || '').trim();
      if (q.length < 2) { render(); return; }
      personaBuscarTimer = setTimeout(async function () {
        try {
          const data = await apiGet('buscar_persona', { q: q });
          state.personasSugeridas = (data.personas || []).slice(0, 8);
        } catch (error) {
          state.personasSugeridas = [];
        }
        render();
      }, 420);
    }

    function seleccionarPersona(dni, nombre) {
      state.accesoForm.dni = String(dni || '');
      state.accesoForm.nombre_completo = String(nombre || '');
      const partes = String(nombre || '').trim().split(/\s+/);
      if (partes.length >= 3) {
        state.accesoForm.apellido_paterno = partes[0];
        state.accesoForm.apellido_materno = partes[1];
        state.accesoForm.nombres = partes.slice(2).join(' ');
      }
      state.personasSugeridas = [];
      render();
    }

    function editarAcceso(dni) {
      const lista = (state.accesosData && state.accesosData.accesos) || [];
      const a = lista.find(function (item) { return String(item.dni) === String(dni); });
      if (!a) return;
      state.accesoForm = {
        dni: String(a.dni || ''),
        nombre_completo: String(a.nombre_completo || ''),
        nombres: String(a.nombres || ''),
        apellido_paterno: String(a.apellido_paterno || ''),
        apellido_materno: String(a.apellido_materno || ''),
        rol: String(a.rol || 'OBSTETRA'),
        cod_estab: String(a.cod_estab || ''),
        pin: '',
        email: String(a.email || ''),
        celular: String(a.celular || ''),
        password: '',
        activo: Number(a.activo) === 1 ? 1 : 0
      };
      state.personasSugeridas = [];
      state.showAccesoModal = true;
      render();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    async function cambiarRolUsuario(dni, rol) {
      const lista = (state.accesosData && state.accesosData.accesos) || [];
      const a = lista.find(function (item) { return String(item.dni) === String(dni); });
      if (!a) return;
      if (!window.confirm('¿Cambiar el rol de ' + (a.nombre_completo || dni) + ' a ' + rol + '?')) {
        render();
        return;
      }
      try {
        await apiPost('guardar_acceso', {
          dni: a.dni,
          nombre_completo: a.nombre_completo,
          nombres: a.nombres || '',
          apellido_paterno: a.apellido_paterno || '',
          apellido_materno: a.apellido_materno || '',
          rol: rol,
          cod_estab: a.cod_estab,
          email: a.email || '',
          celular: a.celular || '',
          activo: Number(a.activo) === 1 ? 1 : 0
        });
        state.feedback = { type: 'success', text: 'Rol actualizado a ' + rol + '.' };
        await cargarAccesos(false);
        render();
      } catch (error) {
        showFeedback('error', error.message);
      }
    }

    async function guardarAcceso() {
      const dni = soloDigitos((document.getElementById('acc-dni') || {}).value || state.accesoForm.dni || '');
      if (dni.length < 8) {
        showFeedback('error', 'Ingrese un DNI válido de 8 a 11 dígitos.');
        return;
      }
      const codEstab = state.accesoForm.cod_estab || (state.session && state.session.cod_estab) || '';
      if (!codEstab) {
        showFeedback('error', 'Seleccione el establecimiento del acceso.');
        return;
      }
      try {
        const data = await apiPost('guardar_acceso', {
          dni: dni,
          nombre_completo: state.accesoForm.nombre_completo || '',
          nombres: (document.getElementById('acc-nombres') || {}).value || state.accesoForm.nombres || '',
          apellido_paterno: (document.getElementById('acc-ap') || {}).value || state.accesoForm.apellido_paterno || '',
          apellido_materno: (document.getElementById('acc-am') || {}).value || state.accesoForm.apellido_materno || '',
          rol: state.accesoForm.rol || 'OBSTETRA',
          cod_estab: codEstab,
          email: (document.getElementById('acc-email') || {}).value || state.accesoForm.email || '',
          celular: (document.getElementById('acc-cel') || {}).value || state.accesoForm.celular || '',
          pin: (document.getElementById('acc-pin') || {}).value || state.accesoForm.pin || '',
          password: (document.getElementById('acc-pass') || {}).value || state.accesoForm.password || '',
          activo: Number(state.accesoForm.activo) === 1 ? 1 : 0
        });
        state.showAccesoModal = false;
        state.accesoForm = { dni: '', nombre_completo: '', nombres: '', apellido_paterno: '', apellido_materno: '', rol: 'OBSTETRA', cod_estab: (state.session && state.session.cod_estab) || '', pin: '', email: '', celular: '', password: '', activo: 1 };
        state.personasSugeridas = [];
        state.feedback = { type: 'success', text: data.message || 'Acceso guardado correctamente.' };
        await cargarAccesos(false);
        render();
      } catch (error) {
        showFeedback('error', error.message);
      }
    }

    async function cambiarEstadoAcceso(dni, activo) {
      const accion = Number(activo) === 1 ? 'activar' : 'desactivar';
      if (!window.confirm('¿Confirma ' + accion + ' el acceso del DNI ' + dni + '?')) return;
      try {
        await apiPost('cambiar_estado_acceso', { dni: dni, activo: Number(activo) === 1 ? 1 : 0 });
        state.feedback = { type: 'success', text: 'Acceso ' + (Number(activo) === 1 ? 'activado' : 'desactivado') + ' correctamente.' };
        await cargarAccesos(false);
        render();
      } catch (error) {
        showFeedback('error', error.message);
      }
    }

    async function resetearClaveUsuario(dni, nombre) {
      if (!window.confirm('¿Restablecer la clave de ' + (nombre || ('DNI ' + dni)) + '? La contraseña temporal será su DNI y se limpiará el PIN.')) return;
      try {
        const data = await apiPost('resetear_clave_usuario', { dni: dni });
        state.feedback = { type: 'success', text: data.message || ('Clave de ' + dni + ' restablecida a su DNI.') };
        if (state.session && state.session.puedeGestionarAccesos) await cargarAccesos(false);
        if (state.session && state.session.isJefa) await cargarEquipoJefatura(false);
        render();
      } catch (error) {
        showFeedback('error', error.message);
      }
    }

    async function resetearClaveManual() {
      const input = document.getElementById('reset-dni');
      const dni = soloDigitos(input ? input.value : state.resetDni || '');
      state.resetDni = dni;
      if (dni.length < 8) {
        showFeedback('error', 'Ingrese un DNI válido de 8 a 11 dígitos.');
        return;
      }
      await resetearClaveUsuario(dni, '');
    }

    // ---------------------------------------------------------------------
    // PWA, iOS y sincronización automática
    // ---------------------------------------------------------------------
    let deferredInstallPrompt = null;
    window.addEventListener('beforeinstallprompt', function (event) {
      event.preventDefault();
      deferredInstallPrompt = event;
      state.canInstall = true;
      render();
    });
    async function installPwa() {
      if (deferredInstallPrompt) {
        deferredInstallPrompt.prompt();
        await deferredInstallPrompt.userChoice;
        deferredInstallPrompt = null;
        state.canInstall = false;
        render();
        return;
      }
      const ua = window.navigator.userAgent.toLowerCase();
      if (/iphone|ipad|ipod/.test(ua)) {
        state.iosBanner = true;
        render();
        return;
      }
      showFeedback('error', 'Para instalar: abra el menú del navegador y elija “Instalar aplicación” o “Agregar a pantalla de inicio”.');
    }

    function isIos() {
      return /iphone|ipad|ipod/.test(window.navigator.userAgent.toLowerCase());
    }
    function isStandalone() {
      return window.matchMedia('(display-mode: standalone)').matches ||
        window.navigator.standalone === true;
    }
    function renderIosBanner() {
      const container = document.getElementById('ios-banner-root');
      if (!container) return;
      if (!state.iosBanner || localStorage.getItem(IOS_DISMISS_KEY) === '1') {
        container.innerHTML = '';
        return;
      }
      container.innerHTML = `<div class="fixed inset-x-0 bottom-16 z-50 px-3 safe-bottom">
        <div class="mx-auto max-w-[430px] rounded-2xl bg-slate-950 text-white shadow-2xl border border-slate-700 p-4">
          <div class="flex items-start justify-between gap-3"><div><div class="text-sm font-bold">Instalar PlanificaHIS en iPhone</div><div class="text-[11px] text-slate-300">Paso ${state.iosStep} de 2 · Safari iOS</div></div><button type="button" onclick="dismissIosBanner()" class="text-slate-400 text-lg leading-none" aria-label="Cerrar">×</button></div>
          <p class="mt-3 text-xs text-slate-200">${state.iosStep === 1 ? '1. Toca el botón Compartir en la barra inferior de Safari (cuadro con flecha hacia arriba).' : '2. Desliza y elige “Agregar a pantalla de inicio”, luego confirma con “Agregar”.'}</p>
          <div class="mt-3 flex items-center justify-between"><button type="button" onclick="dismissIosBanner()" class="min-h-[40px] px-3 text-xs font-semibold text-slate-300">Ahora no</button>${state.iosStep === 1 ? '<button type="button" onclick="nextIosStep()" class="min-h-[40px] px-4 rounded-xl bg-sky-600 text-xs font-bold">Siguiente paso</button>' : '<button type="button" onclick="dismissIosBanner()" class="min-h-[40px] px-4 rounded-xl bg-emerald-600 text-xs font-bold">Entendido</button>'}</div>
        </div></div>`;
    }
    function nextIosStep() { state.iosStep = 2; renderIosBanner(); }
    function dismissIosBanner() {
      try { localStorage.setItem(IOS_DISMISS_KEY, '1'); } catch (e) {}
      state.iosBanner = false;
      renderIosBanner();
    }

    let syncTimer = null;
    function startOfflineSync() {
      if (syncTimer) return;
      syncTimer = setInterval(function () {
        if (state.token && navigator.onLine && readQueueRaw().length) syncOfflineQueue(true);
      }, 60000);
    }
    window.addEventListener('online', function () {
      if (state.token) syncOfflineQueue(true);
      render();
    });
    window.addEventListener('offline', function () { render(); });

    if ('serviceWorker' in navigator) {
      window.addEventListener('load', function () {
        navigator.serviceWorker.register('./sw.js', { scope: './' }).catch(function () {
          // La app funciona igual sin SW; el registro es opcional.
        });
      });
    }

    // Restaurar sesión persistente (7 días) desde localStorage o cookie HttpOnly.
    (async function boot() {
      if (isIos() && !isStandalone()) state.iosBanner = true;
      state.offlinePending = readQueueRaw().length;
      let sesionGuardada = null;
      try {
        const raw = localStorage.getItem(SESSION_KEY) || sessionStorage.getItem(SESSION_KEY) || '';
        if (raw) sesionGuardada = JSON.parse(raw);
      } catch (e) {
        sesionGuardada = null;
      }
      if (sesionGuardada && sesionGuardada.token) {
        state.token = sesionGuardada.token;
        state.session = sesionGuardada;
      }
      try {
        // Valida el Bearer de localStorage o la cookie HttpOnly y renueva la
        // sesión 7 días (sliding expiration) sin pedir login.
        const data = await apiGet('session_restore');
        if (data && data.session && data.session.token) {
          state.token = data.session.token;
          state.session = data.session;
          persistSession();
          await loadOverview();
          startOfflineSync();
        }
      } catch (e) {
        // Sin sesión válida se muestra el login. Si el fallo es de red y la
        // sesión local sigue presente, se conserva para operar offline.
        if (!state.token || !state.session) clearSession();
      }
      render();
      updatePendingIndicators();
    })();
  </script>
</body>
</html>
