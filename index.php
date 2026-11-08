<?php
/**
 * index.php — Interfaz móvil oficial (Apache + PHP + MariaDB / XAMPP)
 * Hospital San Juan Bautista Huaral — Red de Salud Huaral-Chancay
 *
 * Esta variante consume api.php con Bearer Token emitido tras validar DNI y
 * contraseña (el segundo factor TOTP es opcional con APP_2FA_REQUIRED=1).
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
  <link rel="icon" type="image/svg+xml" href="./public/icon.svg" />
  <link rel="apple-touch-icon" href="./public/apple-touch-icon.png" />
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
  <style>
    body { font-family: 'Plus Jakarta Sans', sans-serif; -webkit-tap-highlight-color: transparent; }
    .font-mono { font-family: 'JetBrains Mono', monospace; font-variant-numeric: tabular-nums; }
    .hide-scrollbar::-webkit-scrollbar { display: none; }
    .safe-bottom { padding-bottom: env(safe-area-inset-bottom); }
  </style>
</head>
<body class="bg-slate-200/70 text-slate-900 antialiased min-h-screen flex flex-col items-center">
  <div id="app-root" class="w-full max-w-[430px] min-h-screen bg-slate-50 shadow-2xl border-x border-slate-200 flex flex-col relative"></div>
  <div id="ios-banner-root"></div>

  <script>
    'use strict';

    const CATALOGO = <?= $catalogoJson ?>;
    const POR_DISTRITO = <?= $porDistritoJson ?>;
    const TOTAL_ESTABLECIMIENTOS = <?= (int)$totalEstablecimientos ?>;
    const APK_URL = <?= $apkJson ?>;
    const API = './api.php';
    const TOKEN_KEY = 'planificahis.php.token.v1';
    const SESSION_KEY = 'planificahis.php.session.v1';
    const QUEUE_KEY = 'planificahis.php.offline.queue.v1';
    const DEVICE_KEY = 'planificahis.php.offline.device-key.v1';
    const IOS_DISMISS_KEY = 'planificahis.php.ios-install-dismissed.v1';
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

    const LOGO_SVG = `
      <svg viewBox="0 0 240 260" fill="none" xmlns="http://www.w3.org/2000/svg" class="w-full h-full">
        <ellipse cx="120" cy="130" rx="96" ry="116" fill="#FFFFFF" stroke="#0082C8" stroke-width="8" />
        <path d="M52 46 C 85 95, 85 165, 52 214" stroke="#0082C8" stroke-width="7" stroke-linecap="round" fill="none" />
        <path d="M188 46 C 155 95, 155 165, 188 214" stroke="#0082C8" stroke-width="7" stroke-linecap="round" fill="none" />
        <path d="M78 74 C 92 74, 96 86, 96 96 L 96 164 C 96 174, 92 186, 78 186" stroke="#0082C8" stroke-width="6" fill="none" />
        <path d="M162 74 C 148 74, 144 86, 144 96 L 144 164 C 144 174, 148 186, 162 186" stroke="#0082C8" stroke-width="6" fill="none" />
        <rect x="66" y="38" width="108" height="36" fill="#FFFFFF" stroke="#0082C8" stroke-width="7" />
        <text x="120" y="62" text-anchor="middle" fill="#111827" font-family="Arial, sans-serif" font-weight="900" font-size="18">HOSPITAL</text>
        <rect x="66" y="186" width="108" height="36" fill="#FFFFFF" stroke="#0082C8" stroke-width="7" />
        <text x="120" y="210" text-anchor="middle" fill="#111827" font-family="Arial, sans-serif" font-weight="900" font-size="18">HUARAL</text>
        <path d="M120 104 C 98 90, 74 92, 66 104 C 76 112, 96 114, 120 112 Z" fill="#D4AF37" stroke="#9A7B1C" stroke-width="2" />
        <path d="M120 104 C 142 90, 166 92, 174 104 C 164 112, 144 114, 120 112 Z" fill="#D4AF37" stroke="#9A7B1C" stroke-width="2" />
        <line x1="120" y1="84" x2="120" y2="178" stroke="#B8860B" stroke-width="5" stroke-linecap="round" />
        <circle cx="120" cy="82" r="8" fill="#EAB308" stroke="#9A7B1C" stroke-width="2.5" />
        <text x="120" y="152" text-anchor="middle" fill="#0F172A" font-family="Georgia, serif" font-weight="bold" font-size="48">SJB</text>
      </svg>`;

    function localIsoDate(offsetDays) {
      const d = new Date();
      d.setDate(d.getDate() + Number(offsetDays || 0));
      const mm = String(d.getMonth() + 1).padStart(2, '0');
      const dd = String(d.getDate()).padStart(2, '0');
      return d.getFullYear() + '-' + mm + '-' + dd;
    }

    function formatIsoToDdMmYyyy(iso) {
      const value = String(iso || '').slice(0, 10);
      const parts = value.split('-');
      return parts.length === 3 ? (parts[2] + '/' + parts[1] + '/' + parts[0]) : '';
    }

    let state = {
      token: sessionStorage.getItem(TOKEN_KEY) || '',
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
      iosBanner: false,
      iosStep: 1,
      showSecurity: true,
      booted: false,
      reporteFecha: localIsoDate(0),
      reporteModo: 'exacto',
      reporteAlcance: 'establecimiento',
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
      sessionStorage.removeItem(TOKEN_KEY);
      sessionStorage.removeItem(SESSION_KEY);
    }

    function persistSession() {
      if (state.token) sessionStorage.setItem(TOKEN_KEY, state.token);
      if (state.session) sessionStorage.setItem(SESSION_KEY, JSON.stringify(state.session));
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
          <div class="w-24 h-24 mx-auto mb-3">${LOGO_SVG}</div>
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
            </form>` : ''}
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
          ${state.authStep === 'VERIFY_2FA' ? `
            <form onsubmit="handleVerify2FA(event)" class="space-y-4">
              <div class="p-4 rounded-2xl bg-sky-950 text-white space-y-2">
                <div class="text-xs font-semibold text-sky-200">Verificación de Seguridad en Dos Pasos (2FA TOTP)</div>
                <div class="text-xs text-slate-300">${esc((state.pendingUser && state.pendingUser.nombreCompleto) || 'Obstetra')} · ${esc((state.pendingUser && state.pendingUser.estab_nombre) || '')}</div>
                ${state.demoCode ? `<div class="flex items-center justify-between pt-1"><span class="text-2xl font-bold font-mono tracking-widest">${esc(state.demoCode)}</span><button type="button" onclick="useDemoCode()" class="px-3 py-1.5 rounded-lg bg-sky-700 text-xs font-semibold">Usar código</button></div>` : '<p class="text-[11px] text-slate-300">Abra su aplicación autenticadora e ingrese el código de 6 dígitos.</p>'}
              </div>
              ${state.pendingUser && state.pendingUser.totpSecret ? `<div class="p-3.5 rounded-xl bg-amber-50 border border-amber-300 text-[11px] text-amber-950 space-y-1.5">
                <div class="font-bold">Enrole su autenticador (clave visible una sola vez)</div>
                <p>En Google Authenticator o Microsoft Authenticator elija “Agregar cuenta → Clave de configuración” e ingrese:</p>
                <div class="font-mono text-xs break-all bg-white/80 rounded-lg p-2 border border-amber-200">${esc(state.pendingUser.totpSecret)}</div>
                ${state.pendingUser.otpauthUri ? `<div class="font-mono text-[9px] break-all text-amber-800">${esc(state.pendingUser.otpauthUri)}</div>` : ''}
              </div>` : ''}
              <div>
                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Código de 6 dígitos</label>
                <input id="totp-input" type="text" inputmode="numeric" maxlength="6" value="${esc(state.demoCode)}" required class="w-full min-h-[50px] px-4 rounded-xl border border-slate-300 text-center text-xl font-bold font-mono tracking-widest" />
              </div>
              <div class="flex gap-2.5">
                <button type="button" onclick="backToCredentials()" class="min-h-[48px] px-4 rounded-xl border border-slate-300 text-xs font-semibold text-slate-700">Atrás</button>
                <button type="submit" class="flex-1 min-h-[48px] rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-sm font-semibold">Confirmar y Entrar</button>
              </div>
            </form>` : ''}
        </div>
        <div class="px-6 py-4 bg-slate-50 border-t border-slate-100 flex items-center justify-between">
          <span class="text-xs text-slate-500">App Móvil Oficial</span>
          <button type="button" onclick="installPwa()" class="min-h-[40px] px-3 rounded-xl bg-slate-900 text-white text-xs font-semibold">Instalar</button>
        </div>`;
    }

    function renderApp() {
      const s = state.session;
      return `
        <div class="sticky top-0 z-30 bg-white/95 backdrop-blur-md border-b border-slate-200 px-3 py-2.5 flex items-center justify-between gap-2">
          <div class="flex items-center gap-2 min-w-0 flex-1">
            <div class="w-9 h-9 shrink-0">${LOGO_SVG}</div>
            <div class="min-w-0 flex-1">
              <div class="text-xs font-bold text-slate-900 truncate">${esc(s.nombreCompleto || 'Hospital SJB Huaral')}</div>
              <select aria-label="Establecimiento activo" onchange="cambiarEstablecimiento(this.value)" ${state.changingEstab ? 'disabled' : ''} class="mt-0.5 w-full max-w-[250px] min-h-[30px] px-2 py-0.5 rounded-lg border border-sky-200 bg-sky-50 text-[10px] text-sky-950 font-medium truncate">
                ${optionsEstablecimientos(s.cod_estab || '000005481')}
              </select>
            </div>
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <span data-pending class="hidden px-2 py-1 rounded-lg bg-amber-100 text-amber-900 text-[10px] font-bold"></span>
            <button type="button" onclick="logout()" aria-label="Cerrar sesión" class="min-h-[40px] min-w-[40px] flex items-center justify-center rounded-xl text-slate-500 hover:text-red-600 hover:bg-slate-100">Salir</button>
          </div>
        </div>
        ${!navigator.onLine ? '<div class="mx-4 mt-3 p-2.5 rounded-xl bg-amber-50 border border-amber-200 text-[11px] text-amber-900 font-medium">Sin conexión. Las captaciones se guardarán cifradas en este dispositivo y se sincronizarán automáticamente.</div>' : ''}
        <main class="flex-1 p-4 pb-24 space-y-4">
          ${state.activeTab === 'CAPTAR' ? renderCaptar() : ''}
          ${state.activeTab === 'PACIENTES' ? renderPacientes() : ''}
          ${state.activeTab === 'AGENDA' ? renderAgenda() : ''}
          ${state.activeTab === 'SEGURIDAD' ? renderSeguridad() : ''}
          ${state.activeTab === 'PERFIL' ? renderPerfil() : ''}
        </main>
        <nav class="fixed bottom-0 left-1/2 -translate-x-1/2 w-full max-w-[430px] z-40 bg-white/95 backdrop-blur-md border-t border-slate-200 grid grid-cols-5 items-center h-16 safe-bottom">
          ${navButton('CAPTAR', 'Captar')}
          ${navButton('PACIENTES', 'Pacientes')}
          ${navButton('AGENDA', 'Agenda')}
          ${navButton('SEGURIDAD', 'Seguridad')}
          ${navButton('PERFIL', 'Mi Perfil')}
        </nav>`;
    }

    function navButton(tab, label) {
      const active = state.activeTab === tab;
      return '<button type="button" onclick="setTab(\'' + tab + '\')" class="min-h-[44px] flex flex-col items-center justify-center ' +
        (active ? 'text-sky-700 font-bold' : 'text-slate-400') + '"><span class="text-[11px]">' + label + '</span></button>';
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
      const wa = whatsappHref(fila.celular);
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
          <div class="flex gap-1.5 shrink-0">
            ${tel ? '<a href="' + esc(tel) + '" class="px-2 py-1 rounded-lg bg-slate-900 text-white text-[10px] font-bold">📞 Llamar</a>' : ''}
            ${wa ? '<a href="' + esc(wa) + '" target="_blank" rel="noopener" class="px-2 py-1 rounded-lg bg-emerald-600 text-white text-[10px] font-bold">WhatsApp</a>' : ''}
          </div>
        </div>
        <div class="text-[9px] text-slate-500 font-mono">${esc(fila.establecimiento)} · Obstetra ${esc(fila.obstetra_dni || '—')}</div>
      </div>`;
    }

    function renderReporteProgramacion() {
      const r = state.reporteProgramacion;
      if (!r) return '';
      const filas = r.filas || [];
      const visibles = filas.slice(0, 100);
      const resumen = r.resumen || {};
      const tituloAlcance = r.alcance === 'red' ? 'Toda la Red Huaral-Chancay' : ((r.establecimiento && r.establecimiento.nombre) || 'Mi establecimiento');
      return `<div class="p-4 rounded-2xl bg-white border-2 border-sky-200 space-y-3">
        <div class="flex items-start justify-between gap-2">
          <div>
            <h3 class="text-sm font-bold text-slate-900">Programación calculada</h3>
            <p class="text-[10px] text-slate-500">${esc(descripcionRangoReporte(r))} · ${esc(tituloAlcance)}</p>
            <p class="text-[10px] text-slate-500">Método: ${esc(etiquetaFiltroMetodo(r))}</p>
          </div>
          <span class="px-2.5 py-1 rounded-xl bg-sky-700 text-white text-xs font-extrabold shrink-0">${Number(resumen.total || 0)}</span>
        </div>
        <div class="grid grid-cols-3 gap-1.5 text-center">
          <div class="p-2 rounded-xl bg-red-50 border border-red-200"><div class="text-[9px] font-bold text-red-800">Vencidas</div><div class="text-base font-extrabold font-mono text-red-700">${Number(resumen.vencido_abandono || 0)}</div></div>
          <div class="p-2 rounded-xl bg-amber-50 border border-amber-200"><div class="text-[9px] font-bold text-amber-800">Toca en fecha</div><div class="text-base font-extrabold font-mono text-amber-700">${Number(resumen.toca_en_fecha || 0)}</div></div>
          <div class="p-2 rounded-xl bg-sky-50 border border-sky-200"><div class="text-[9px] font-bold text-sky-800">Próx. 7 días</div><div class="text-base font-extrabold font-mono text-sky-700">${Number(resumen.proximo_7_dias || 0)}</div></div>
        </div>
        <div class="grid grid-cols-1 gap-1.5">
          <button type="button" onclick="exportarReporteExcel()" class="min-h-[42px] rounded-xl bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-bold">📊 Exportar Excel (.xls)</button>
          <button type="button" onclick="descargarVistaCelular()" class="min-h-[42px] rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-xs font-bold">📱 Descargar Vista Celular</button>
          <button type="button" onclick="copiarResumenWhatsapp()" class="min-h-[42px] rounded-xl bg-teal-700 hover:bg-teal-800 text-white text-xs font-bold">📲 Copiar Resumen WhatsApp</button>
        </div>
        <div class="space-y-2">
          ${visibles.length ? visibles.map(renderReporteCard).join('') : '<div class="p-4 rounded-xl bg-slate-50 border border-slate-200 text-center text-xs text-slate-500">No hay pacientes programadas para los filtros seleccionados.</div>'}
        </div>
        ${filas.length > visibles.length ? '<div class="text-[10px] text-center text-slate-500">Mostrando ' + visibles.length + ' de ' + filas.length + '. El Excel y la vista celular incluyen todas las filas.</div>' : ''}
      </div>`;
    }

    function renderAgenda() {
      const r = state.reporteProgramacion;
      const hoy = localIsoDate(0);
      const manana = localIsoDate(1);
      return `<div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
        <div class="flex items-start justify-between gap-2">
          <div>
            <h3 class="text-sm font-bold text-slate-900">Reporte de Programación por Fecha</h3>
            <p class="text-[10px] text-slate-500 leading-relaxed">Calcula el próximo método desde la última aplicación en HIS + los días del ciclo. Diseñado para Obstetricia.</p>
          </div>
          <span class="px-2 py-1 rounded-lg bg-sky-100 text-sky-800 text-[9px] font-extrabold shrink-0">PF</span>
        </div>
        <div class="grid grid-cols-4 gap-1.5">
          <button type="button" onclick="aplicarRapidoReporte('hoy')" class="min-h-[38px] rounded-xl text-[10px] font-bold ${state.reporteModo === 'exacto' && state.reporteFecha === hoy ? 'bg-sky-700 text-white' : 'bg-slate-100 text-slate-700'}">Hoy</button>
          <button type="button" onclick="aplicarRapidoReporte('manana')" class="min-h-[38px] rounded-xl text-[10px] font-bold ${state.reporteModo === 'exacto' && state.reporteFecha === manana ? 'bg-sky-700 text-white' : 'bg-slate-100 text-slate-700'}">Mañana</button>
          <button type="button" onclick="aplicarRapidoReporte('7d')" class="min-h-[38px] rounded-xl text-[10px] font-bold ${state.reporteModo === 'ventana_7d' ? 'bg-sky-700 text-white' : 'bg-slate-100 text-slate-700'}">Próx. 7 días</button>
          <button type="button" onclick="aplicarRapidoReporte('vencidas')" class="min-h-[38px] rounded-xl text-[10px] font-bold ${state.reporteModo === 'vencidas' ? 'bg-red-700 text-white' : 'bg-slate-100 text-slate-700'}">Vencidas</button>
        </div>
        <div>
          <label class="block text-xs font-semibold text-slate-700 mb-1">Fecha a consultar</label>
          <input id="rep-fecha" type="date" value="${esc(state.reporteFecha)}" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm font-mono" />
        </div>
        <div class="grid grid-cols-1 gap-2">
          <div>
            <label class="block text-xs font-semibold text-slate-700 mb-1">Método</label>
            <select id="rep-metodo" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-xs bg-white">
              <option value="TODOS" ${state.reporteMetodo === 'TODOS' ? 'selected' : ''}>Todos los métodos</option>
              <option value="90782" ${state.reporteMetodo === '90782' ? 'selected' : ''}>Ampolla Mensual (30d)</option>
              <option value="Z304" ${state.reporteMetodo === 'Z304' ? 'selected' : ''}>Ampolla Trimestral (90d)</option>
              <option value="99208" ${state.reporteMetodo === '99208' ? 'selected' : ''}>Código 99208 (30d)</option>
              <option value="Z301,58300,11981" ${state.reporteMetodo === 'Z301,58300,11981' ? 'selected' : ''}>DIU / Implante (365 / 1095d)</option>
              <option value="9920801" ${state.reporteMetodo === '9920801' ? 'selected' : ''}>Administración Mensual (30d)</option>
              <option value="9920802" ${state.reporteMetodo === '9920802' ? 'selected' : ''}>Administración Trimestral (90d)</option>
              <option value="9940204" ${state.reporteMetodo === '9940204' ? 'selected' : ''}>Orientación / Consejería (30d)</option>
              <option value="Z300" ${state.reporteMetodo === 'Z300' ? 'selected' : ''}>Consejería General (15d)</option>
            </select>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="block text-xs font-semibold text-slate-700 mb-1">Alcance</label>
              <select id="rep-alcance" class="w-full min-h-[44px] px-2 rounded-xl border border-slate-300 text-[11px] bg-white">
                <option value="establecimiento" ${state.reporteAlcance === 'establecimiento' ? 'selected' : ''}>Mi Establecimiento</option>
                <option value="red" ${state.reporteAlcance === 'red' ? 'selected' : ''}>Toda la Red</option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-700 mb-1">Rango</label>
              <select id="rep-rango" class="w-full min-h-[44px] px-2 rounded-xl border border-slate-300 text-[11px] bg-white">
                <option value="exacto" ${state.reporteModo === 'exacto' ? 'selected' : ''}>Fecha exacta</option>
                <option value="ventana_7d" ${state.reporteModo === 'ventana_7d' ? 'selected' : ''}>Próximos 7 días</option>
                <option value="vencidas" ${state.reporteModo === 'vencidas' ? 'selected' : ''}>Vencidas</option>
                <option value="todos" ${state.reporteModo === 'todos' ? 'selected' : ''}>Todos</option>
              </select>
            </div>
          </div>
        </div>
        <button type="button" onclick="buscarProgramacion()" ${state.reporteLoading ? 'disabled' : ''} class="w-full min-h-[46px] rounded-xl bg-slate-900 hover:bg-slate-800 disabled:opacity-60 text-white text-xs font-bold">${state.reporteLoading ? 'Calculando programación...' : 'Buscar Programación'}</button>
        ${state.reporteError ? '<div class="p-3 rounded-xl bg-red-50 border border-red-200 text-[11px] text-red-800">' + esc(state.reporteError) + '</div>' : ''}
        ${state.feedback ? '<div class="p-3 rounded-xl border text-[11px] ' + (state.feedback.type === 'error' ? 'bg-red-50 border-red-200 text-red-800' : 'bg-emerald-50 border-emerald-200 text-emerald-900') + '">' + esc(state.feedback.text) + '</div>' : ''}
      </div>
      ${renderReporteProgramacion()}
      <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
        <div class="flex items-center justify-between"><h3 class="text-sm font-bold text-slate-900">Agenda de Ampollas y Controles</h3><span class="text-[10px] text-slate-500">Próximas citas HIS</span></div>
        <div class="divide-y divide-slate-100">${state.agendaAmpollas.length ? state.agendaAmpollas.map(function (a) {
          return '<div class="py-3 text-xs"><div class="flex items-center justify-between font-bold text-slate-900"><span>' + esc(a.paciente_nombre) + '</span><span class="font-mono text-slate-500">DNI ' + esc(a.dni) + '</span></div><div class="text-slate-600">' + esc(a.metodo_descripcion || a.codigo_his) + '</div><div class="flex items-center justify-between pt-1"><span class="font-mono text-[11px] text-slate-500">Próxima: <strong>' + esc(a.fecha_proxima_cita || 'Sin método') + '</strong></span><span class="' + (a.estado_cita === 'VENCIDA_ABANDONO' ? 'text-red-700' : 'text-sky-800') + ' font-bold">' + esc(a.estado_cita) + '</span></div></div>';
        }).join('') : '<div class="py-3 text-xs text-slate-500">Sin citas de ampolla en el lote actual.</div>'}</div>
      </div>
      <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-2.5">
        <h3 class="text-sm font-bold text-slate-900">Avance de Captación por Obstetra</h3>
        <div class="divide-y divide-slate-100 text-xs">${state.produccionObstetras.length ? state.produccionObstetras.map(function (o) {
          return '<div class="py-2.5 flex items-center justify-between"><div><div class="font-semibold text-slate-900">' + esc(o.nombre) + '</div><div class="font-mono text-[11px] text-slate-500">DNI: ' + esc(o.codpsal) + '</div></div><div class="text-right font-mono"><div class="font-bold text-sky-800">' + Number(o.totalCaptadas || 0) + ' captadas</div><div class="text-[11px] text-amber-700">' + Number(o.insatisfechasCaptadas || 0) + ' sin método</div></div></div>';
        }).join('') : '<div class="py-2 text-slate-500">Sin registros aún.</div>'}</div>
      </div>`;
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
      if (fechaInput && fechaInput.value) state.reporteFecha = fechaInput.value;
      if (metodoInput) state.reporteMetodo = metodoInput.value || 'TODOS';
      if (alcanceInput) state.reporteAlcance = alcanceInput.value || 'establecimiento';
      if (rangoInput) state.reporteModo = rangoInput.value || 'exacto';
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
        '<table>' +
        '<tr><td colspan="15" class="title">HOSPITAL SAN JUAN BAUTISTA HUARAL</td></tr>' +
        '<tr><td colspan="15" class="sub">RED DE SALUD HUARAL-CHANCAY · PLANIFICACIÓN FAMILIAR</td></tr>' +
        '<tr><td colspan="15" class="sub2">REPORTE DE PROGRAMACIÓN DE MÉTODOS POR FECHA</td></tr>' +
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

    function renderSeguridad() {
      const m = state.securityMetrics;
      const chain = state.chainVerification;
      return `
        <div class="grid grid-cols-2 gap-2.5">
          <div class="p-3.5 rounded-2xl bg-white border border-slate-200"><div class="text-[10px] text-slate-500">SQLi / XSS bloqueados</div><div class="text-xl font-bold font-mono">${Number(m.sqliBlockedCount || 0) + Number(m.xssBlockedCount || 0)}</div><div class="text-[10px] text-teal-700">${Number(m.sqliBlockedCount || 0)} SQLi · ${Number(m.xssBlockedCount || 0)} XSS</div></div>
          <div class="p-3.5 rounded-2xl bg-white border border-slate-200"><div class="text-[10px] text-slate-500">Registros cifrados AES-256</div><div class="text-xl font-bold font-mono">${Number(m.encryptedRecordsCount || 0)}</div><div class="text-[10px] text-teal-700">PII protegida en reposo</div></div>
          <div class="p-3.5 rounded-2xl bg-white border border-slate-200"><div class="text-[10px] text-slate-500">Verificaciones 2FA</div><div class="text-xl font-bold font-mono">${Number(m.totpVerifiedCount || 0)}</div><div class="text-[10px] text-slate-600">RFC 6238 · 30 s</div></div>
          <div class="p-3.5 rounded-2xl bg-white border border-slate-200"><div class="text-[10px] text-slate-500">Eventos de auditoría</div><div class="text-xl font-bold font-mono">${Number(m.auditLogCount || state.auditLogs.length || 0)}</div><div class="text-[10px] text-teal-700">Cadena SHA-256</div></div>
        </div>

        <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
          <div class="flex items-center justify-between gap-2">
            <div><h3 class="text-sm font-bold text-slate-900">Auditoría clínica SHA-256</h3><p class="text-[10px] text-slate-500">Actor, establecimiento, plataforma, IP y hash encadenado.</p></div>
            <button type="button" onclick="verificarCadena()" class="min-h-[38px] px-3 rounded-xl bg-slate-900 text-white text-[11px] font-semibold">Verificar cadena</button>
          </div>
          ${chain ? `<div class="p-3 rounded-xl border text-[11px] ${chain.valid ? 'bg-teal-50 border-teal-200 text-teal-900' : 'bg-red-50 border-red-300 text-red-900'}">${chain.valid ? 'Integridad verificada: ' + Number(chain.verified || 0) + ' bloques sin alteración.' : 'CADENA ALTERADA en el registro #' + esc(chain.brokenAt || 'desconocido') + '. Notifique a Estadística.'}</div>` : ''}
          <div class="divide-y divide-slate-100 max-h-72 overflow-y-auto">
            ${state.auditLogs.slice(0, 20).map(function (log) {
              return '<div class="py-2.5 text-[11px]"><div class="flex items-center justify-between gap-2 font-mono text-slate-500"><span>' + esc(log.accion) + '</span><span>' + esc(log.fecha_hora) + '</span></div><div class="text-slate-700 mt-0.5">' + esc(log.detalle) + '</div><div class="text-slate-400 font-mono mt-0.5">' + esc(log.actor_dni) + ' · ' + esc(log.actor_estab || '') + ' · ' + esc(log.plataforma || '') + ' · IP ' + esc(log.ip) + '</div></div>';
            }).join('') || '<div class="py-2 text-slate-500">Sin eventos de auditoría disponibles.</div>'}
          </div>
        </div>

        <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
          <h3 class="text-sm font-bold text-slate-900">Prueba Anti-SQLi y Anti-XSS</h3>
          <p class="text-[11px] text-slate-500">El WAF audita el intento y nunca modifica las tablas del hospital.</p>
          <textarea id="waf-payload" rows="2" class="w-full p-3 rounded-xl border border-slate-300 text-xs font-mono">73819204' OR '1'='1 --</textarea>
          <button type="button" onclick="probarWaf()" class="w-full min-h-[42px] rounded-xl bg-slate-900 text-white text-xs font-semibold">Ejecutar prueba</button>
          ${state.wafResult ? `<div class="p-3 rounded-xl border text-[11px] ${state.wafResult.blocked ? 'bg-red-50 border-red-200 text-red-900' : 'bg-teal-50 border-teal-200 text-teal-900'}"><div class="font-bold">${state.wafResult.blocked ? 'ATAQUE ' + esc(state.wafResult.attackType) + ' BLOQUEADO' : 'ENTRADA LIMPIA PERMITIDA'}</div><div class="font-mono mt-1 break-all">Patrón: ${esc(state.wafResult.matchedPattern || '—')}</div><div class="font-mono mt-1 break-all">AES: ${esc(state.wafResult.aes256Preview || '')}</div></div>` : ''}
        </div>

        ${state.session && state.session.isAdmin ? `<div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
          <h3 class="text-sm font-bold text-slate-900">Exportación Nube → Local (5 GB)</h3>
          <p class="text-[11px] text-slate-500">Solo administrador. INSERT ... ON DUPLICATE KEY UPDATE, sin DROP/DELETE.</p>
          <select id="sync-mode" class="w-full min-h-[42px] px-3 rounded-xl border border-slate-300 text-xs bg-white">
            <option value="directo" ${state.syncMode === 'directo' ? 'selected' : ''}>Directo · ON DUPLICATE KEY UPDATE</option>
            <option value="puente" ${state.syncMode === 'puente' ? 'selected' : ''}>Puente · r_his_dl + sp_get_recepcion()</option>
          </select>
          <button type="button" onclick="generarExportacion()" class="w-full min-h-[42px] rounded-xl bg-slate-900 text-white text-xs font-semibold">${state.loadingSync ? 'Generando...' : 'Generar exportación SQL'}</button>
          ${state.syncExport ? `<div class="p-3 rounded-xl bg-slate-50 border border-slate-200 text-[11px] space-y-1"><div class="font-semibold">${esc(state.syncExport.filename)} · ${state.syncExport.rows} filas</div><div class="text-slate-600">${esc((state.syncExport.tables || []).join(', ') || 'Sin tablas locales')}</div><div class="flex gap-2 pt-1"><button type="button" onclick="descargarExportacion()" class="px-3 py-1.5 rounded-lg bg-teal-700 text-white font-semibold">Descargar SQL</button><button type="button" onclick="descargarIndices()" class="px-3 py-1.5 rounded-lg bg-slate-800 text-white font-semibold">Descargar índices</button></div></div>` : ''}
          <button type="button" onclick="descargarIndices()" class="w-full min-h-[40px] rounded-xl border border-slate-300 text-slate-800 text-xs font-semibold">Descargar optimizar_indices_5gb.sql</button>
        </div>` : ''}`;
    }

    function renderPerfil() {
      const s = state.session;
      return `<div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
        <div class="flex items-center gap-3"><div class="w-12 h-12 shrink-0">${LOGO_SVG}</div><div><div class="text-sm font-bold text-slate-900">${esc(s.nombreCompleto)}</div><div class="text-xs text-slate-500 font-mono">DNI / CODPSAL: ${esc(s.dni)}</div><div class="text-xs text-sky-700">${esc(s.estab_nombre || establishName(s.cod_estab))}</div></div></div>
        <div class="pt-3 border-t border-slate-100 flex items-center justify-between text-xs"><span class="text-slate-600">Instalación en celular</span><button type="button" onclick="installPwa()" class="min-h-[38px] px-3 rounded-xl bg-slate-900 text-white text-xs font-semibold">Instalar App</button></div>
      </div>
      <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-2.5">
        <div class="text-xs font-bold text-slate-900">Instalación Android / iPhone</div>
        <div class="rounded-xl bg-sky-50 border border-sky-200 px-3 py-2 text-[11px] text-sky-950 leading-relaxed">
          <strong>Android (Chrome):</strong> menú ⋮ → “Instalar aplicación” o “Agregar a pantalla de inicio”. La app queda como WebAPK con icono propio.<br />
          <strong>iPhone (Safari):</strong> Compartir → “Agregar a pantalla de inicio”.
        </div>
        ${APK_URL
          ? `<a href="${APK_URL}" download class="block text-center w-full min-h-[44px] leading-[44px] rounded-xl bg-emerald-700 text-white text-xs font-bold">Descargar APK Android</a>`
          : '<div class="text-[10px] text-slate-500">APK opcional: Estadística puede publicar <code class="font-mono">public/planificahis.apk</code> y el botón de descarga aparecerá automáticamente.</div>'}
      </div>
      <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-2.5">
        <div class="text-xs font-bold text-slate-900">Establecimiento activo (${TOTAL_ESTABLECIMIENTOS} IPRESS)</div>
        <select onchange="cambiarEstablecimiento(this.value)" ${state.changingEstab ? 'disabled' : ''} class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-xs bg-white">${optionsEstablecimientos(s.cod_estab || '000005481')}</select>
        <div class="flex items-center justify-between text-[11px] text-slate-600"><span>${state.offlinePending > 0 ? state.offlinePending + ' captación(es) cifradas pendientes' : 'Cola offline vacía'}</span><button type="button" onclick="sincronizarOffline()" ${state.syncingOffline ? 'disabled' : ''} class="px-2.5 py-1.5 rounded-lg bg-slate-900 text-white font-semibold">${state.syncingOffline ? 'Sincronizando...' : 'Sincronizar'}</button></div>
      </div>
      <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-2.5">
        <div class="text-xs font-bold text-slate-900">Últimos Registros de Actividad (${state.auditLogs.length})</div>
        <div class="divide-y divide-slate-100 max-h-64 overflow-y-auto">${state.auditLogs.slice(0, 8).map(function (log) { return '<div class="py-2 text-xs"><div class="flex items-center justify-between font-mono text-[11px] text-slate-500"><span>' + esc(log.accion) + '</span><span>' + esc(log.fecha_hora) + '</span></div><p class="text-slate-700 mt-0.5">' + esc(log.detalle) + '</p></div>'; }).join('') || '<div class="py-2 text-xs text-slate-500">Sin actividad reciente.</div>'}</div>
      </div>
      <button type="button" onclick="logout()" class="w-full min-h-[48px] rounded-2xl border border-red-200 bg-red-50 text-red-700 text-sm font-semibold">Cerrar Sesión</button>`;
    }

    // ---------------------------------------------------------------------
    // Handlers de autenticación
    // ---------------------------------------------------------------------
    function setAuthTab(tab) {
      state.authTab = tab;
      state.feedback = null;
      render();
    }
    function setTab(tab) {
      state.activeTab = tab;
      state.feedback = null;
      render();
    }
    function backToCredentials() {
      state.authStep = 'CREDENTIALS';
      state.demoCode = '';
      state.feedback = null;
      render();
    }
    function useDemoCode() {
      const input = document.getElementById('totp-input');
      if (input) input.value = state.demoCode;
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
        if (data.session && data.session.token) {
          await enterApp(data.session);
          return;
        }
        state.challengeId = data.challengeId;
        state.pendingUser = data.userPreview || { dni: data.dni, nombreCompleto: data.nombreCompleto, estab_nombre: data.estab_nombre };
        state.demoCode = (data.userPreview && (data.userPreview.demoCurrentCode || data.userPreview.currentTotpCode)) || data.demoCurrentCode || '';
        state.authStep = 'VERIFY_2FA';
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
        if (data.session && data.session.token) {
          await enterApp(data.session);
          return;
        }
        state.challengeId = data.challengeId;
        state.pendingUser = data.userPreview || { dni: data.dni, nombreCompleto: data.nombreCompleto, estab_nombre: data.estab_nombre };
        state.demoCode = (data.userPreview && (data.userPreview.demoCurrentCode || data.userPreview.currentTotpCode)) || data.demoCurrentCode || '';
        state.authStep = 'VERIFY_2FA';
        render();
      } catch (error) {
        showFeedback('error', error.message);
      }
    }

    async function handleVerify2FA(event) {
      event.preventDefault();
      state.feedback = null;
      const code = document.getElementById('totp-input').value.replace(/\D/g, '');
      try {
        const data = await apiPost('verify_2fa', { challengeId: state.challengeId, code: code });
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

    // Restaurar sesión guardada y validar contra la API.
    (async function boot() {
      if (isIos() && !isStandalone()) state.iosBanner = true;
      state.offlinePending = readQueueRaw().length;
      if (state.token) {
        try {
          const saved = sessionStorage.getItem(SESSION_KEY);
          state.session = saved ? JSON.parse(saved) : null;
          await loadOverview();
          startOfflineSync();
        } catch (e) {
          clearSession();
        }
      }
      render();
      updatePendingIndicators();
    })();
  </script>
</body>
</html>
