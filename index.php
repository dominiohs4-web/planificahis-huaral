<?php
/**
 * index.php — Interfaz móvil oficial (Apache + PHP + MariaDB / XAMPP)
 * Hospital San Juan Bautista Huaral — Red de Salud Huaral-Chancay
 *
 * Esta variante consume api.php con Bearer Token emitido tras 2FA TOTP.
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
  <meta name="description" content="Captación y seguimiento de Planificación Familiar del Hospital San Juan Bautista Huaral y la Red Huaral-Chancay. Seguridad 2FA, AES-256-GCM y auditoría SHA-256." />
  <meta name="theme-color" content="#0f172a" />
  <meta name="mobile-web-app-capable" content="yes" />
  <meta name="apple-mobile-web-app-capable" content="yes" />
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
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
      booted: false
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
              <strong>Acceso clínico protegido:</strong> DNI de la obstetra, contraseña y segundo factor TOTP.
              El código 2FA se muestra aquí solo cuando <code class="font-mono">APP_DEMO_MODE=1</code>.
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
              <p class="text-xs text-slate-600">Cada obstetra crea su propio acceso vinculado a su DNI, correo y establecimiento. El sistema le asignará su secreto TOTP individual.</p>
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

    function renderCaptar() {
      const lookup = state.hisLookup;
      const draft = state.formDraft || {};
      const ups = lookup && lookup.upsPlanificacionFamiliar;
      const alerta99208 = lookup && lookup.atencion99208;
      const paseDirecto = Boolean(ups && ups.paseDirectoHabilitado);
      return `
        <div class="grid grid-cols-3 gap-2">
          <div class="p-3 rounded-2xl bg-white border border-slate-200"><div class="text-[10px] text-slate-500 leading-tight">Sin Método Captadas</div><div class="text-lg font-bold text-amber-700 font-mono mt-0.5">${Number(state.stats.insatisfechasSinMetodo || 0)}</div></div>
          <div class="p-3 rounded-2xl bg-white border border-slate-200"><div class="text-[10px] text-slate-500 leading-tight">Citas Ampolla Hoy/Mañana</div><div class="text-lg font-bold text-sky-700 font-mono mt-0.5">${Number(state.stats.citasAmpollaHoyManana || 0)}</div></div>
          <div class="p-3 rounded-2xl ${Number(state.stats.atenciones99208 || 0) > 0 ? 'bg-red-50 border-red-300' : 'bg-white border-slate-200'} border"><div class="text-[10px] text-slate-500 leading-tight">Atenciones 99208</div><div class="text-lg font-bold text-red-700 font-mono mt-0.5">${Number(state.stats.atenciones99208 || 0)}</div></div>
        </div>

        <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
          <div class="text-xs font-bold text-slate-900">1. Validar DNI de la Paciente</div>
          <div class="rounded-xl bg-sky-50 border border-sky-200 px-3 py-2 text-[11px] text-sky-950">
            <div class="font-semibold">Búsqueda restringida a su establecimiento activo:</div>
            <div class="mt-0.5">${esc(state.session.estab_nombre || establishName(state.session.cod_estab))}</div>
            <div class="text-sky-700 mt-0.5">UPS Planificación Familiar (COD_SERVSA 302304 / DX 99208, 90782, Z304, Z301, Z300)</div>
          </div>
          <div class="flex gap-2">
            <input id="f-dni" type="text" inputmode="numeric" maxlength="15" value="${esc(draft.dni || '')}" placeholder="Ingrese DNI (8 dígitos)" class="flex-1 min-h-[46px] px-3.5 rounded-xl border border-slate-300 text-sm font-mono" />
            <button type="button" onclick="validarDni()" class="min-h-[46px] px-4 rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-xs font-semibold shrink-0">Validar</button>
          </div>

          ${lookup ? `<div class="p-3.5 rounded-xl border text-xs space-y-1 ${lookup.hasActiveMethodInHis ? 'bg-emerald-50 border-emerald-300 text-emerald-950' : 'bg-amber-50 border-amber-300 text-amber-950'}">
            ${lookup.hasActiveMethodInHis
              ? '<div class="font-bold">Paciente ya recibe método activo en el Hospital</div><p>' + esc((lookup.hisRecord && (lookup.hisRecord.Apellido_p + ' ' + lookup.hisRecord.Apellido_m + ', ' + (lookup.hisRecord.Dnombres || lookup.hisRecord.Pnombre))) || '') + ' (' + esc((lookup.hisRecord && lookup.hisRecord.COD_ESTAB) || '') + ').</p>'
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

        ${ups ? `<div class="p-4 rounded-2xl border-2 space-y-2.5 ${paseDirecto ? 'bg-emerald-50 border-emerald-400 text-emerald-950' : 'bg-amber-50 border-amber-400 text-amber-950'}">
          <div class="flex items-center justify-between gap-2">
            <div class="text-xs font-extrabold">UPS Planificación Familiar · ${esc(ups.establecimiento.nombre)}</div>
            <span class="px-2 py-1 rounded-lg text-[10px] font-extrabold shrink-0 ${paseDirecto ? 'bg-emerald-700 text-white' : 'bg-amber-600 text-white'}">${paseDirecto ? 'CASO A' : 'CASO B'}</span>
          </div>
          <p class="text-xs leading-relaxed font-semibold">${esc(ups.mensaje)}</p>
          ${paseDirecto ? `<div class="space-y-1">${(ups.atenciones || []).filter(function (a) { return a.es_planificacion_familiar; }).slice(0, 3).map(function (a) {
            return '<div class="rounded-lg bg-white/70 border border-emerald-200 px-2.5 py-1.5 text-[11px] font-mono">' + esc(a.fecha) + ' · Cód. ' + esc(a.dx || a.cod_servsa) + ' · Dosis ' + esc(a.id_dosis || '—') + '</div>';
          }).join('')}</div>
          <div class="rounded-xl bg-white/70 border border-emerald-200 px-3 py-2 text-[11px] text-emerald-900">
            <strong>Pase directo habilitado.</strong> No necesita completar el formulario: solo confirme el pase/control. El registro se completará automáticamente desde el HIS.
          </div>
          <button type="button" onclick="confirmarPaseUps()" class="w-full min-h-[48px] rounded-xl bg-emerald-700 hover:bg-emerald-800 text-white text-sm font-bold">Confirmar Pase Directo en UPS</button>` : `<div class="rounded-xl bg-white/70 border border-amber-200 px-3 py-2 text-[11px] text-amber-900">
            <strong>Formulario precargado desde HIS (Caso B).</strong> Nombres, apellidos y edad ya vienen del HIS. Complete celular, dirección, sector y guarde para registrar la captación en esta IPRESS.
          </div>`}
        </div>` : ''}

        ${state.feedback ? `<div class="p-3.5 rounded-xl border text-xs ${state.feedback.type === 'error' ? 'bg-red-50 border-red-200 text-red-800' : 'bg-emerald-50 border-emerald-200 text-emerald-900'}">${esc(state.feedback.text)}</div>` : ''}

        ${paseDirecto ? '' : `<form onsubmit="guardarPaciente(event)" class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3.5">
          <div class="text-xs font-bold text-slate-900">2. Datos de la Paciente a Captar</div>
          ${ups && ups.requiereFormularioCompleto ? '<div class="rounded-xl bg-sky-50 border border-sky-200 px-3 py-2 text-[11px] text-sky-950">Datos personales precargados desde <code class="font-mono">his_dl</code>. Verifique y complete los campos de contacto.</div>' : ''}
          <div class="grid grid-cols-2 gap-2.5">
            <div><label class="block text-xs text-slate-700 mb-1">Apellido Paterno</label><input id="f-app" type="text" required value="${esc(draft.apellido_paterno || '')}" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm" /></div>
            <div><label class="block text-xs text-slate-700 mb-1">Apellido Materno</label><input id="f-apm" type="text" required value="${esc(draft.apellido_materno || '')}" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm" /></div>
          </div>
          <div class="grid grid-cols-3 gap-2.5">
            <div class="col-span-2"><label class="block text-xs text-slate-700 mb-1">Nombres</label><input id="f-nom" type="text" required value="${esc(draft.nombres || '')}" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm" /></div>
            <div><label class="block text-xs text-slate-700 mb-1">Edad</label><input id="f-edad" type="number" min="10" max="65" required value="${esc(draft.edad || '')}" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm font-mono" /></div>
          </div>
          <div class="grid grid-cols-2 gap-2.5">
            <div><label class="block text-xs text-slate-700 mb-1">Celular</label><input id="f-cel" type="tel" value="${esc(draft.celular || '')}" placeholder="987654321" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm font-mono" /></div>
            <div><label class="block text-xs text-slate-700 mb-1">Correo</label><input id="f-cor" type="email" value="${esc(draft.correo || '')}" placeholder="Opcional" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm" /></div>
          </div>
          <div>
            <label class="block text-xs text-slate-700 mb-1">Distrito (Provincia de Huaral)</label>
            <select id="f-dist" onchange="onChangeDistrito(this.value)" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm bg-white">${optionsDistritos(draft.distrito || state.distritoSelect)}</select>
          </div>
          <div id="otros-box" class="${(draft.distrito || state.distritoSelect) === 'OTROS' ? '' : 'hidden'}">
            <label class="block text-xs font-semibold text-amber-800 mb-1">Especifique otro Distrito / Procedencia</label>
            <input id="f-dist-otros" type="text" value="${esc(draft.distritoOtros || state.distritoOtros || '')}" placeholder="Ej. Huacho, Lima..." class="w-full min-h-[44px] px-3 rounded-xl border border-amber-400 bg-amber-50/40 text-sm" />
          </div>
          <div><label class="block text-xs text-slate-700 mb-1">Dirección Domiciliaria</label><input id="f-dir" type="text" required value="${esc(draft.direccion || '')}" placeholder="Calle / Av. / Urb. / Referencia" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm" /></div>
          <div class="grid grid-cols-2 gap-2.5">
            <div><label class="block text-xs text-slate-700 mb-1">Sector</label><input id="f-sec" type="text" required value="${esc(draft.sector || '')}" placeholder="Ej. Sector 28" class="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm" /></div>
            <div><label class="block text-xs text-slate-700 mb-1">Estado</label><select id="f-est" class="w-full min-h-[44px] px-2 rounded-xl border border-slate-300 text-xs bg-white">${Object.keys(ESTADOS).map(function (e) { return '<option value="' + e + '"' + ((draft.estado_paciente || 'INSATISFECHA_SIN_METODO') === e ? ' selected' : '') + '>' + esc(ESTADOS[e]) + '</option>'; }).join('')}</select></div>
          </div>
          <button type="submit" class="w-full min-h-[48px] rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-sm font-semibold">Guardar Paciente</button>
        </form>`}`;
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

    function renderAgenda() {
      return `<div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
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

    function renderSeguridad() {
      const m = state.securityMetrics;
      const chain = state.chainVerification;
      return `
        <div class="grid grid-cols-2 gap-2.5">
          <div class="p-3.5 rounded-2xl bg-white border border-slate-200"><div class="text-[10px] text-slate-500">SQLi / XSS bloqueados</div><div class="text-xl font-bold font-mono">${Number(m.sqliBlockedCount || 0) + Number(m.xssBlockedCount || 0)}</div><div class="text-[10px] text-teal-700">${Number(m.sqliBlockedCount || 0)} SQLi · ${Number(m.xssBlockedCount || 0)} XSS</div></div>
          <div class="p-3.5 rounded-2xl bg-white border border-slate-200"><div class="text-[10px] text-slate-500">Registros cifrados AES-256</div><div class="text-xl font-bold font-mono">${Number(m.encryptedRecordsCount || 0)}</div><div class="text-[10px] text-teal-700">PII protegida en reposo</div></div>
          <div class="p-3.5 rounded-2xl bg-white border border-slate-200"><div class="text-[10px] text-slate-500">2FA TOTP verificados</div><div class="text-xl font-bold font-mono">${Number(m.totpVerifiedCount || 0)}</div><div class="text-[10px] text-slate-600">RFC 6238 · 30 s</div></div>
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

    async function handleLogin(event) {
      event.preventDefault();
      state.feedback = null;
      const dni = document.getElementById('login-dni').value.trim();
      const password = document.getElementById('login-pass').value;
      try {
        const data = await apiPost('login', { dni: dni, password: password });
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
        state.token = data.session.token;
        state.session = data.session;
        persistSession();
        state.authStep = 'CREDENTIALS';
        state.activeTab = 'CAPTAR';
        state.pendingUser = null;
        state.demoCode = '';
        await loadOverview();
        startOfflineSync();
        render();
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
        state.feedback = { type: 'success', text: 'Establecimiento activo: ' + data.session.estab_nombre + '. Las búsquedas de DNI quedan restringidas a su UPS de Planificación Familiar.' };
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
      const distrito = cap.distrito || his.DESC_DIST || 'HUARAL';
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
        render();
      } catch (error) {
        state.feedback = { type: 'error', text: error.message };
        render();
      }
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
        await loadOverview();
        render();
      } catch (error) {
        if (!navigator.onLine) {
          try {
            await queueOfflinePatient(payload);
            state.feedback = { type: 'success', text: 'Sin conexión: la captación quedó guardada CIFRADA y se sincronizará automáticamente.' };
            state.formDraft = null;
            state.hisLookup = null;
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
