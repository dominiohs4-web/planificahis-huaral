import React, { useState } from 'react';
import { ShieldCheck, Lock, KeyRound, Smartphone, AlertTriangle, RefreshCw, UserPlus, X } from 'lucide-react';
import { ESTABLECIMIENTOS_POR_DISTRITO, TOTAL_ESTABLECIMIENTOS } from '../data/establecimientos';

interface Auth2FAModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccessSession: (session: {
    token: string;
    dni: string;
    nombreCompleto: string;
    rol: string;
    nivelid: number;
    cod_estab: string;
    estab_nombre: string;
    verified2FA: boolean;
    platform: string;
  }) => void;
}

export const Auth2FAModal: React.FC<Auth2FAModalProps> = ({ isOpen, onClose, onSuccessSession }) => {
  const [authMode, setAuthMode] = useState<'LOGIN' | 'REGISTER_OBSTETRA'>('LOGIN');
  const [step, setStep] = useState<'CREDENTIALS' | 'TOTP_2FA'>('CREDENTIALS');
  const [dni, setDni] = useState('41829304');
  const [password, setPassword] = useState('Obstetra2026!');
  const [challengeId, setChallengeId] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [loading, setLoading] = useState(false);

  // Registration form state for new Obstetricians in Hospital Huaral
  const [regDni, setRegDni] = useState('');
  const [regNombre, setRegNombre] = useState('');
  const [regApPaterno, setRegApPaterno] = useState('');
  const [regApMaterno, setRegApMaterno] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regCelular, setRegCelular] = useState('');
  const [regEstab, setRegEstab] = useState('000005481');
  const [regPassword, setRegPassword] = useState('');

  const [userPreview, setUserPreview] = useState<{
    dni: string;
    nombreCompleto: string;
    email: string;
    celularMasked: string;
    rol: string;
    totpSecret: string;
    currentTotpCode?: string;
    demoCurrentCode?: string;
    remainingSeconds: number;
  } | null>(null);

  if (!isOpen) return null;

  const handleStep1Submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    setLoading(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dni, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || 'Error de autenticación');
      } else {
        setChallengeId(data.challengeId);
        setUserPreview(data.userPreview);
        setTotpCode(
          data.userPreview?.demoCurrentCode ||
            data.userPreview?.currentTotpCode ||
            data.demoCurrentCode ||
            ''
        );
        setStep('TOTP_2FA');
      }
    } catch {
      setErrorMsg('No se pudo conectar con el servidor de autenticación.');
    } finally {
      setLoading(false);
    }
  };

  const handleRegisterObstetra = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    setLoading(true);
    try {
      const res = await fetch('/api/auth/register-obstetra', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          dni: regDni,
          nombre1: regNombre,
          apaterno: regApPaterno,
          amaterno: regApMaterno,
          email: regEmail,
          celular: regCelular,
          cod_estab: regEstab,
          password: regPassword,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || 'No se pudo crear el acceso.');
      } else {
        setChallengeId(data.challengeId);
        setUserPreview(data.userPreview);
        setTotpCode(
          data.userPreview?.demoCurrentCode ||
            data.userPreview?.currentTotpCode ||
            data.demoCurrentCode ||
            ''
        );
        setStep('TOTP_2FA');
      }
    } catch {
      setErrorMsg('Error de red al crear el acceso de obstetra.');
    } finally {
      setLoading(false);
    }
  };

  const handleStep2Verify = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    setLoading(true);
    try {
      const res = await fetch('/api/auth/verify-2fa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challengeId, code: totpCode }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || 'Código 2FA inválido.');
      } else {
        onSuccessSession(data.session);
        onClose();
      }
    } catch {
      setErrorMsg('Error al verificar el código de segundo factor.');
    } finally {
      setLoading(false);
    }
  };

  const selectQuickProfile = (selectedDni: string, defaultPass: string) => {
    setAuthMode('LOGIN');
    setDni(selectedDni);
    setPassword(defaultPass);
    setErrorMsg('');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-slate-950/70 backdrop-blur-xs p-3 sm:p-6">
      <div className="w-full max-w-lg rounded-2xl bg-white border border-slate-200 shadow-2xl overflow-hidden max-h-[92vh] flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 bg-slate-900 text-white flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="w-5 h-5 text-teal-400 shrink-0" />
            <div>
              <h2 className="text-base font-bold tracking-tight">
                Acceso Obstétrico 2FA — Hospital San Juan Bautista Huaral
              </h2>
              <p className="text-xs text-slate-300">
                Vinculado a <code className="font-mono text-teal-300">usuario</code>,{' '}
                <code className="font-mono text-teal-300">mstrpers</code> y{' '}
                <code className="font-mono text-teal-300">codpsal_obstetra</code>
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="min-h-[44px] min-w-[44px] flex items-center justify-center text-slate-400 hover:text-white rounded-lg cursor-pointer"
            aria-label="Cerrar"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 overflow-y-auto space-y-4">
          {step === 'CREDENTIALS' && (
            <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-xl">
              <button
                type="button"
                onClick={() => {
                  setAuthMode('LOGIN');
                  setErrorMsg('');
                }}
                className={`flex-1 min-h-[40px] px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                  authMode === 'LOGIN'
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Iniciar Sesión Obstetra
              </button>
              <button
                type="button"
                onClick={() => {
                  setAuthMode('REGISTER_OBSTETRA');
                  setErrorMsg('');
                }}
                className={`flex-1 min-h-[40px] px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                  authMode === 'REGISTER_OBSTETRA'
                    ? 'bg-white text-teal-800 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Crear Acceso Nueva Obstetra
              </button>
            </div>
          )}

          {errorMsg && (
            <div className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-red-800 text-xs flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
              <span>{errorMsg}</span>
            </div>
          )}

          {step === 'CREDENTIALS' && authMode === 'LOGIN' && (
            <>
              <div>
                <p className="text-xs font-semibold text-slate-600 mb-2">
                  Perfiles del Hospital San Juan Bautista Huaral para prueba rápida:
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <button
                    type="button"
                    onClick={() => selectQuickProfile('41829304', 'Obstetra2026!')}
                    className={`p-2.5 rounded-xl border text-left transition-colors cursor-pointer ${
                      dni === '41829304'
                        ? 'border-teal-600 bg-teal-50/60 text-slate-900'
                        : 'border-slate-200 hover:bg-slate-50 text-slate-700'
                    }`}
                  >
                    <div className="text-xs font-bold">Lic. Obst. Roxana</div>
                    <div className="text-[11px] font-mono text-slate-500">DNI: 41829304</div>
                    <div className="text-[11px] text-teal-700 mt-0.5">Coordinadora (iPhone)</div>
                  </button>
                  <button
                    type="button"
                    onClick={() => selectQuickProfile('44910283', 'Obstetra2026!')}
                    className={`p-2.5 rounded-xl border text-left transition-colors cursor-pointer ${
                      dni === '44910283'
                        ? 'border-teal-600 bg-teal-50/60 text-slate-900'
                        : 'border-slate-200 hover:bg-slate-50 text-slate-700'
                    }`}
                  >
                    <div className="text-xs font-bold">Obst. Carmen</div>
                    <div className="text-[11px] font-mono text-slate-500">DNI: 44910283</div>
                    <div className="text-[11px] text-teal-700 mt-0.5">Captación Campo</div>
                  </button>
                  <button
                    type="button"
                    onClick={() => selectQuickProfile('70192834', 'AdminHIS2026!')}
                    className={`p-2.5 rounded-xl border text-left transition-colors cursor-pointer ${
                      dni === '70192834'
                        ? 'border-teal-600 bg-teal-50/60 text-slate-900'
                        : 'border-slate-200 hover:bg-slate-50 text-slate-700'
                    }`}
                  >
                    <div className="text-xs font-bold">Estadística / Cómputo</div>
                    <div className="text-[11px] font-mono text-slate-500">DNI: 70192834</div>
                    <div className="text-[11px] text-teal-700 mt-0.5">Luis / Ing. Alex</div>
                  </button>
                </div>
              </div>

              <form onSubmit={handleStep1Submit} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                    DNI de la Obstetra (<code className="font-mono">CODPSAL</code>)
                  </label>
                  <input
                    type="text"
                    inputMode="numeric"
                    value={dni}
                    onChange={(e) => setDni(e.target.value)}
                    placeholder="Ej. 41829304"
                    className="w-full min-h-[44px] px-3.5 py-2.5 rounded-xl border border-slate-300 text-sm font-mono focus:outline-none focus:border-teal-600"
                    required
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                    Contraseña Cifrada (Hash Scrypt / PBKDF2)
                  </label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full min-h-[44px] px-3.5 py-2.5 rounded-xl border border-slate-300 text-sm focus:outline-none focus:border-teal-600"
                    required
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full min-h-[48px] rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-sm font-semibold flex items-center justify-center gap-2 transition-colors cursor-pointer"
                >
                  <Lock className="w-4 h-4" />
                  <span>{loading ? 'Verificando credenciales...' : 'Continuar al Paso 2 (Código 2FA)'}</span>
                </button>
              </form>
            </>
          )}

          {step === 'CREDENTIALS' && authMode === 'REGISTER_OBSTETRA' && (
            <form onSubmit={handleRegisterObstetra} className="space-y-3.5">
              <p className="text-xs text-slate-600">
                Cada obstetra registra su propio usuario vinculado a su DNI (<code className="font-mono">codpsal_obstetra</code>) y correo electrónico para que la Coordinación sepa quién capta a cada paciente en campo:
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    DNI Obstetra (8 dígitos)
                  </label>
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={8}
                    value={regDni}
                    onChange={(e) => setRegDni(e.target.value.replace(/\D/g, ''))}
                    required
                    placeholder="Ej. 43819205"
                    className="w-full min-h-[44px] px-3 py-2 rounded-xl border border-slate-300 text-sm font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Nombres
                  </label>
                  <input
                    type="text"
                    value={regNombre}
                    onChange={(e) => setRegNombre(e.target.value)}
                    required
                    placeholder="Ej. PATRICIA"
                    className="w-full min-h-[44px] px-3 py-2 rounded-xl border border-slate-300 text-sm"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Apellido Paterno
                  </label>
                  <input
                    type="text"
                    value={regApPaterno}
                    onChange={(e) => setRegApPaterno(e.target.value)}
                    required
                    className="w-full min-h-[44px] px-3 py-2 rounded-xl border border-slate-300 text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Apellido Materno
                  </label>
                  <input
                    type="text"
                    value={regApMaterno}
                    onChange={(e) => setRegApMaterno(e.target.value)}
                    required
                    className="w-full min-h-[44px] px-3 py-2 rounded-xl border border-slate-300 text-sm"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Correo Electrónico
                  </label>
                  <input
                    type="email"
                    value={regEmail}
                    onChange={(e) => setRegEmail(e.target.value)}
                    required
                    placeholder="obstetra@hospitalhuaral.gob.pe"
                    className="w-full min-h-[44px] px-3 py-2 rounded-xl border border-slate-300 text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Celular
                  </label>
                  <input
                    type="tel"
                    inputMode="numeric"
                    maxLength={9}
                    value={regCelular}
                    onChange={(e) => setRegCelular(e.target.value.replace(/\D/g, ''))}
                    placeholder="987654321"
                    className="w-full min-h-[44px] px-3 py-2 rounded-xl border border-slate-300 text-sm font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Establecimiento ({TOTAL_ESTABLECIMIENTOS} IPRESS Red Huaral-Chancay)
                  </label>
                  <select
                    value={regEstab}
                    onChange={(e) => setRegEstab(e.target.value)}
                    className="w-full min-h-[44px] px-3 py-2 rounded-xl border border-slate-300 text-xs bg-white"
                  >
                    {Object.entries(ESTABLECIMIENTOS_POR_DISTRITO).map(([distrito, lista]) => (
                      <optgroup key={distrito} label={`${distrito} (${lista.length})`}>
                        {lista.map((est) => (
                          <option key={est.COD_ESTAB} value={est.COD_ESTAB}>
                            {est.DESC_ESTAB} · {est.CATEGORIA}
                          </option>
                        ))}
                      </optgroup>
                    ))}
                  </select>
                  <p className="text-[10px] text-slate-500 mt-1">
                    Las búsquedas de DNI se restringen a la UPS de Planificación Familiar de esta
                    IPRESS y podrá cambiarla en la barra superior.
                  </p>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Crear Contraseña Segura
                  </label>
                  <input
                    type="password"
                    value={regPassword}
                    onChange={(e) => setRegPassword(e.target.value)}
                    required
                    minLength={8}
                    placeholder="Mínimo 8 caracteres"
                    className="w-full min-h-[44px] px-3 py-2 rounded-xl border border-slate-300 text-sm"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full min-h-[48px] rounded-xl bg-teal-700 hover:bg-teal-800 text-white text-sm font-semibold flex items-center justify-center gap-2 transition-colors cursor-pointer"
              >
                <UserPlus className="w-4 h-4" />
                <span>{loading ? 'Creando acceso...' : 'Registrar Obstetra y Activar 2FA'}</span>
              </button>
            </form>
          )}

          {step === 'TOTP_2FA' && (
            <form onSubmit={handleStep2Verify} className="space-y-4">
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                <div className="text-xs font-semibold text-slate-900">
                  {userPreview?.nombreCompleto}
                </div>
                <div className="text-xs text-slate-500 mt-0.5">
                  {userPreview?.rol} · Celular registrado: {userPreview?.celularMasked}
                </div>
              </div>

              <div className="p-4 rounded-xl bg-teal-950 text-white border border-teal-800">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Smartphone className="w-4 h-4 text-teal-400" />
                    <span className="text-xs font-semibold text-teal-200">
                      Token 2FA Sincronizado (iPhone / Android Authenticator)
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-teal-300">
                    Expira en {userPreview?.remainingSeconds ?? 30}s
                  </span>
                </div>
                <div className="mt-2 flex items-center justify-between">
                  <div>
                    <div className="text-2xl font-bold font-mono tracking-widest text-white tabular-nums">
                      {userPreview?.currentTotpCode || userPreview?.demoCurrentCode || '••••••'}
                    </div>
                    <div className="text-[11px] text-teal-300 font-mono mt-0.5">
                      Secreto: {userPreview?.totpSecret}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() =>
                      setTotpCode(
                        userPreview?.currentTotpCode || userPreview?.demoCurrentCode || ''
                      )
                    }
                    className="min-h-[40px] px-3 py-1.5 rounded-lg bg-teal-700 hover:bg-teal-600 text-xs font-semibold text-white flex items-center gap-1.5 cursor-pointer"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Autocompletar</span>
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                  Ingrese el código de verificación 2FA de 6 dígitos
                </label>
                <input
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                  placeholder="000000"
                  className="w-full min-h-[48px] px-4 py-2.5 rounded-xl border border-slate-300 text-center text-xl font-bold font-mono tracking-widest focus:outline-none focus:border-teal-600"
                  required
                />
              </div>

              <div className="flex items-center gap-3 pt-1">
                <button
                  type="button"
                  onClick={() => setStep('CREDENTIALS')}
                  className="min-h-[48px] px-4 rounded-xl border border-slate-300 text-slate-700 text-xs font-semibold hover:bg-slate-50 cursor-pointer"
                >
                  Atrás
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="flex-1 min-h-[48px] rounded-xl bg-teal-700 hover:bg-teal-800 text-white text-sm font-semibold flex items-center justify-center gap-2 transition-colors cursor-pointer"
                >
                  <KeyRound className="w-4 h-4" />
                  <span>{loading ? 'Validando 2FA...' : 'Verificar 2FA y Entrar'}</span>
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};
