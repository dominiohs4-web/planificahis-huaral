import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  Users,
  UserPlus,
  CalendarClock,
  UserCheck,
  Search,
  CheckCircle2,
  AlertCircle,
  Clock,
  Phone,
  MapPin,
  Lock,
  KeyRound,
  Download,
  LogOut,
  ChevronRight,
  RefreshCw,
  ShieldCheck,
  CloudOff,
  Wifi,
} from 'lucide-react';
import { HospitalHuaralLogo } from './components/HospitalHuaralLogo';
import { PWAInstallButton, OfflineBanner } from './components/PWAInstallButton';
import { IOSInstallBanner } from './components/IOSInstallBanner';
import { AuditLogItem, SecurityAndAuditPanel } from './components/SecurityAndAuditPanel';
import {
  ESTABLECIMIENTOS_POR_DISTRITO,
  TOTAL_ESTABLECIMIENTOS,
} from './data/establecimientos';
import {
  getOfflineQueueCount,
  queueOfflinePatient,
  syncOfflineQueue,
  offlineQueueSupported,
} from './lib/offlineQueue';

interface HisDiagnostico {
  ID: string;
  ID_CITA: string;
  num: number;
  DX: string;
  TDX: string;
  LDX: string;
  Alerta: string | null;
  fecha_reg: string;
  DESC_ENF?: string;
  METODO_CORTO?: string;
  CICLO_DIAS?: number;
  FECHA_PROXIMA_CITA?: string | null;
}

interface HisRecord {
  ID: string;
  id_cita: string;
  COD_ESTAB: string;
  DESC_ESTAB?: string;
  DNI: string;
  Apellido_p: string;
  Apellido_m: string;
  Pnombre: string;
  Dnombres: string;
  EDAD: number;
  SEXO: string;
  UBIGEO: string;
  FICHAFAM: string;
  HCLFAM: string;
  hmb: number | null;
  Fecha_Ultima_Regla: string | null;
  PESO: string;
  TALLA: string;
  IMC: string;
  FECHA_NAC: string;
  condicion_gestante: string | null;
  gruporiesgo_desc: string | null;
  fecha_reg: string;
  diagnosticos?: HisDiagnostico[];
}

interface PacienteSinMetodoItem {
  id: number;
  dni: string;
  apellido_paterno: string;
  apellido_materno: string;
  nombres: string;
  edad: number;
  celular: string;
  correo: string;
  distrito: string;
  direccion: string;
  sector: string;
  estado_paciente:
    | 'INSATISFECHA_SIN_METODO'
    | 'CAPTADA_CON_METODO'
    | 'SEGUIMIENTO_DOMICILIARIO'
    | 'CONSEJERIA_REALIZADA'
    | 'RECHAZA_METODO';
  codpsal_obstetra: string;
  nombre_obstetra: string;
  cod_estab?: string;
  atencion_99208?: boolean;
  fecha_registro: string;
  his_vinculado: boolean;
  his_ultimo_control: HisRecord | null;
  his_diagnosticos: HisDiagnostico[];
  encrypted_raw?: {
    celular: string;
    correo: string;
    direccion: string;
  };
}

interface AgendaAmpollaItem {
  id_his: string;
  dni: string;
  paciente_nombre: string;
  edad: number;
  historia_clinica: string;
  ficha_familiar: string;
  establecimiento: string;
  codigo_his: string;
  metodo_descripcion: string;
  dosis_nro: string;
  fecha_ultima_aplicacion: string;
  ciclo_dias: number;
  fecha_proxima_cita: string | null;
  estado_cita: 'TOCA_HOY' | 'TOCA_MANANA' | 'VENCIDA_ABANDONO' | 'VIGENTE' | 'SIN_METODO_EN_HIS';
  celular_contacto: string;
  sector: string;
  alerta_his: string | null;
}

interface ProduccionObstetraItem {
  codpsal: string;
  nombre: string;
  establecimiento: string;
  totalCaptadas: number;
  insatisfechasCaptadas: number;
  conMetodoLogrado: number;
}

interface SessionInfo {
  token: string;
  dni: string;
  nombreCompleto: string;
  rol: string;
  nivelid?: number;
  cod_estab: string;
  estab_nombre: string;
  verified2FA: boolean;
  platform?: string;
}

interface Atencion99208Item {
  establecimiento: string;
  cod_estab: string;
  fecha: string;
  fecha_iso: string;
  profesional: string;
  dx: string;
  tdx: string;
  ldx: string;
}

interface UpsAtencionItem {
  id_his: string;
  fecha: string;
  cod_servsa: string;
  dx: string;
  profesional: string;
  id_dosis: string;
  alerta: string;
}

interface LookupResult {
  foundInHis: boolean;
  foundInEstablecimiento?: boolean;
  hasActiveMethodInHis: boolean;
  alreadyInPacientesSinMetodo: boolean;
  hisRecord: (HisRecord & { DESC_DIST?: string; DESC_ESTAB?: string }) | null;
  hisDetails: HisDiagnostico[];
  existingCaptacion?: PacienteSinMetodoItem | null;
  establecimiento?: {
    codigo: string;
    nombre: string;
    categoria?: string;
    distrito?: string;
  };
  atencion99208?: {
    tieneCodigo99208: boolean;
    mensajeOficial99208: string;
    historial99208: Atencion99208Item[];
  };
  upsPlanificacionFamiliar?: {
    establecimiento: { codigo: string; nombre: string };
    codigosUps: string[];
    tieneAtencionPrevia: boolean;
    caso: 'A' | 'B';
    mensaje: string;
    atenciones: UpsAtencionItem[];
  };
}

const ESTADO_LABELS: Record<PacienteSinMetodoItem['estado_paciente'], string> = {
  INSATISFECHA_SIN_METODO: 'Insatisfecha (Sin método)',
  SEGUIMIENTO_DOMICILIARIO: 'En seguimiento / Llamar',
  CONSEJERIA_REALIZADA: 'Consejería realizada',
  CAPTADA_CON_METODO: 'Satisfecha (Con método)',
  RECHAZA_METODO: 'Rechaza método',
};

export default function App() {
  // Authentication state — starts unauthenticated so the Login/Register screen is the very first view
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [authTab, setAuthTab] = useState<'LOGIN' | 'REGISTER'>('LOGIN');
  const [authStep, setAuthStep] = useState<'CREDENTIALS' | 'VERIFY_2FA'>('CREDENTIALS');
  const [loginDni, setLoginDni] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [challengeId, setChallengeId] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [demoCodeHint, setDemoCodeHint] = useState('');
  const [authError, setAuthError] = useState('');
  const [authLoading, setAuthLoading] = useState(false);

  // Registration state for new Obstetrician
  const [regDni, setRegDni] = useState('');
  const [regNombre, setRegNombre] = useState('');
  const [regApPaterno, setRegApPaterno] = useState('');
  const [regApMaterno, setRegApMaterno] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regCelular, setRegCelular] = useState('');
  const [regEstab, setRegEstab] = useState('000005481');
  const [regPassword, setRegPassword] = useState('');

  // Logged-in session state
  const [sessionToken, setSessionToken] = useState<string>('');
  const [sessionInfo, setSessionInfo] = useState<SessionInfo | null>(null);

  // Main Mobile App Navigation Tabs
  const [activeTab, setActiveTab] = useState<'CAPTAR' | 'PACIENTES' | 'AGENDA' | 'SEGURIDAD' | 'PERFIL'>('CAPTAR');

  // App Data
  const [loading, setLoading] = useState(false);
  const [pacientes, setPacientes] = useState<PacienteSinMetodoItem[]>([]);
  const [agendaAmpollas, setAgendaAmpollas] = useState<AgendaAmpollaItem[]>([]);
  const [produccionObstetras, setProduccionObstetras] = useState<ProduccionObstetraItem[]>([]);
  const [distritos, setDistritos] = useState<Array<{ UBIGEO: string; DESC_DIST: string }>>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [securityMetrics, setSecurityMetrics] = useState({
    sqliBlockedCount: 0,
    xssBlockedCount: 0,
    totpVerifiedCount: 0,
    encryptedRecordsCount: 0,
    failedLoginsBlocked: 0,
    auditLogCount: 0,
  });
  const [offlinePending, setOfflinePending] = useState(0);
  const [syncingOffline, setSyncingOffline] = useState(false);
  const [changingEstab, setChangingEstab] = useState(false);
  const [stats, setStats] = useState({
    totalCaptadas: 0,
    insatisfechasSinMetodo: 0,
    captadasConMetodo: 0,
    seguimientoDomiciliario: 0,
    citasAmpollaHoyManana: 0,
    alertasHisPorCaptar: 0,
    atenciones99208: 0,
  });

  // Search & Filter states
  const [searchQuery, setSearchQuery] = useState('');
  const [estadoFilter, setEstadoFilter] = useState<string>('ALL');
  const [selectedPaciente, setSelectedPaciente] = useState<PacienteSinMetodoItem | null>(null);
  const [agendaFilter, setAgendaFilter] = useState<'ALL' | 'TOCA_HOY_MANANA' | 'VENCIDA_ABANDONO'>('ALL');

  // Patient Capture Form
  const [formDni, setFormDni] = useState('');
  const [formApPaterno, setFormApPaterno] = useState('');
  const [formApMaterno, setFormApMaterno] = useState('');
  const [formNombres, setFormNombres] = useState('');
  const [formEdad, setFormEdad] = useState('');
  const [formCelular, setFormCelular] = useState('');
  const [formCorreo, setFormCorreo] = useState('');
  const [formDistritoSelect, setFormDistritoSelect] = useState('HUARAL');
  const [formDistritoOtros, setFormDistritoOtros] = useState('');
  const [formDireccion, setFormDireccion] = useState('');
  const [formSector, setFormSector] = useState('');
  const [formEstado, setFormEstado] = useState<PacienteSinMetodoItem['estado_paciente']>('INSATISFECHA_SIN_METODO');

  const [hisLookupResult, setHisLookupResult] = useState<LookupResult | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [formFeedback, setFormFeedback] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [submittingForm, setSubmittingForm] = useState(false);

  const fetchAppData = useCallback(async (tokenToUse: string) => {
    if (!tokenToUse) return;
    setLoading(true);
    try {
      const [overviewRes, auditRes] = await Promise.all([
        fetch('/api/overview', {
          headers: { Authorization: `Bearer ${tokenToUse}` },
        }),
        fetch('/api/audit/logs', {
          headers: { Authorization: `Bearer ${tokenToUse}` },
        }),
      ]);

      if (overviewRes.ok) {
        const data = await overviewRes.json();
        setPacientes(data.pacientes || []);
        setAgendaAmpollas(data.agendaAmpollas || []);
        setProduccionObstetras(data.produccionObstetras || []);
        setDistritos(data.distritos || []);
        setStats((prev) => ({ ...prev, ...(data.stats || {}) }));
        if (data.securityMetrics) setSecurityMetrics(data.securityMetrics);
        if (data.session) {
          setSessionInfo((prev) =>
            prev
              ? {
                  ...prev,
                  cod_estab: data.session.cod_estab || prev.cod_estab,
                  estab_nombre: data.session.estab_nombre || prev.estab_nombre,
                }
              : prev
          );
        }
      }
      if (auditRes.ok) {
        const auditData = await auditRes.json();
        setAuditLogs(auditData.logs || []);
      }
      setOfflinePending(getOfflineQueueCount());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isAuthenticated && sessionToken) {
      fetchAppData(sessionToken);
    }
  }, [isAuthenticated, sessionToken, fetchAppData]);

  // Sincronización automática de la cola cifrada al recuperar señal.
  useEffect(() => {
    if (!isAuthenticated || !sessionToken || !offlineQueueSupported()) return;
    let cancelled = false;
    const runSync = async () => {
      if (!navigator.onLine || cancelled) return;
      setSyncingOffline(true);
      try {
        const result = await syncOfflineQueue(sessionToken);
        if (cancelled) return;
        setOfflinePending(result.pending);
        if (result.synced > 0) {
          setFormFeedback({
            type: 'success',
            text: `${result.synced} captación(es) offline sincronizada(s) con el servidor del hospital.`,
          });
          await fetchAppData(sessionToken);
        }
      } finally {
        if (!cancelled) setSyncingOffline(false);
      }
    };
    void runSync();
    window.addEventListener('online', runSync);
    const timer = window.setInterval(runSync, 60_000);
    return () => {
      cancelled = true;
      window.removeEventListener('online', runSync);
      window.clearInterval(timer);
    };
  }, [isAuthenticated, sessionToken, fetchAppData]);

  // --- AUTH HANDLERS ---
  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError('');
    setAuthLoading(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dni: loginDni.trim(), password: loginPassword }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAuthError(data.error || 'DNI o contraseña incorrectos.');
      } else {
        setChallengeId(data.challengeId);
        setDemoCodeHint(data.userPreview?.demoCurrentCode || '');
        setTotpCode(data.userPreview?.demoCurrentCode || '');
        setAuthStep('VERIFY_2FA');
      }
    } catch {
      setAuthError('Error de conexión con el servidor.');
    } finally {
      setAuthLoading(false);
    }
  };

  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError('');
    setAuthLoading(true);
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
        setAuthError(data.error || 'No se pudo completar el registro.');
      } else {
        setChallengeId(data.challengeId);
        setDemoCodeHint(data.userPreview?.demoCurrentCode || '');
        setTotpCode(data.userPreview?.demoCurrentCode || '');
        setAuthStep('VERIFY_2FA');
      }
    } catch {
      setAuthError('Error al registrar obstetra.');
    } finally {
      setAuthLoading(false);
    }
  };

  const handleVerify2FA = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError('');
    setAuthLoading(true);
    try {
      const res = await fetch('/api/auth/verify-2fa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challengeId, code: totpCode }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAuthError(data.error || 'Código de verificación incorrecto.');
      } else {
        setSessionToken(data.session.token);
        setSessionInfo(data.session);
        setIsAuthenticated(true);
      }
    } catch {
      setAuthError('Error al verificar el código 2FA.');
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      if (sessionToken) {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: { Authorization: `Bearer ${sessionToken}` },
        });
      }
    } catch {
      // La sesión local se cierra incluso si no hay conexión.
    }
    setIsAuthenticated(false);
    setSessionToken('');
    setSessionInfo(null);
    setAuthStep('CREDENTIALS');
    setTotpCode('');
    setHisLookupResult(null);
    setFormFeedback(null);
  };

  const handleChangeEstablecimiento = async (codEstab: string) => {
    if (!sessionToken || !codEstab || codEstab === sessionInfo?.cod_estab) return;
    setChangingEstab(true);
    setFormFeedback(null);
    try {
      const res = await fetch('/api/auth/session/establecimiento', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({ cod_estab: codEstab }),
      });
      const data = await res.json();
      if (!res.ok) {
        setFormFeedback({ type: 'error', text: data.error || 'No se pudo cambiar el establecimiento.' });
        return;
      }
      setSessionInfo((prev) =>
        prev
          ? { ...prev, cod_estab: data.session.cod_estab, estab_nombre: data.session.estab_nombre }
          : prev
      );
      setHisLookupResult(null);
      setFormFeedback({
        type: 'success',
        text: `Establecimiento activo: ${data.session.estab_nombre}. Las búsquedas de DNI quedan restringidas a su UPS de Planificación Familiar.`,
      });
      await fetchAppData(sessionToken);
    } catch {
      setFormFeedback({ type: 'error', text: 'Error de conexión al cambiar de establecimiento.' });
    } finally {
      setChangingEstab(false);
    }
  };

  // --- CLINICAL HANDLERS ---
  const handleDniLookupInHis = async (dniOverride?: string) => {
    const cleanDni = (dniOverride ?? formDni).replace(/\D/g, '');
    if (cleanDni.length < 8) {
      setFormFeedback({ type: 'error', text: 'Ingrese un DNI válido de 8 dígitos.' });
      return;
    }
    setLookupLoading(true);
    setFormFeedback(null);
    try {
      const res = await fetch(`/api/his/lookup/${cleanDni}`, {
        headers: { Authorization: `Bearer ${sessionToken}` },
      });
      const data = await res.json();
      if (!res.ok) {
        setFormFeedback({ type: 'error', text: data.error || 'Error al validar DNI.' });
        return;
      }
      setHisLookupResult(data);
      setFormDni(cleanDni);

      if (data.hisRecord) {
        setFormApPaterno(data.hisRecord.Apellido_p);
        setFormApMaterno(data.hisRecord.Apellido_m);
        setFormNombres(data.hisRecord.Dnombres || data.hisRecord.Pnombre);
        setFormEdad(String(data.hisRecord.EDAD));
        if (data.hisRecord.DESC_DIST) {
          setFormDistritoSelect(data.hisRecord.DESC_DIST);
        }
      } else if (!data.existingCaptacion) {
        setFormApPaterno('');
        setFormApMaterno('');
        setFormNombres('');
        setFormEdad('');
        setFormCelular('');
        setFormCorreo('');
        setFormDireccion('');
        setFormSector('');
      }

      if (data.existingCaptacion) {
        setFormApPaterno(data.existingCaptacion.apellido_paterno);
        setFormApMaterno(data.existingCaptacion.apellido_materno);
        setFormNombres(data.existingCaptacion.nombres);
        setFormEdad(String(data.existingCaptacion.edad));
        setFormCelular(data.existingCaptacion.celular || '');
        setFormCorreo(data.existingCaptacion.correo || '');
        setFormDireccion(data.existingCaptacion.direccion || '');
        setFormSector(data.existingCaptacion.sector || '');
        setFormEstado(data.existingCaptacion.estado_paciente);
        if (data.existingCaptacion.distrito?.startsWith('OTROS:')) {
          setFormDistritoSelect('OTROS');
          setFormDistritoOtros(data.existingCaptacion.distrito.replace('OTROS:', '').trim());
        } else {
          setFormDistritoSelect(data.existingCaptacion.distrito || 'HUARAL');
        }
      }
    } finally {
      setLookupLoading(false);
    }
  };

  const handleSavePaciente = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sessionInfo) return;
    setSubmittingForm(true);
    setFormFeedback(null);

    const finalDistrito =
      formDistritoSelect === 'OTROS'
        ? `OTROS: ${formDistritoOtros.trim().toUpperCase() || 'FUERA DE HUARAL'}`
        : formDistritoSelect;

    const payload = {
      dni: formDni,
      apellido_paterno: formApPaterno,
      apellido_materno: formApMaterno,
      nombres: formNombres,
      edad: Number(formEdad),
      celular: formCelular,
      correo: formCorreo,
      distrito: finalDistrito,
      direccion: formDireccion,
      sector: formSector,
      estado_paciente: formEstado,
      codpsal_obstetra: sessionInfo.dni,
      atencion_99208: Boolean(hisLookupResult?.atencion99208?.tieneCodigo99208),
      pase_ups: false,
    };

    const saveOffline = async () => {
      try {
        await queueOfflinePatient(payload);
        setOfflinePending(getOfflineQueueCount());
        setFormFeedback({
          type: 'success',
          text: 'Sin conexión: la captación quedó guardada CIFRADA en el dispositivo y se sincronizará automáticamente al recuperar señal.',
        });
      } catch {
        setFormFeedback({
          type: 'error',
          text: 'No hay conexión y no se pudo guardar la cola cifrada en este dispositivo.',
        });
      }
    };

    if (!navigator.onLine) {
      await saveOffline();
      setSubmittingForm(false);
      return;
    }

    try {
      const res = await fetch('/api/pacientes', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setFormFeedback({ type: 'error', text: data.error || 'No se pudo guardar.' });
      } else {
        setFormFeedback({ type: 'success', text: 'Paciente guardada correctamente.' });
        setFormDni('');
        setFormApPaterno('');
        setFormApMaterno('');
        setFormNombres('');
        setFormEdad('');
        setFormCelular('');
        setFormCorreo('');
        setFormDireccion('');
        setFormSector('');
        setHisLookupResult(null);
        await fetchAppData(sessionToken);
      }
    } catch {
      await saveOffline();
    } finally {
      setSubmittingForm(false);
    }
  };

  // Caso A: un solo botón para confirmar el pase/control en la UPS.
  const handleConfirmarPaseUps = async () => {
    if (!sessionInfo || !hisLookupResult?.upsPlanificacionFamiliar?.tieneAtencionPrevia) return;
    setSubmittingForm(true);
    setFormFeedback(null);
    const payload = {
      dni: formDni,
      apellido_paterno: formApPaterno,
      apellido_materno: formApMaterno,
      nombres: formNombres,
      edad: Number(formEdad),
      celular: formCelular,
      correo: formCorreo,
      distrito:
        formDistritoSelect === 'OTROS'
          ? `OTROS: ${formDistritoOtros.trim().toUpperCase() || 'FUERA DE HUARAL'}`
          : formDistritoSelect,
      direccion: formDireccion,
      sector: formSector,
      estado_paciente: formEstado,
      codpsal_obstetra: sessionInfo.dni,
      atencion_99208: Boolean(hisLookupResult?.atencion99208?.tieneCodigo99208),
      pase_ups: true,
    };
    try {
      if (!navigator.onLine) {
        await queueOfflinePatient(payload);
        setOfflinePending(getOfflineQueueCount());
        setFormFeedback({
          type: 'success',
          text: 'Pase guardado CIFRADO en el dispositivo. Se sincronizará al recuperar señal.',
        });
        return;
      }
      const res = await fetch('/api/pacientes', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setFormFeedback({ type: 'error', text: data.error || 'No se pudo confirmar el pase.' });
        return;
      }
      setFormFeedback({
        type: 'success',
        text: 'Pase directo confirmado en la UPS de Planificación Familiar.',
      });
      await fetchAppData(sessionToken);
    } catch {
      await queueOfflinePatient(payload);
      setOfflinePending(getOfflineQueueCount());
      setFormFeedback({
        type: 'success',
        text: 'Sin conexión: el pase quedó guardado CIFRADO y se sincronizará automáticamente.',
      });
    } finally {
      setSubmittingForm(false);
    }
  };

  const handleQuickStatusUpdate = async (
    id: number,
    nuevoEstado: PacienteSinMetodoItem['estado_paciente']
  ) => {
    const res = await fetch(`/api/pacientes/${id}/estado`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sessionToken}`,
      },
      body: JSON.stringify({ estado_paciente: nuevoEstado }),
    });
    if (res.ok) {
      await fetchAppData(sessionToken);
      if (selectedPaciente && selectedPaciente.id === id) {
        setSelectedPaciente({ ...selectedPaciente, estado_paciente: nuevoEstado });
      }
    }
  };

  const handleExportIndicadoresCsv = () => {
    const headers = [
      'DNI',
      'APELLIDO_PATERNO',
      'APELLIDO_MATERNO',
      'NOMBRES',
      'EDAD',
      'CELULAR',
      'CORREO',
      'DISTRITO',
      'DIRECCION',
      'SECTOR',
      'ESTADO',
      'DNI_OBSTETRA',
      'FECHA_REGISTRO',
    ];
    const rows = pacientes.map((p) =>
      [
        p.dni,
        `"${p.apellido_paterno}"`,
        `"${p.apellido_materno}"`,
        `"${p.nombres}"`,
        p.edad,
        `"${p.celular}"`,
        `"${p.correo}"`,
        `"${p.distrito}"`,
        `"${p.direccion}"`,
        `"${p.sector}"`,
        p.estado_paciente,
        p.codpsal_obstetra,
        p.fecha_registro,
      ].join(',')
    );
    const csvContent = '\uFEFF' + [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Reporte_Planificacion_Huaral_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredPacientes = pacientes.filter((p) => {
    const matchesEstado = estadoFilter === 'ALL' || p.estado_paciente === estadoFilter;
    const q = searchQuery.trim().toLowerCase();
    if (!q) return matchesEstado;
    const fullText = `${p.dni} ${p.apellido_paterno} ${p.apellido_materno} ${p.nombres} ${p.distrito} ${p.sector}`.toLowerCase();
    return matchesEstado && fullText.includes(q);
  });

  const filteredAgenda = agendaAmpollas.filter((item) => {
    if (agendaFilter === 'ALL') return true;
    if (agendaFilter === 'TOCA_HOY_MANANA') {
      return item.estado_cita === 'TOCA_HOY' || item.estado_cita === 'TOCA_MANANA';
    }
    return item.estado_cita === agendaFilter;
  });

  // ==========================================================================
  // VIEW 1: MOBILE LOGIN & REGISTRATION SCREEN (First screen on phone)
  // ==========================================================================
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-slate-200/70 flex flex-col justify-center items-center sm:py-6">
        <div className="w-full max-w-[430px] min-h-screen sm:min-h-[780px] sm:rounded-[36px] bg-white sm:shadow-2xl sm:border sm:border-slate-200 flex flex-col justify-between overflow-hidden">
          <OfflineBanner />
          <IOSInstallBanner />

          {/* Top Hospital Huaral Brand Header */}
          <div className="px-6 pt-8 pb-5 text-center bg-gradient-to-b from-sky-50/80 to-white border-b border-slate-100">
            <div className="flex justify-center mb-3">
              <HospitalHuaralLogo className="w-24 h-24 drop-shadow-xs" />
            </div>
            <h1 className="text-lg font-bold text-slate-900 tracking-tight">
              Hospital San Juan Bautista Huaral
            </h1>
            <p className="text-xs text-slate-500 mt-0.5">
              Planificación Familiar · Captación y Seguimiento Obstétrico
            </p>
          </div>

          {/* Main Auth Body */}
          <div className="flex-1 px-6 py-5 space-y-4">
            {authStep === 'CREDENTIALS' && (
              <div className="grid grid-cols-2 gap-1 p-1 bg-slate-100 rounded-xl">
                <button
                  type="button"
                  onClick={() => {
                    setAuthTab('LOGIN');
                    setAuthError('');
                  }}
                  className={`min-h-[42px] rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                    authTab === 'LOGIN'
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Iniciar Sesión
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setAuthTab('REGISTER');
                    setAuthError('');
                  }}
                  className={`min-h-[42px] rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                    authTab === 'REGISTER'
                      ? 'bg-white text-sky-800 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Crear Cuenta Obstetra
                </button>
              </div>
            )}

            {authError && (
              <div className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-red-800 text-xs flex items-start gap-2">
                <AlertCircle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
                <span>{authError}</span>
              </div>
            )}

            {/* LOGIN FORM */}
            {authStep === 'CREDENTIALS' && authTab === 'LOGIN' && (
              <form onSubmit={handleLoginSubmit} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                    DNI de la Obstetra
                  </label>
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={11}
                    value={loginDni}
                    onChange={(e) => setLoginDni(e.target.value.replace(/\D/g, ''))}
                    placeholder="Ingrese su DNI (8 dígitos)"
                    className="w-full min-h-[48px] px-4 py-2.5 rounded-xl border border-slate-300 text-sm font-mono focus:outline-none focus:border-sky-600"
                    required
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                    Contraseña
                  </label>
                  <input
                    type="password"
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full min-h-[48px] px-4 py-2.5 rounded-xl border border-slate-300 text-sm focus:outline-none focus:border-sky-600"
                    required
                  />
                </div>

                <button
                  type="submit"
                  disabled={authLoading}
                  className="w-full min-h-[50px] rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-sm font-semibold flex items-center justify-center gap-2 transition-colors cursor-pointer shadow-xs"
                >
                  <Lock className="w-4 h-4" />
                  <span>{authLoading ? 'Validando acceso...' : 'Ingresar a la Aplicación'}</span>
                </button>

                {/* Quick Test Credentials Helper */}
                <div className="pt-3 border-t border-slate-100">
                  <p className="text-[11px] text-slate-400 mb-2 text-center">
                    Accesos rápidos de demostración:
                  </p>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setLoginDni('41829304');
                        setLoginPassword('Obstetra2026!');
                      }}
                      className="p-2 rounded-xl border border-slate-200 hover:bg-slate-50 text-left text-xs cursor-pointer"
                    >
                      <div className="font-semibold text-slate-800">Obst. Roxana</div>
                      <div className="text-[10px] font-mono text-slate-500">DNI: 41829304</div>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setLoginDni('44910283');
                        setLoginPassword('Obstetra2026!');
                      }}
                      className="p-2 rounded-xl border border-slate-200 hover:bg-slate-50 text-left text-xs cursor-pointer"
                    >
                      <div className="font-semibold text-slate-800">Obst. Carmen</div>
                      <div className="text-[10px] font-mono text-slate-500">DNI: 44910283</div>
                    </button>
                  </div>
                </div>
              </form>
            )}

            {/* REGISTER NEW OBSTETRICIAN FORM */}
            {authStep === 'CREDENTIALS' && authTab === 'REGISTER' && (
              <form onSubmit={handleRegisterSubmit} className="space-y-3">
                <div className="grid grid-cols-2 gap-2.5">
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">
                      DNI (8 dígitos)
                    </label>
                    <input
                      type="text"
                      inputMode="numeric"
                      maxLength={8}
                      value={regDni}
                      onChange={(e) => setRegDni(e.target.value.replace(/\D/g, ''))}
                      required
                      placeholder="43819205"
                      className="w-full min-h-[44px] px-3 py-2 rounded-xl border border-slate-300 text-sm font-mono"
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
                      required
                      placeholder="987654321"
                      className="w-full min-h-[44px] px-3 py-2 rounded-xl border border-slate-300 text-sm font-mono"
                    />
                  </div>
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
                    placeholder="Nombres completos"
                    className="w-full min-h-[44px] px-3 py-2 rounded-xl border border-slate-300 text-sm"
                  />
                </div>

                <div className="grid grid-cols-2 gap-2.5">
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

                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Correo Electrónico
                  </label>
                  <input
                    type="email"
                    value={regEmail}
                    onChange={(e) => setRegEmail(e.target.value)}
                    required
                    placeholder="obstetra@correo.pe"
                    className="w-full min-h-[44px] px-3 py-2 rounded-xl border border-slate-300 text-sm"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Establecimiento de Salud ({TOTAL_ESTABLECIMIENTOS} IPRESS Red Huaral-Chancay)
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
                    El DNI de sus pacientes se buscará únicamente en la UPS de Planificación Familiar de
                    este establecimiento. Podrá cambiarlo luego en la barra superior.
                  </p>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Contraseña
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

                <button
                  type="submit"
                  disabled={authLoading}
                  className="w-full min-h-[48px] rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-sm font-semibold flex items-center justify-center gap-2 transition-colors cursor-pointer"
                >
                  <UserPlus className="w-4 h-4" />
                  <span>{authLoading ? 'Registrando...' : 'Crear Cuenta de Obstetra'}</span>
                </button>
              </form>
            )}

            {/* STEP 2: 2FA VERIFICATION */}
            {authStep === 'VERIFY_2FA' && (
              <form onSubmit={handleVerify2FA} className="space-y-4">
                <div className="p-4 rounded-2xl bg-sky-950 text-white space-y-2">
                  <div className="text-xs font-semibold text-sky-200">
                    Verificación de Seguridad en Dos Pasos (2FA)
                  </div>
                  <p className="text-xs text-slate-300">
                    Código de seguridad generado para su sesión móvil:
                  </p>
                  <div className="flex items-center justify-between pt-1">
                    <span className="text-2xl font-bold font-mono tracking-widest text-white">
                      {demoCodeHint}
                    </span>
                    <button
                      type="button"
                      onClick={() => setTotpCode(demoCodeHint)}
                      className="px-3 py-1.5 rounded-lg bg-sky-700 text-xs font-semibold flex items-center gap-1 cursor-pointer"
                    >
                      <RefreshCw className="w-3.5 h-3.5" />
                      <span>Usar código</span>
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                    Código de 6 dígitos
                  </label>
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                    className="w-full min-h-[50px] px-4 rounded-xl border border-slate-300 text-center text-xl font-bold font-mono tracking-widest focus:outline-none focus:border-sky-600"
                    required
                  />
                </div>

                <div className="flex gap-2.5">
                  <button
                    type="button"
                    onClick={() => setAuthStep('CREDENTIALS')}
                    className="min-h-[48px] px-4 rounded-xl border border-slate-300 text-xs font-semibold text-slate-700 cursor-pointer"
                  >
                    Atrás
                  </button>
                  <button
                    type="submit"
                    disabled={authLoading}
                    className="flex-1 min-h-[48px] rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-sm font-semibold flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <KeyRound className="w-4 h-4" />
                    <span>{authLoading ? 'Verificando...' : 'Confirmar y Entrar'}</span>
                  </button>
                </div>
              </form>
            )}
          </div>

          {/* Bottom Install App Bar */}
          <div className="px-6 py-4 bg-slate-50 border-t border-slate-100 flex items-center justify-between">
            <span className="text-xs text-slate-500">App Móvil Oficial</span>
            <PWAInstallButton />
          </div>
        </div>
      </div>
    );
  }

  // ==========================================================================
  // VIEW 2: AUTHENTICATED MOBILE APP SHELL (Max-Width 430px Mobile App Layout)
  // ==========================================================================
  return (
    <div className="min-h-screen bg-slate-200/70 flex flex-col items-center">
      <div className="w-full max-w-[430px] min-h-screen bg-slate-50 shadow-2xl border-x border-slate-200 flex flex-col relative pb-20">
        <OfflineBanner />
        <IOSInstallBanner />

        {/* COMPACT MOBILE TOP APP BAR */}
        <header className="sticky top-0 z-30 bg-white/95 backdrop-blur-md border-b border-slate-200 px-3 py-2.5 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0 flex-1">
            <HospitalHuaralLogo className="w-9 h-9 shrink-0" />
            <div className="min-w-0 flex-1">
              <div className="text-xs font-bold text-slate-900 truncate">
                {sessionInfo?.nombreCompleto || 'Hospital SJB Huaral'}
              </div>
              <select
                aria-label="Establecimiento activo de la obstetra"
                value={sessionInfo?.cod_estab || '000005481'}
                onChange={(e) => handleChangeEstablecimiento(e.target.value)}
                disabled={changingEstab}
                className="mt-0.5 w-full max-w-[250px] min-h-[30px] px-2 py-0.5 rounded-lg border border-sky-200 bg-sky-50 text-[10px] text-sky-950 font-medium truncate"
              >
                {Object.entries(ESTABLECIMIENTOS_POR_DISTRITO).map(([distrito, lista]) => (
                  <optgroup key={distrito} label={distrito}>
                    {lista.map((est) => (
                      <option key={est.COD_ESTAB} value={est.COD_ESTAB}>
                        {est.DESC_ESTAB} · {est.CATEGORIA}
                      </option>
                    ))}
                  </optgroup>
                ))}
              </select>
            </div>
          </div>

          <div className="flex items-center gap-1 shrink-0">
            {offlinePending > 0 && (
              <span
                className="px-2 py-1 rounded-lg bg-amber-100 text-amber-900 text-[10px] font-bold"
                title="Captaciones cifradas pendientes de sincronizar"
              >
                {offlinePending} offline
              </span>
            )}
            <button
              type="button"
              onClick={handleLogout}
              className="min-h-[40px] min-w-[40px] flex items-center justify-center rounded-xl text-slate-500 hover:text-red-600 hover:bg-slate-100 cursor-pointer"
              title="Cerrar sesión"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </header>

        {/* SCROLLABLE MOBILE CONTENT AREA */}
        <main className="flex-1 p-4 space-y-4">
          {/* ================================================================= */}
          {/* TAB 1: CAPTAR PACIENTE EN CAMPO                                   */}
          {/* ================================================================= */}
          {activeTab === 'CAPTAR' && (
            <div className="space-y-4">
              {/* Quick Summary Strip */}
              <div className="grid grid-cols-3 gap-2">
                <div className="p-3 rounded-2xl bg-white border border-slate-200">
                  <div className="text-[10px] text-slate-500 leading-tight">Sin Método Captadas</div>
                  <div className="text-lg font-bold text-amber-700 font-mono tabular-nums mt-0.5">
                    {stats.insatisfechasSinMetodo}
                  </div>
                </div>
                <div className="p-3 rounded-2xl bg-white border border-slate-200">
                  <div className="text-[10px] text-slate-500 leading-tight">Citas Ampolla Hoy/Mañana</div>
                  <div className="text-lg font-bold text-sky-700 font-mono tabular-nums mt-0.5">
                    {stats.citasAmpollaHoyManana}
                  </div>
                </div>
                <div
                  className={`p-3 rounded-2xl border ${
                    stats.atenciones99208 > 0
                      ? 'bg-red-50 border-red-300'
                      : 'bg-white border-slate-200'
                  }`}
                >
                  <div className="text-[10px] text-slate-500 leading-tight">Atenciones 99208</div>
                  <div className="text-lg font-bold text-red-700 font-mono tabular-nums mt-0.5">
                    {stats.atenciones99208}
                  </div>
                </div>
              </div>

              {/* Step 1: Validate DNI */}
              <div className="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
                <div className="text-xs font-bold text-slate-900">
                  1. Validar DNI de la Paciente
                </div>
                <div className="rounded-xl bg-sky-50 border border-sky-200 px-3 py-2 text-[11px] text-sky-950">
                  <div className="font-semibold">Búsqueda restringida a su establecimiento activo:</div>
                  <div className="mt-0.5">{sessionInfo?.estab_nombre}</div>
                  <div className="text-sky-700 mt-0.5">
                    UPS Planificación Familiar (COD_SERVSA 302304 / DX 99208, 90782, Z304, Z301, Z300)
                  </div>
                </div>
                <div className="flex gap-2">
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={15}
                    value={formDni}
                    onChange={(e) => setFormDni(e.target.value.replace(/\D/g, ''))}
                    placeholder="Ingrese DNI (8 dígitos)"
                    className="flex-1 min-h-[46px] px-3.5 rounded-xl border border-slate-300 text-sm font-mono focus:outline-none focus:border-sky-600"
                  />
                  <button
                    type="button"
                    onClick={() => handleDniLookupInHis()}
                    disabled={lookupLoading}
                    className="min-h-[46px] px-4 rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-xs font-semibold flex items-center gap-1.5 shrink-0 cursor-pointer"
                  >
                    <Search className="w-4 h-4" />
                    <span>{lookupLoading ? '...' : 'Validar'}</span>
                  </button>
                </div>

                {/* Validation Result Alert */}
                {hisLookupResult && (
                  <div
                    className={`p-3.5 rounded-xl border text-xs space-y-1 ${
                      hisLookupResult.hasActiveMethodInHis
                        ? 'bg-emerald-50 border-emerald-300 text-emerald-950'
                        : 'bg-amber-50 border-amber-300 text-amber-950'
                    }`}
                  >
                    {hisLookupResult.hasActiveMethodInHis ? (
                      <>
                        <div className="font-bold flex items-center gap-1.5 text-emerald-900">
                          <CheckCircle2 className="w-4 h-4 text-emerald-700 shrink-0" />
                          <span>Paciente ya recibe método activo en el Hospital</span>
                        </div>
                        <p>
                          <strong>
                            {hisLookupResult.hisRecord?.Apellido_p}{' '}
                            {hisLookupResult.hisRecord?.Apellido_m},{' '}
                            {hisLookupResult.hisRecord?.Dnombres}
                          </strong>{' '}
                          ({hisLookupResult.hisRecord?.DESC_ESTAB}).
                        </p>
                        {hisLookupResult.hisDetails.map((d, i) => (
                          <div key={i} className="font-mono text-[11px] pt-1">
                            {d.METODO_CORTO} · Próxima cita: <strong>{d.FECHA_PROXIMA_CITA}</strong>
                          </div>
                        ))}
                      </>
                    ) : (
                      <>
                        <div className="font-bold flex items-center gap-1.5 text-amber-900">
                          <AlertCircle className="w-4 h-4 text-amber-700 shrink-0" />
                          <span>
                            {hisLookupResult.foundInHis
                              ? 'Paciente en base del hospital pero SIN método vigente'
                              : 'Paciente nueva sin método registrado'}
                          </span>
                        </div>
                        <p>Complete sus datos abajo para registrarla en seguimiento.</p>
                      </>
                    )}
                  </div>
                )}
              </div>

              {/* BANNER CLÍNICO DESTACADO 99208 */}
              {hisLookupResult?.atencion99208?.tieneCodigo99208 && (
                <div className="p-4 rounded-2xl bg-red-950 border-2 border-red-500 text-white shadow-lg space-y-2">
                  <div className="flex items-center gap-2 text-sm font-extrabold text-red-100">
                    <AlertCircle className="w-5 h-5 text-red-300 shrink-0" />
                    <span>ALERTA CLÍNICA · CÓDIGO 99208</span>
                  </div>
                  <p className="text-xs leading-relaxed text-red-50">
                    {hisLookupResult.atencion99208.mensajeOficial99208}
                  </p>
                  {hisLookupResult.atencion99208.historial99208.slice(0, 3).map((item, index) => (
                    <div
                      key={`${item.fecha_iso}-${index}`}
                      className="rounded-xl bg-red-900/60 border border-red-700 px-3 py-2 text-[11px] font-mono"
                    >
                      {item.fecha} · {item.establecimiento} · DX {item.dx}{' '}
                      {item.tdx ? `(${item.tdx})` : ''}
                    </div>
                  ))}
                </div>
              )}

              {/* CASO A / CASO B · UPS PLANIFICACIÓN FAMILIAR */}
              {hisLookupResult?.upsPlanificacionFamiliar && (
                <div
                  className={`p-4 rounded-2xl border-2 space-y-2.5 ${
                    hisLookupResult.upsPlanificacionFamiliar.caso === 'A'
                      ? 'bg-emerald-50 border-emerald-400 text-emerald-950'
                      : 'bg-amber-50 border-amber-400 text-amber-950'
                  }`}
                >
                  <div className="text-xs font-extrabold flex items-center gap-2">
                    {hisLookupResult.upsPlanificacionFamiliar.caso === 'A' ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-700 shrink-0" />
                    ) : (
                      <AlertCircle className="w-4 h-4 text-amber-700 shrink-0" />
                    )}
                    <span>
                      UPS Planificación Familiar ·{' '}
                      {hisLookupResult.upsPlanificacionFamiliar.establecimiento.nombre}
                    </span>
                  </div>
                  <p className="text-xs leading-relaxed font-semibold">
                    {hisLookupResult.upsPlanificacionFamiliar.mensaje}
                  </p>
                  {hisLookupResult.upsPlanificacionFamiliar.caso === 'A' && (
                    <>
                      <div className="space-y-1">
                        {hisLookupResult.upsPlanificacionFamiliar.atenciones
                          .slice(0, 3)
                          .map((a, i) => (
                            <div
                              key={`${a.id_his}-${i}`}
                              className="rounded-lg bg-white/70 border border-emerald-200 px-2.5 py-1.5 text-[11px] font-mono"
                            >
                              {a.fecha} · Cód. {a.dx || a.cod_servsa} · Dosis {a.id_dosis || '—'}
                            </div>
                          ))}
                      </div>
                      <button
                        type="button"
                        onClick={handleConfirmarPaseUps}
                        disabled={submittingForm}
                        className="w-full min-h-[46px] rounded-xl bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-bold flex items-center justify-center gap-2 cursor-pointer"
                      >
                        <UserCheck className="w-4 h-4" />
                        <span>
                          {submittingForm ? 'Confirmando pase...' : 'Confirmar Pase / Control en UPS'}
                        </span>
                      </button>
                    </>
                  )}
                  {hisLookupResult.upsPlanificacionFamiliar.caso === 'B' && (
                    <p className="text-[11px] text-amber-900">
                      Complete los datos del formulario inferior para registrar la captación en esta IPRESS.
                    </p>
                  )}
                </div>
              )}

              {formFeedback && (
                <div
                  className={`p-3.5 rounded-xl border text-xs flex items-center gap-2 ${
                    formFeedback.type === 'success'
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-900 font-medium'
                      : 'bg-red-50 border-red-200 text-red-800 font-medium'
                  }`}
                >
                  {formFeedback.type === 'success' ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-700 shrink-0" />
                  ) : (
                    <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
                  )}
                  <span>{formFeedback.text}</span>
                </div>
              )}

              {/* Step 2: Patient Registration Form */}
              <form
                onSubmit={handleSavePaciente}
                className="p-4 rounded-2xl bg-white border border-slate-200 space-y-3.5"
              >
                <div className="text-xs font-bold text-slate-900">
                  2. Datos de la Paciente a Captar
                </div>

                <div className="grid grid-cols-2 gap-2.5">
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Apellido Paterno
                    </label>
                    <input
                      type="text"
                      value={formApPaterno}
                      onChange={(e) => setFormApPaterno(e.target.value)}
                      required
                      className="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Apellido Materno
                    </label>
                    <input
                      type="text"
                      value={formApMaterno}
                      onChange={(e) => setFormApMaterno(e.target.value)}
                      required
                      className="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-2.5">
                  <div className="col-span-2">
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Nombres
                    </label>
                    <input
                      type="text"
                      value={formNombres}
                      onChange={(e) => setFormNombres(e.target.value)}
                      required
                      className="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Edad
                    </label>
                    <input
                      type="number"
                      min={10}
                      max={65}
                      value={formEdad}
                      onChange={(e) => setFormEdad(e.target.value)}
                      required
                      className="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm font-mono"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2.5">
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Celular
                    </label>
                    <input
                      type="tel"
                      inputMode="tel"
                      value={formCelular}
                      onChange={(e) => setFormCelular(e.target.value)}
                      placeholder="987654321"
                      className="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Correo Electrónico
                    </label>
                    <input
                      type="email"
                      value={formCorreo}
                      onChange={(e) => setFormCorreo(e.target.value)}
                      placeholder="Opcional"
                      className="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">
                    Distrito (Provincia de Huaral)
                  </label>
                  <select
                    value={formDistritoSelect}
                    onChange={(e) => setFormDistritoSelect(e.target.value)}
                    className="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm bg-white"
                  >
                    {distritos.map((d) => (
                      <option key={d.UBIGEO} value={d.DESC_DIST}>
                        {d.DESC_DIST}
                      </option>
                    ))}
                    <option value="OTROS">OTROS (Fuera de Huaral)</option>
                  </select>
                </div>

                {formDistritoSelect === 'OTROS' && (
                  <div>
                    <label className="block text-xs font-semibold text-amber-800 mb-1">
                      Especifique otro Distrito / Procedencia
                    </label>
                    <input
                      type="text"
                      value={formDistritoOtros}
                      onChange={(e) => setFormDistritoOtros(e.target.value)}
                      required
                      placeholder="Ej. Huacho, Chancayllo, Lima..."
                      className="w-full min-h-[44px] px-3 rounded-xl border border-amber-400 bg-amber-50/40 text-sm"
                    />
                  </div>
                )}

                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">
                    Dirección Domiciliaria
                  </label>
                  <input
                    type="text"
                    value={formDireccion}
                    onChange={(e) => setFormDireccion(e.target.value)}
                    required
                    placeholder="Calle / Av. / Urb. / Referencia"
                    className="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm"
                  />
                </div>

                <div className="grid grid-cols-2 gap-2.5">
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Sector
                    </label>
                    <input
                      type="text"
                      value={formSector}
                      onChange={(e) => setFormSector(e.target.value)}
                      required
                      placeholder="Ej. Sector 28"
                      className="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-sm"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Estado
                    </label>
                    <select
                      value={formEstado}
                      onChange={(e) =>
                        setFormEstado(e.target.value as PacienteSinMetodoItem['estado_paciente'])
                      }
                      className="w-full min-h-[44px] px-2.5 rounded-xl border border-slate-300 text-xs bg-white"
                    >
                      <option value="INSATISFECHA_SIN_METODO">Sin Método (Insatisfecha)</option>
                      <option value="SEGUIMIENTO_DOMICILIARIO">En Seguimiento</option>
                      <option value="CONSEJERIA_REALIZADA">Consejería Realizada</option>
                      <option value="CAPTADA_CON_METODO">Con Método (Satisfecha)</option>
                    </select>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={submittingForm}
                  className="w-full min-h-[48px] rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-sm font-semibold flex items-center justify-center gap-2 transition-colors cursor-pointer"
                >
                  <UserPlus className="w-4 h-4" />
                  <span>{submittingForm ? 'Guardando...' : 'Guardar Paciente'}</span>
                </button>
              </form>
            </div>
          )}

          {/* ================================================================= */}
          {/* TAB 2: LISTA DE PACIENTES Y SEGUIMIENTO POR SECTOR                */}
          {/* ================================================================= */}
          {activeTab === 'PACIENTES' && (
            <div className="space-y-3">
              <div className="p-3.5 rounded-2xl bg-white border border-slate-200 space-y-2.5">
                <div className="relative">
                  <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Buscar por DNI, nombre o sector..."
                    className="w-full min-h-[44px] pl-10 pr-3 rounded-xl border border-slate-300 text-sm focus:outline-none focus:border-sky-600"
                  />
                </div>

                <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-xl overflow-x-auto">
                  <button
                    type="button"
                    onClick={() => setEstadoFilter('ALL')}
                    className={`min-h-[34px] px-3 rounded-lg text-xs font-medium whitespace-nowrap shrink-0 cursor-pointer ${
                      estadoFilter === 'ALL' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600'
                    }`}
                  >
                    Todas ({pacientes.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setEstadoFilter('INSATISFECHA_SIN_METODO')}
                    className={`min-h-[34px] px-3 rounded-lg text-xs font-medium whitespace-nowrap shrink-0 cursor-pointer ${
                      estadoFilter === 'INSATISFECHA_SIN_METODO'
                        ? 'bg-white text-amber-800 shadow-xs'
                        : 'text-slate-600'
                    }`}
                  >
                    Sin Método
                  </button>
                  <button
                    type="button"
                    onClick={() => setEstadoFilter('SEGUIMIENTO_DOMICILIARIO')}
                    className={`min-h-[34px] px-3 rounded-lg text-xs font-medium whitespace-nowrap shrink-0 cursor-pointer ${
                      estadoFilter === 'SEGUIMIENTO_DOMICILIARIO'
                        ? 'bg-white text-slate-900 shadow-xs'
                        : 'text-slate-600'
                    }`}
                  >
                    Seguimiento
                  </button>
                  <button
                    type="button"
                    onClick={() => setEstadoFilter('CAPTADA_CON_METODO')}
                    className={`min-h-[34px] px-3 rounded-lg text-xs font-medium whitespace-nowrap shrink-0 cursor-pointer ${
                      estadoFilter === 'CAPTADA_CON_METODO'
                        ? 'bg-white text-emerald-800 shadow-xs'
                        : 'text-slate-600'
                    }`}
                  >
                    Con Método
                  </button>
                </div>
              </div>

              {loading ? (
                <div className="p-8 text-center text-xs text-slate-500">Cargando pacientes...</div>
              ) : filteredPacientes.length === 0 ? (
                <div className="p-8 rounded-2xl bg-white border border-slate-200 text-center text-xs text-slate-500">
                  No se encontraron pacientes en esta vista.
                </div>
              ) : (
                <div className="space-y-2.5">
                  {filteredPacientes.map((p) => (
                    <div
                      key={p.id}
                      onClick={() => setSelectedPaciente(selectedPaciente?.id === p.id ? null : p)}
                      className="p-4 rounded-2xl bg-white border border-slate-200 space-y-2.5 cursor-pointer"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <div className="text-sm font-bold text-slate-900">
                            {p.apellido_paterno} {p.apellido_materno}, {p.nombres}
                          </div>
                          <div className="text-xs text-slate-500 mt-0.5">
                            DNI <span className="font-mono font-semibold text-slate-800">{p.dni}</span> ·{' '}
                            {p.edad} años · {p.distrito}
                          </div>
                        </div>
                        <ChevronRight
                          className={`w-4 h-4 text-slate-400 transition-transform ${
                            selectedPaciente?.id === p.id ? 'rotate-90' : ''
                          }`}
                        />
                      </div>

                      <div className="flex items-center justify-between text-xs pt-1 border-t border-slate-100">
                        <span className="font-semibold text-slate-700">{p.sector}</span>
                        {p.estado_paciente === 'CAPTADA_CON_METODO' ? (
                          <span className="text-emerald-700 font-semibold flex items-center gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5" /> Con Método
                          </span>
                        ) : p.estado_paciente === 'INSATISFECHA_SIN_METODO' ? (
                          <span className="text-amber-700 font-semibold flex items-center gap-1">
                            <AlertCircle className="w-3.5 h-3.5" /> Sin Método
                          </span>
                        ) : (
                          <span className="text-sky-700 font-semibold flex items-center gap-1">
                            <Clock className="w-3.5 h-3.5" /> Seguimiento
                          </span>
                        )}
                      </div>

                      {selectedPaciente?.id === p.id && (
                        <div
                          onClick={(e) => e.stopPropagation()}
                          className="pt-3 border-t border-slate-100 space-y-3 text-xs"
                        >
                          <div className="space-y-1 text-slate-600">
                            <div className="flex items-center gap-1.5">
                              <MapPin className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                              <span>{p.direccion}</span>
                            </div>
                            <div className="flex items-center justify-between pt-1">
                              <div className="flex items-center gap-1.5 font-mono text-slate-800">
                                <Phone className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                                <span>{p.celular || 'Sin teléfono'}</span>
                              </div>
                              {p.celular && (
                                <a
                                  href={`tel:${p.celular}`}
                                  className="px-3 py-1.5 rounded-lg bg-sky-50 text-sky-800 font-semibold"
                                >
                                  Llamar
                                </a>
                              )}
                            </div>
                          </div>

                          <div>
                            <div className="text-[11px] font-semibold text-slate-500 mb-1.5">
                              Cambiar Estado:
                            </div>
                            <div className="grid grid-cols-2 gap-1.5">
                              {(
                                [
                                  'INSATISFECHA_SIN_METODO',
                                  'SEGUIMIENTO_DOMICILIARIO',
                                  'CONSEJERIA_REALIZADA',
                                  'CAPTADA_CON_METODO',
                                ] as const
                              ).map((est) => (
                                <button
                                  key={est}
                                  type="button"
                                  onClick={() => handleQuickStatusUpdate(p.id, est)}
                                  className={`min-h-[38px] px-2.5 py-1.5 rounded-xl border text-left text-[11px] font-medium cursor-pointer ${
                                    p.estado_paciente === est
                                      ? 'border-sky-700 bg-sky-50 text-sky-950 font-semibold'
                                      : 'border-slate-200 text-slate-700'
                                  }`}
                                >
                                  {ESTADO_LABELS[est]}
                                </button>
                              ))}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* TAB 3: AGENDA DE AMPOLLAS (30 / 90 DÍAS) E INDICADORES            */}
          {/* ================================================================= */}
          {activeTab === 'AGENDA' && (
            <div className="space-y-4">
              <div className="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-sm font-bold text-slate-900">
                      Agenda de Ampollas y Controles
                    </h2>
                    <p className="text-[11px] text-slate-500">
                      Pacientes citadas cada 30 o 90 días según el HIS
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={handleExportIndicadoresCsv}
                    className="min-h-[38px] px-3 py-1.5 rounded-xl bg-slate-900 text-white text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Excel CSV</span>
                  </button>
                </div>

                <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-xl">
                  <button
                    type="button"
                    onClick={() => setAgendaFilter('ALL')}
                    className={`flex-1 min-h-[34px] rounded-lg text-xs font-medium cursor-pointer ${
                      agendaFilter === 'ALL' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600'
                    }`}
                  >
                    Todas
                  </button>
                  <button
                    type="button"
                    onClick={() => setAgendaFilter('TOCA_HOY_MANANA')}
                    className={`flex-1 min-h-[34px] rounded-lg text-xs font-medium cursor-pointer ${
                      agendaFilter === 'TOCA_HOY_MANANA'
                        ? 'bg-white text-sky-800 shadow-xs'
                        : 'text-slate-600'
                    }`}
                  >
                    Hoy / Mañana
                  </button>
                  <button
                    type="button"
                    onClick={() => setAgendaFilter('VENCIDA_ABANDONO')}
                    className={`flex-1 min-h-[34px] rounded-lg text-xs font-medium cursor-pointer ${
                      agendaFilter === 'VENCIDA_ABANDONO'
                        ? 'bg-white text-red-700 shadow-xs'
                        : 'text-slate-600'
                    }`}
                  >
                    Vencidas
                  </button>
                </div>

                <div className="divide-y divide-slate-100">
                  {filteredAgenda.map((item) => (
                    <div key={item.id_his} className="py-3 space-y-1 text-xs">
                      <div className="flex items-center justify-between font-bold text-slate-900">
                        <span>{item.paciente_nombre}</span>
                        <span className="font-mono text-slate-500">DNI {item.dni}</span>
                      </div>
                      <div className="text-slate-600">
                        {item.metodo_descripcion} (Cód. <span className="font-mono">{item.codigo_his}</span>)
                      </div>
                      <div className="flex items-center justify-between pt-1">
                        <span className="font-mono text-[11px] text-slate-500">
                          Próxima: <strong className="text-slate-900">{item.fecha_proxima_cita || 'Sin método'}</strong>
                        </span>
                        {item.estado_cita === 'TOCA_HOY' && (
                          <span className="text-sky-800 font-bold">TOCA HOY</span>
                        )}
                        {item.estado_cita === 'TOCA_MANANA' && (
                          <span className="text-sky-700 font-bold">TOCA MAÑANA</span>
                        )}
                        {item.estado_cita === 'VENCIDA_ABANDONO' && (
                          <span className="text-red-700 font-bold">VENCIDA</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Indicadores por Obstetra */}
              <div className="p-4 rounded-2xl bg-white border border-slate-200 space-y-2.5">
                <h3 className="text-sm font-bold text-slate-900">
                  Avance de Captación por Obstetra
                </h3>
                <div className="divide-y divide-slate-100 text-xs">
                  {produccionObstetras.map((o) => (
                    <div key={o.codpsal} className="py-2.5 flex items-center justify-between">
                      <div className="pr-2">
                        <div className="font-semibold text-slate-900">{o.nombre}</div>
                        <div className="font-mono text-[11px] text-slate-500">
                          DNI: {o.codpsal}
                        </div>
                      </div>
                      <div className="text-right font-mono shrink-0">
                        <div className="font-bold text-sky-800">{o.totalCaptadas} captadas</div>
                        <div className="text-[11px] text-amber-700">
                          {o.insatisfechasCaptadas} sin método
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ================================================================= */}
          {/* TAB 4: SEGURIDAD, ESTADÍSTICAS Y AUDITORÍA SHA-256               */}
          {/* ================================================================= */}
          {activeTab === 'SEGURIDAD' && (
            <SecurityAndAuditPanel
              sessionToken={sessionToken}
              auditLogs={auditLogs}
              pacientes={pacientes.map((p) => ({
                id: p.id,
                dni: p.dni,
                apellido_paterno: p.apellido_paterno,
                apellido_materno: p.apellido_materno,
                nombres: p.nombres,
                celular: p.celular,
                correo: p.correo,
                direccion: p.direccion,
                encrypted_raw: p.encrypted_raw || {
                  celular: p.celular,
                  correo: p.correo,
                  direccion: p.direccion,
                },
              }))}
              securityMetrics={securityMetrics}
              onRefreshAudit={() => fetchAppData(sessionToken)}
            />
          )}

          {/* ================================================================= */}
          {/* TAB 5: MI PERFIL OBSTETRA E INSTALACIÓN MÓVIL                     */}
          {/* ================================================================= */}
          {activeTab === 'PERFIL' && (
            <div className="space-y-4">
              <div className="p-4 rounded-2xl bg-white border border-slate-200 space-y-3">
                <div className="flex items-center gap-3">
                  <HospitalHuaralLogo className="w-12 h-12 shrink-0" />
                  <div>
                    <div className="text-sm font-bold text-slate-900">
                      {sessionInfo?.nombreCompleto}
                    </div>
                    <div className="text-xs text-slate-500 font-mono">
                      DNI / CODPSAL: {sessionInfo?.dni}
                    </div>
                    <div className="text-xs text-sky-700 font-medium">
                      {sessionInfo?.estab_nombre}
                    </div>
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-100 flex items-center justify-between">
                  <span className="text-xs text-slate-600">Instalación en Celular</span>
                  <PWAInstallButton />
                </div>
              </div>

              <div className="p-4 rounded-2xl bg-white border border-slate-200 space-y-2.5">
                <div className="text-xs font-bold text-slate-900">
                  Establecimiento activo ({TOTAL_ESTABLECIMIENTOS} IPRESS)
                </div>
                <select
                  value={sessionInfo?.cod_estab || '000005481'}
                  onChange={(e) => handleChangeEstablecimiento(e.target.value)}
                  disabled={changingEstab}
                  className="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 text-xs bg-white"
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
                <div className="flex items-center justify-between text-[11px] text-slate-600">
                  <span>
                    {offlinePending > 0
                      ? `${offlinePending} captación(es) cifradas pendientes`
                      : 'Cola offline vacía'}
                  </span>
                  <button
                    type="button"
                    onClick={async () => {
                      setSyncingOffline(true);
                      try {
                        const result = await syncOfflineQueue(sessionToken);
                        setOfflinePending(result.pending);
                        setFormFeedback(
                          result.synced > 0
                            ? {
                                type: 'success',
                                text: `${result.synced} captación(es) sincronizada(s).`,
                              }
                            : {
                                type: result.failed ? 'error' : 'success',
                                text: result.failed
                                  ? `${result.failed} registro(s) no se pudieron sincronizar.`
                                  : 'No hay registros pendientes para sincronizar.',
                              }
                        );
                        if (result.synced > 0) await fetchAppData(sessionToken);
                      } finally {
                        setSyncingOffline(false);
                      }
                    }}
                    disabled={syncingOffline}
                    className="px-2.5 py-1.5 rounded-lg bg-slate-900 text-white font-semibold flex items-center gap-1"
                  >
                    {navigator.onLine ? <Wifi className="w-3 h-3" /> : <CloudOff className="w-3 h-3" />}
                    <span>{syncingOffline ? 'Sincronizando...' : 'Sincronizar'}</span>
                  </button>
                </div>
              </div>

              <div className="p-4 rounded-2xl bg-white border border-slate-200 space-y-2.5">
                <div className="text-xs font-bold text-slate-900">
                  Últimos Registros de Actividad ({auditLogs.length})
                </div>
                <div className="divide-y divide-slate-100 max-h-64 overflow-y-auto">
                  {auditLogs.slice(0, 8).map((log) => (
                    <div key={log.id} className="py-2 text-xs">
                      <div className="flex items-center justify-between font-mono text-[11px] text-slate-500">
                        <span>{log.action}</span>
                        <span>{log.timestamp}</span>
                      </div>
                      <p className="text-slate-700 mt-0.5">{log.details}</p>
                    </div>
                  ))}
                </div>
              </div>

              <button
                type="button"
                onClick={handleLogout}
                className="w-full min-h-[48px] rounded-2xl border border-red-200 bg-red-50 text-red-700 text-sm font-semibold flex items-center justify-center gap-2 cursor-pointer"
              >
                <LogOut className="w-4 h-4" />
                <span>Cerrar Sesión</span>
              </button>
            </div>
          )}
        </main>

        {/* FIXED BOTTOM NAVIGATION BAR (Always visible inside the Mobile App Shell) */}
        <nav
          aria-label="Navegación principal móvil"
          className="fixed bottom-0 left-1/2 -translate-x-1/2 w-full max-w-[430px] z-40 bg-white/95 backdrop-blur-md border-t border-slate-200 grid grid-cols-5 items-center h-16 pb-safe"
        >
          <button
            type="button"
            onClick={() => setActiveTab('CAPTAR')}
            className={`min-h-[44px] flex flex-col items-center justify-center cursor-pointer ${
              activeTab === 'CAPTAR' ? 'text-sky-700 font-bold' : 'text-slate-400'
            }`}
          >
            <UserPlus className="w-5 h-5" />
            <span className="text-[10px] mt-1">Captar</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('PACIENTES')}
            className={`min-h-[44px] flex flex-col items-center justify-center cursor-pointer ${
              activeTab === 'PACIENTES' ? 'text-sky-700 font-bold' : 'text-slate-400'
            }`}
          >
            <Users className="w-5 h-5" />
            <span className="text-[10px] mt-1">Pacientes</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('AGENDA')}
            className={`min-h-[44px] flex flex-col items-center justify-center cursor-pointer ${
              activeTab === 'AGENDA' ? 'text-sky-700 font-bold' : 'text-slate-400'
            }`}
          >
            <CalendarClock className="w-5 h-5" />
            <span className="text-[10px] mt-1">Agenda</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('SEGURIDAD')}
            className={`min-h-[44px] flex flex-col items-center justify-center cursor-pointer ${
              activeTab === 'SEGURIDAD' ? 'text-sky-700 font-bold' : 'text-slate-400'
            }`}
          >
            <ShieldCheck className="w-5 h-5" />
            <span className="text-[10px] mt-1">Seguridad</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('PERFIL')}
            className={`min-h-[44px] flex flex-col items-center justify-center cursor-pointer ${
              activeTab === 'PERFIL' ? 'text-sky-700 font-bold' : 'text-slate-400'
            }`}
          >
            <UserCheck className="w-5 h-5" />
            <span className="text-[10px] mt-1">Mi Perfil</span>
          </button>
        </nav>
      </div>
    </div>
  );
}
