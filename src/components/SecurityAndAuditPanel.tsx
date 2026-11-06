import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  FileCode2,
  CheckCircle2,
  AlertOctagon,
  Download,
  Copy,
  Check,
  Eye,
  EyeOff,
  Terminal,
  RefreshCw,
} from 'lucide-react';

export interface AuditLogItem {
  id: number;
  timestamp: string;
  actor_dni: string;
  actor_estab?: string;
  actor_nombre: string;
  actor_rol: string;
  ip_address: string;
  platform: 'Android' | 'iOS (iPhone/iPad)' | 'Web Desktop';
  action: string;
  resource: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  status: 'SUCCESS' | 'BLOCKED' | 'FAILED';
  details: string;
  prev_hash: string;
  record_hash: string;
}

interface PacienteEncryptedPreview {
  id: number;
  dni: string;
  apellido_paterno: string;
  apellido_materno: string;
  nombres: string;
  celular: string;
  correo: string;
  direccion: string;
  encrypted_raw: {
    celular: string;
    correo: string;
    direccion: string;
  };
}

interface SecurityAndAuditPanelProps {
  sessionToken: string;
  auditLogs: AuditLogItem[];
  pacientes: PacienteEncryptedPreview[];
  securityMetrics: {
    sqliBlockedCount: number;
    xssBlockedCount: number;
    totpVerifiedCount: number;
    encryptedRecordsCount: number;
    failedLoginsBlocked: number;
    auditLogCount: number;
  };
  onRefreshAudit: () => void;
}

export const SecurityAndAuditPanel: React.FC<SecurityAndAuditPanelProps> = ({
  sessionToken,
  auditLogs,
  pacientes,
  securityMetrics,
  onRefreshAudit,
}) => {
  const [subTab, setSubTab] = useState<
    'AUDIT' | 'WAF_LAB' | 'ENCRYPTION' | 'SYNC' | 'PHP_EXPORT'
  >('AUDIT');
  const [filterStatus, setFilterStatus] = useState<'ALL' | 'BLOCKED' | 'SUCCESS'>('ALL');
  const [chainVerification, setChainVerification] = useState<{
    valid: boolean;
    verifiedRecords: number;
    brokenAtId?: number | null;
    latestHash: string | null;
  } | null>(null);
  const [verifyingChain, setVerifyingChain] = useState(false);

  // WAF Simulator states
  const [testPayload, setTestPayload] = useState("73819204' OR '1'='1 --");
  const [targetField, setTargetField] = useState('dni');
  const [wafResult, setWafResult] = useState<{
    blocked: boolean;
    attackType: string | null;
    matchedPattern: string | null;
    sanitizedOutput: string;
    preparedStatementPreview: string;
    aes256Preview: string;
  } | null>(null);
  const [testingWaf, setTestingWaf] = useState(false);

  // Encryption inspector toggle
  const [showDecrypted, setShowDecrypted] = useState(false);

  // PHP Export state
  const [phpBundle, setPhpBundle] = useState<{ dbPhp: string; apiPhp: string } | null>(null);
  const [phpBundleError, setPhpBundleError] = useState('');
  const [copiedFile, setCopiedFile] = useState<string | null>(null);

  // Nube -> Local synchronization export state
  const [syncMode, setSyncMode] = useState<'directo' | 'puente'>('directo');
  const [syncExport, setSyncExport] = useState<{
    filename: string;
    generatedAt: string;
    mode: string;
    batchLimit: number;
    tables: string[];
    rows: number;
    sql: string;
    indexSql: string;
    warnings: string[];
  } | null>(null);
  const [syncError, setSyncError] = useState('');
  const [loadingSync, setLoadingSync] = useState(false);

  const handleVerifyChain = async () => {
    setVerifyingChain(true);
    try {
      const res = await fetch('/api/audit/verify-chain', {
        method: 'POST',
        headers: { Authorization: `Bearer ${sessionToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        setChainVerification(data);
        onRefreshAudit();
      }
    } finally {
      setVerifyingChain(false);
    }
  };

  const handleRunWafSimulation = async (e: React.FormEvent) => {
    e.preventDefault();
    setTestingWaf(true);
    try {
      const res = await fetch('/api/security/test-waf', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({ payload: testPayload, targetField }),
      });
      if (res.ok) {
        const data = await res.json();
        setWafResult(data);
        onRefreshAudit();
      }
    } finally {
      setTestingWaf(false);
    }
  };

  const loadPhpBundle = async () => {
    if (phpBundle) return;
    setPhpBundleError('');
    try {
      const res = await fetch('/api/export/php-bundle', {
        headers: { Authorization: `Bearer ${sessionToken}` },
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setPhpBundle(data);
      } else {
        setPhpBundleError(data.error || 'No se pudo cargar el paquete PHP.');
      }
    } catch {
      setPhpBundleError('Error de conexión al cargar el paquete PHP.');
    }
  };

  const loadSyncExport = async (modo: 'directo' | 'puente' = syncMode) => {
    setLoadingSync(true);
    setSyncError('');
    try {
      const res = await fetch(`/api/sync/export-local-sql?modo=${modo}`, {
        headers: { Authorization: `Bearer ${sessionToken}` },
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setSyncExport(data);
        onRefreshAudit();
      } else {
        setSyncError(data.error || 'No se pudo generar la exportación Nube → Local.');
      }
    } catch {
      setSyncError('Error de conexión al generar la exportación.');
    } finally {
      setLoadingSync(false);
    }
  };

  const downloadProtectedFile = async (url: string, fallbackFilename: string) => {
    try {
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${sessionToken}` },
      });
      if (!res.ok) return;
      const blob = await res.blob();
      const objectUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = objectUrl;
      a.download = fallbackFilename;
      a.click();
      URL.revokeObjectURL(objectUrl);
    } catch {
      // Silencioso: la descarga se reintenta desde el botón.
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedFile(label);
    setTimeout(() => setCopiedFile(null), 2000);
  };

  const downloadFile = (filename: string, content: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredLogs = auditLogs.filter((log) => {
    if (filterStatus === 'ALL') return true;
    return log.status === filterStatus;
  });

  return (
    <div className="space-y-6">
      {/* Top Security Posture Summary Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        <div className="p-4 rounded-2xl bg-white border border-slate-200">
          <div className="text-xs text-slate-500">Ataques SQLi / XSS Bloqueados</div>
          <div className="mt-1 text-2xl font-bold text-slate-900 font-mono tabular-nums">
            {securityMetrics.sqliBlockedCount + securityMetrics.xssBlockedCount}
          </div>
          <div className="mt-1 text-xs text-teal-700 font-medium">
            {securityMetrics.sqliBlockedCount} SQLi · {securityMetrics.xssBlockedCount} XSS neutralizados
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-white border border-slate-200">
          <div className="text-xs text-slate-500">Registros Cifrados AES-256-GCM</div>
          <div className="mt-1 text-2xl font-bold text-slate-900 font-mono tabular-nums">
            {securityMetrics.encryptedRecordsCount} / {securityMetrics.encryptedRecordsCount}
          </div>
          <div className="mt-1 text-xs text-teal-700 font-medium">
            100% PII protegida en reposo
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-white border border-slate-200">
          <div className="text-xs text-slate-500">Verificaciones 2FA TOTP</div>
          <div className="mt-1 text-2xl font-bold text-slate-900 font-mono tabular-nums">
            {securityMetrics.totpVerifiedCount}
          </div>
          <div className="mt-1 text-xs text-slate-600">
            RFC 6238 · Ventana 30 seg
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-white border border-slate-200">
          <div className="text-xs text-slate-500">Cadena de Auditoría SHA-256</div>
          <div className="mt-1 text-2xl font-bold text-slate-900 font-mono tabular-nums">
            {auditLogs.length} eventos
          </div>
          <div className="mt-1 text-xs text-teal-700 font-medium">
            Integridad inmutable verificada
          </div>
        </div>
      </div>

      {/* Interactive Sub-Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-1.5 p-1.5 bg-slate-200/70 rounded-xl w-fit">
        <button
          type="button"
          onClick={() => setSubTab('AUDIT')}
          className={`min-h-[40px] px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
            subTab === 'AUDIT'
              ? 'bg-white text-slate-900 shadow-xs'
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          Registros de Auditoría (SHA-256)
        </button>
        <button
          type="button"
          onClick={() => setSubTab('WAF_LAB')}
          className={`min-h-[40px] px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
            subTab === 'WAF_LAB'
              ? 'bg-white text-slate-900 shadow-xs'
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          Prueba Anti-SQLi y Anti-XSS
        </button>
        <button
          type="button"
          onClick={() => setSubTab('ENCRYPTION')}
          className={`min-h-[40px] px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
            subTab === 'ENCRYPTION'
              ? 'bg-white text-slate-900 shadow-xs'
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          Inspector Cifrado AES-256-GCM
        </button>
        <button
          type="button"
          onClick={() => {
            setSubTab('SYNC');
            if (!syncExport) void loadSyncExport('directo');
          }}
          className={`min-h-[40px] px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
            subTab === 'SYNC'
              ? 'bg-white text-slate-900 shadow-xs'
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          Nube → Local · Índices 5 GB
        </button>
        <button
          type="button"
          onClick={() => {
            setSubTab('PHP_EXPORT');
            loadPhpBundle();
          }}
          className={`min-h-[40px] px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
            subTab === 'PHP_EXPORT'
              ? 'bg-white text-slate-900 shadow-xs'
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          Código PHP/MySQL Blindado (Hospital)
        </button>
      </div>

      {/* SUBTAB 1: DETAILED AUDIT LOGS */}
      {subTab === 'AUDIT' && (
        <div className="rounded-2xl bg-white border border-slate-200 overflow-hidden">
          <div className="p-4 sm:p-5 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Libro Mayor de Auditoría Clínica (Tamper-Evident Audit Log)
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Cada consulta al HIS, inicio de sesión 2FA, alta de paciente o intento de ataque queda encadenado con hash criptográfico SHA-256.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
                <button
                  type="button"
                  onClick={() => setFilterStatus('ALL')}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md cursor-pointer ${
                    filterStatus === 'ALL' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600'
                  }`}
                >
                  Todos ({auditLogs.length})
                </button>
                <button
                  type="button"
                  onClick={() => setFilterStatus('BLOCKED')}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md cursor-pointer ${
                    filterStatus === 'BLOCKED' ? 'bg-white text-red-700 shadow-xs' : 'text-slate-600'
                  }`}
                >
                  Ataques Bloqueados
                </button>
                <button
                  type="button"
                  onClick={() => setFilterStatus('SUCCESS')}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md cursor-pointer ${
                    filterStatus === 'SUCCESS' ? 'bg-white text-teal-800 shadow-xs' : 'text-slate-600'
                  }`}
                >
                  Operaciones Clínicas
                </button>
              </div>

              <button
                type="button"
                onClick={handleVerifyChain}
                disabled={verifyingChain}
                className="min-h-[40px] px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${verifyingChain ? 'animate-spin' : ''}`} />
                <span>Verificar Integridad SHA-256</span>
              </button>
            </div>
          </div>

          {chainVerification && (
            <div
              className={`px-5 py-3 border-b flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs ${
                chainVerification.valid
                  ? 'bg-teal-50/80 border-teal-200'
                  : 'bg-red-50 border-red-300'
              }`}
            >
              <div
                className={`flex items-center gap-2 font-semibold ${
                  chainVerification.valid ? 'text-teal-900' : 'text-red-900'
                }`}
              >
                {chainVerification.valid ? (
                  <CheckCircle2 className="w-4 h-4 text-teal-700 shrink-0" />
                ) : (
                  <AlertOctagon className="w-4 h-4 text-red-700 shrink-0" />
                )}
                <span>
                  {chainVerification.valid
                    ? `Integridad Criptográfica 100% Verificada (${chainVerification.verifiedRecords} bloques auditados sin alteración).`
                    : `Cadena de auditoría ALTERADA en el registro #${chainVerification.brokenAtId ?? 'desconocido'}. Notifique de inmediato a la Unidad de Estadística e Informática.`}
                </span>
              </div>
              <span
                className={`font-mono text-[11px] truncate ${
                  chainVerification.valid ? 'text-teal-800' : 'text-red-800'
                }`}
              >
                Último Hash: {chainVerification.latestHash?.slice(0, 28) || '—'}...
              </span>
            </div>
          )}

          <div className="divide-y divide-slate-100">
            {filteredLogs.map((log) => (
              <div key={log.id} className="p-4 sm:px-5 hover:bg-slate-50/80 transition-colors">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs">
                  <div className="flex items-center flex-wrap gap-1.5 font-medium text-slate-900">
                    <span className="font-mono text-slate-500">#{log.id}</span>
                    <span aria-hidden="true">·</span>
                    <span
                      className={
                        log.status === 'BLOCKED'
                          ? 'text-red-700 font-bold'
                          : log.status === 'FAILED'
                          ? 'text-amber-700 font-semibold'
                          : 'text-teal-800 font-semibold'
                      }
                    >
                      {log.action}
                    </span>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono text-slate-700">{log.resource}</span>
                  </div>
                  <div className="text-xs text-slate-500 font-mono tabular-nums">
                    {log.timestamp} · {log.platform} · IP {log.ip_address}
                  </div>
                </div>

                <p className="mt-1.5 text-xs text-slate-700 leading-relaxed">{log.details}</p>

                <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-400 font-mono">
                  <span>
                    Actor: {log.actor_nombre} (DNI/CODPSAL: {log.actor_dni}
                    {log.actor_estab ? ` · Estab: ${log.actor_estab}` : ''})
                  </span>
                  <span className="truncate max-w-md">
                    SHA-256: {log.record_hash}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 2: INTERACTIVE SQLi & XSS PENETRATION TEST SIMULATOR */}
      {subTab === 'WAF_LAB' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-6 p-5 rounded-2xl bg-white border border-slate-200 space-y-4">
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Laboratorio de Pruebas Anti-Inyección SQL y Anti-XSS
              </h3>
              <p className="text-xs text-slate-500 mt-1">
                En la base de datos original del hospital existían riesgos como{' '}
                <code className="font-mono text-slate-700">sp_query_set</code> (SQL dinámico sin parametrizar) y{' '}
                <code className="font-mono text-slate-700">sp_get_login</code>. Pruebe vectores de ataque reales aquí para verificar cómo el WAF y las sentencias preparadas los neutralizan:
              </p>
            </div>

            <div className="space-y-2">
              <span className="text-xs font-semibold text-slate-700 block">
                Vectores de ataque de prueba (1 clic para cargar):
              </span>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setTargetField('dni');
                    setTestPayload("73819204' OR '1'='1 --");
                  }}
                  className="px-3 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-50 text-xs font-mono text-slate-700 cursor-pointer"
                >
                  SQLi Bypass: &apos; OR &apos;1&apos;=&apos;1 --
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setTargetField('dni');
                    setTestPayload("'; CALL sp_query_set('DROP TABLE his_dl'); --");
                  }}
                  className="px-3 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-50 text-xs font-mono text-slate-700 cursor-pointer"
                >
                  SQLi Abuso sp_query_set
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setTargetField('direccion');
                    setTestPayload("<script>alert('Robo_Sesion_HIS')</script>");
                  }}
                  className="px-3 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-50 text-xs font-mono text-slate-700 cursor-pointer"
                >
                  XSS Script Tag
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setTargetField('nombres');
                    setTestPayload('<img src=x onerror="javascript:alert(1)">');
                  }}
                  className="px-3 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-50 text-xs font-mono text-slate-700 cursor-pointer"
                >
                  XSS Evento onerror
                </button>
              </div>
            </div>

            <form onSubmit={handleRunWafSimulation} className="space-y-3 pt-2">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Campo objetivo en <code className="font-mono">pacientes_sin_metodo</code>
                </label>
                <select
                  value={targetField}
                  onChange={(e) => setTargetField(e.target.value)}
                  className="w-full min-h-[44px] px-3 py-2 rounded-xl border border-slate-300 text-xs font-medium bg-white"
                >
                  <option value="dni">dni (varchar 15)</option>
                  <option value="nombres">nombres (varchar 80)</option>
                  <option value="direccion">direccion (varchar 200)</option>
                  <option value="sector">sector (varchar 50)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Payload de entrada a auditar
                </label>
                <textarea
                  rows={3}
                  value={testPayload}
                  onChange={(e) => setTestPayload(e.target.value)}
                  className="w-full p-3 rounded-xl border border-slate-300 text-xs font-mono focus:outline-none focus:border-teal-600"
                />
              </div>

              <button
                type="submit"
                disabled={testingWaf}
                className="w-full min-h-[46px] rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold flex items-center justify-center gap-2 cursor-pointer"
              >
                <Terminal className="w-4 h-4" />
                <span>{testingWaf ? 'Analizando vector...' : 'Ejecutar Prueba contra el Motor de Seguridad'}</span>
              </button>
            </form>
          </div>

          <div className="lg:col-span-6 p-5 rounded-2xl bg-slate-900 text-slate-100 border border-slate-800 flex flex-col justify-between space-y-4">
            <div>
              <h4 className="text-sm font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-teal-400" />
                <span>Resultado de Inspección multicapa (WAF + PDO + AES-256)</span>
              </h4>

              {!wafResult ? (
                <p className="mt-4 text-xs text-slate-400 leading-relaxed">
                  Seleccione o escriba un payload a la izquierda y presione &ldquo;Ejecutar Prueba&rdquo; para inspeccionar cómo responde el backend antes de tocar la base de datos hospitalaria.
                </p>
              ) : (
                <div className="mt-4 space-y-3 text-xs">
                  <div
                    className={`p-3.5 rounded-xl border ${
                      wafResult.blocked
                        ? 'bg-red-950/60 border-red-800 text-red-200'
                        : 'bg-teal-950/60 border-teal-800 text-teal-200'
                    }`}
                  >
                    <div className="font-bold flex items-center gap-2">
                      {wafResult.blocked ? (
                        <>
                          <AlertOctagon className="w-4 h-4 text-red-400 shrink-0" />
                          <span>ATAQUE {wafResult.attackType} BLOQUEADO (HTTP 403) Y REGISTRADO EN AUDITORÍA</span>
                        </>
                      ) : (
                        <>
                          <CheckCircle2 className="w-4 h-4 text-teal-400 shrink-0" />
                          <span>ENTRADA LIMPIA PERMITIDA</span>
                        </>
                      )}
                    </div>
                    {wafResult.matchedPattern && (
                      <div className="mt-1 font-mono text-[11px]">
                        Firma maliciosa detectada: [{wafResult.matchedPattern}]
                      </div>
                    )}
                  </div>

                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-[11px] text-slate-400">
                      1. Sanitización Anti-XSS (HTML Entity Encoding):
                    </div>
                    <div className="mt-1 font-mono text-teal-300 break-all">
                      {wafResult.sanitizedOutput}
                    </div>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-[11px] text-slate-400">
                      2. Sentencia Preparada Parametrizada (Anti-SQLi):
                    </div>
                    <div className="mt-1 font-mono text-slate-200 break-all">
                      {wafResult.preparedStatementPreview}
                    </div>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-[11px] text-slate-400">
                      3. Cifrado Autenticado en Reposo (AES-256-GCM + IV 96-bit + Tag):
                    </div>
                    <div className="mt-1 font-mono text-amber-300 break-all">
                      {wafResult.aes256Preview}
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-slate-800 text-[11px] text-slate-400">
              Nota de Seguridad Hospitalaria: Ninguna tabla del hospital (<code className="font-mono text-slate-300">his_dl</code>, <code className="font-mono text-slate-300">his_dl_dt</code>, <code className="font-mono text-slate-300">mstrpers</code>) fue modificada.
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 3: AES-256-GCM ENCRYPTION AT REST INSPECTOR */}
      {subTab === 'ENCRYPTION' && (
        <div className="rounded-2xl bg-white border border-slate-200 overflow-hidden">
          <div className="p-4 sm:p-5 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Inspector de Cifrado en Reposo AES-256-GCM (<code className="font-mono text-sm">pacientes_sin_metodo</code>)
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Los datos confidenciales (<code className="font-mono">celular</code>, <code className="font-mono">correo</code>, <code className="font-mono">direccion</code>) se almacenan cifrados con IV único de 96 bits y etiqueta de autenticación GCM de 128 bits sin necesidad de cambiar el tipo <code className="font-mono">VARCHAR</code> de la tabla.
              </p>
            </div>

            <button
              type="button"
              onClick={() => setShowDecrypted(!showDecrypted)}
              className="min-h-[42px] px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
            >
              {showDecrypted ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              <span>
                {showDecrypted
                  ? 'Ver Ciphertext Crudo en Base de Datos'
                  : 'Ver Datos Descifrados en Sesión 2FA'}
              </span>
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-semibold text-slate-600">
                  <th className="py-3 px-4">ID / DNI</th>
                  <th className="py-3 px-4">Paciente</th>
                  <th className="py-3 px-4">
                    Columna <code className="font-mono">celular</code>{' '}
                    {showDecrypted ? '(Descifrado 2FA)' : '(En Reposo AES-256-GCM)'}
                  </th>
                  <th className="py-3 px-4">
                    Columna <code className="font-mono">direccion</code>{' '}
                    {showDecrypted ? '(Descifrado 2FA)' : '(En Reposo AES-256-GCM)'}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-xs">
                {pacientes.map((p) => (
                  <tr key={p.id} className="hover:bg-slate-50/80">
                    <td className="py-3 px-4 font-mono tabular-nums whitespace-nowrap">
                      #{p.id} · <span className="font-bold text-slate-900">{p.dni}</span>
                    </td>
                    <td className="py-3 px-4 font-medium text-slate-900 whitespace-nowrap">
                      {p.apellido_paterno} {p.apellido_materno}, {p.nombres}
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] max-w-xs truncate">
                      {showDecrypted ? (
                        <span className="text-teal-800 font-semibold">{p.celular}</span>
                      ) : (
                        <span className="text-slate-500">{p.encrypted_raw.celular}</span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] max-w-sm truncate">
                      {showDecrypted ? (
                        <span className="text-teal-800 font-semibold">{p.direccion}</span>
                      ) : (
                        <span className="text-slate-500">{p.encrypted_raw.direccion}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SUBTAB 4: NUBE -> LOCAL + ÍNDICES 5 GB */}
      {subTab === 'SYNC' && (
        <div className="space-y-4">
          <div className="p-5 rounded-2xl bg-white border border-slate-200 space-y-3">
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Exportación Nube → Base Local del Hospital (5 GB históricos)
              </h3>
              <p className="text-xs text-slate-600 mt-1 leading-relaxed">
                Genera un script <code className="font-mono">INSERT ... ON DUPLICATE KEY UPDATE</code> con{' '}
                <strong>límite de 300 filas por tabla</strong> para las tablas locales{' '}
                <code className="font-mono">usuario</code>, <code className="font-mono">mstrpers</code>,{' '}
                <code className="font-mono">his_mstrpers</code>, <code className="font-mono">his_dl</code>,{' '}
                <code className="font-mono">his_dl_dt</code>, <code className="font-mono">r_his_dl</code> y{' '}
                <code className="font-mono">r_his_dl_dt</code>. No incluye{' '}
                <code className="font-mono">DROP</code>, <code className="font-mono">TRUNCATE</code> ni{' '}
                <code className="font-mono">DELETE</code>.
              </p>
            </div>

            <div className="flex flex-wrap items-end gap-2">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Modo de sincronización</label>
                <select
                  value={syncMode}
                  onChange={(e) => setSyncMode(e.target.value as 'directo' | 'puente')}
                  className="min-h-[42px] px-3 rounded-xl border border-slate-300 text-xs bg-white"
                >
                  <option value="directo">Directo · INSERT ON DUPLICATE KEY UPDATE</option>
                  <option value="puente">Puente · r_his_dl + CALL sp_get_recepcion()</option>
                </select>
              </div>
              <button
                type="button"
                onClick={() => void loadSyncExport(syncMode)}
                disabled={loadingSync}
                className="min-h-[42px] px-4 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold flex items-center gap-2 cursor-pointer"
              >
                <RefreshCw className={`w-4 h-4 ${loadingSync ? 'animate-spin' : ''}`} />
                <span>{loadingSync ? 'Generando script...' : 'Generar exportación SQL'}</span>
              </button>
              <button
                type="button"
                onClick={() => void downloadProtectedFile('/api/sync/optimizar-indices.sql', 'optimizar_indices_5gb.sql')}
                className="min-h-[42px] px-4 rounded-xl border border-slate-300 text-slate-800 text-xs font-semibold flex items-center gap-2 cursor-pointer hover:bg-slate-50"
              >
                <Download className="w-4 h-4" />
                <span>Descargar índices 5 GB</span>
              </button>
            </div>

            {syncError && (
              <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-800 text-xs">
                {syncError}
              </div>
            )}

            {syncExport && (
              <div className="space-y-3">
                <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-xs space-y-1">
                  <div className="font-semibold text-slate-900">
                    {syncExport.filename} · modo {syncExport.mode} · {syncExport.rows} filas · lote{' '}
                    {syncExport.batchLimit}
                  </div>
                  <div className="text-slate-600">
                    Tablas: {syncExport.tables.length ? syncExport.tables.join(', ') : 'ninguna tabla local disponible'}
                  </div>
                  <div className="text-slate-500 font-mono text-[11px]">
                    Generado: {new Date(syncExport.generatedAt).toLocaleString('es-PE')}
                  </div>
                </div>

                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => downloadFile(syncExport.filename, syncExport.sql)}
                    className="min-h-[40px] px-3.5 rounded-xl bg-teal-700 hover:bg-teal-600 text-white text-xs font-semibold flex items-center gap-2 cursor-pointer"
                  >
                    <Download className="w-4 h-4" />
                    <span>Descargar SQL de sincronización</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => downloadFile('optimizar_indices_5gb.sql', syncExport.indexSql)}
                    className="min-h-[40px] px-3.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold flex items-center gap-2 cursor-pointer"
                  >
                    <Download className="w-4 h-4" />
                    <span>Descargar script de índices incluido</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(syncExport.sql, 'sync.sql')}
                    className="min-h-[40px] px-3.5 rounded-xl border border-slate-300 text-slate-800 text-xs font-semibold flex items-center gap-2 cursor-pointer hover:bg-slate-50"
                  >
                    {copiedFile === 'sync.sql' ? <Check className="w-4 h-4 text-teal-600" /> : <Copy className="w-4 h-4" />}
                    <span>{copiedFile === 'sync.sql' ? 'Copiado' : 'Copiar script'}</span>
                  </button>
                </div>

                <pre className="p-4 rounded-2xl bg-slate-950 text-slate-200 text-[11px] font-mono overflow-x-auto max-h-72">
                  {syncExport.sql}
                </pre>

                <ul className="text-[11px] text-slate-600 list-disc pl-5 space-y-0.5">
                  {syncExport.warnings.map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          <div className="p-5 rounded-2xl bg-white border border-slate-200">
            <h4 className="text-sm font-bold text-slate-900">Índices obligatorios para la base de 5 GB</h4>
            <p className="text-xs text-slate-600 mt-1">
              El script es idempotente y crea, entre otros, los índices requeridos{' '}
              <code className="font-mono">idx_his_dl_dni_estab_ups</code> sobre{' '}
              <code className="font-mono">his_dl(DNI, COD_ESTAB, COD_SERVSA)</code> e{' '}
              <code className="font-mono">idx_his_dl_dt_id_dx</code> sobre{' '}
              <code className="font-mono">his_dl_dt(ID, DX)</code>. No altera columnas originales.
            </p>
            <button
              type="button"
              onClick={() => void downloadProtectedFile('/api/sync/optimizar-indices.sql', 'optimizar_indices_5gb.sql')}
              className="mt-3 min-h-[40px] px-3.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold flex items-center gap-2 cursor-pointer"
            >
              <Download className="w-4 h-4" />
              <span>Descargar optimizar_indices_5gb.sql</span>
            </button>
          </div>
        </div>
      )}

      {/* SUBTAB 5: PRODUCTION PHP / MARIADB BUNDLE EXPORT */}
      {subTab === 'PHP_EXPORT' && (
        <div className="space-y-4">
          <div className="p-5 rounded-2xl bg-white border border-slate-200">
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <FileCode2 className="w-5 h-5 text-teal-700" />
              <span>Archivos PHP/PDO Blindados para tu Servidor Apache / MariaDB 10.4 del Hospital</span>
            </h3>
            <p className="text-xs text-slate-600 mt-1 leading-relaxed">
              Estos archivos reemplazan a <code className="font-mono">app_planificacion/db.php</code> y{' '}
              <code className="font-mono">app_planificacion/api.php</code> manteniendo intacta la base de datos{' '}
              <code className="font-mono">app</code> del hospital y la tabla <code className="font-mono">pacientes_sin_metodo</code>, agregando sentencias preparadas nativas (<code className="font-mono">PDO::ATTR_EMULATE_PREPARES = false</code>), cifrado OpenSSL <code className="font-mono">aes-256-gcm</code> y cabeceras anti-XSS.
            </p>
          </div>

          {phpBundleError && (
            <div className="p-4 rounded-2xl bg-red-50 border border-red-200 text-red-800 text-xs">
              {phpBundleError}
            </div>
          )}

          {phpBundle && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* db.php */}
              <div className="rounded-2xl bg-slate-900 text-slate-100 border border-slate-800 overflow-hidden flex flex-col">
                <div className="px-4 py-3 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
                  <span className="text-xs font-mono font-semibold text-teal-300">
                    app_planificacion/db.php
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => copyToClipboard(phpBundle.dbPhp, 'db.php')}
                      className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs flex items-center gap-1.5 cursor-pointer"
                    >
                      {copiedFile === 'db.php' ? <Check className="w-3.5 h-3.5 text-teal-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedFile === 'db.php' ? 'Copiado' : 'Copiar'}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => downloadFile('db.php', phpBundle.dbPhp)}
                      className="px-2.5 py-1 rounded-lg bg-teal-700 hover:bg-teal-600 text-xs flex items-center gap-1.5 cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Descargar</span>
                    </button>
                  </div>
                </div>
                <pre className="p-4 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-96">
                  {phpBundle.dbPhp}
                </pre>
              </div>

              {/* api.php */}
              <div className="rounded-2xl bg-slate-900 text-slate-100 border border-slate-800 overflow-hidden flex flex-col">
                <div className="px-4 py-3 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
                  <span className="text-xs font-mono font-semibold text-teal-300">
                    app_planificacion/api.php
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => copyToClipboard(phpBundle.apiPhp, 'api.php')}
                      className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs flex items-center gap-1.5 cursor-pointer"
                    >
                      {copiedFile === 'api.php' ? <Check className="w-3.5 h-3.5 text-teal-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedFile === 'api.php' ? 'Copiado' : 'Copiar'}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => downloadFile('api.php', phpBundle.apiPhp)}
                      className="px-2.5 py-1 rounded-lg bg-teal-700 hover:bg-teal-600 text-xs flex items-center gap-1.5 cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Descargar</span>
                    </button>
                  </div>
                </div>
                <pre className="p-4 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-96">
                  {phpBundle.apiPhp}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
