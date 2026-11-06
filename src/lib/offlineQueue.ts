/**
 * Cola offline cifrada para captaciones de campo.
 *
 * Los datos clínicos se guardan en localStorage CIFRADOS con AES-256-GCM
 * (Web Crypto). La clave de dispositivo es aleatoria y se conserva en el
 * navegador; nunca se envía al servidor. Al recuperar señal, la cola se
 * reenvía automáticamente a /api/pacientes con el Bearer Token de la sesión.
 */

const QUEUE_KEY = 'planificahis.offline.queue.v1';
const DEVICE_KEY = 'planificahis.offline.device-key.v1';

export interface OfflinePatientPayload {
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
  estado_paciente: string;
  codpsal_obstetra: string;
  pase_ups?: boolean;
  atencion_99208?: boolean;
}

interface EncryptedQueueItem {
  id: string;
  createdAt: string;
  iv: string;
  ciphertext: string;
}

export interface QueuedPatient {
  id: string;
  createdAt: string;
  payload: OfflinePatientPayload;
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function getOrCreateDeviceSecret(): Uint8Array {
  const existing = localStorage.getItem(DEVICE_KEY);
  if (existing) {
    try {
      return fromBase64(existing);
    } catch {
      // Si el valor está corrupto se regenera la clave (la cola previa no se
      // podrá descifrar; se elimina para no bloquear la app).
      localStorage.removeItem(QUEUE_KEY);
    }
  }
  const secret = crypto.getRandomValues(new Uint8Array(32));
  localStorage.setItem(DEVICE_KEY, toBase64(secret));
  return secret;
}

async function getAesKey(): Promise<CryptoKey> {
  const secret = getOrCreateDeviceSecret();
  // Use the underlying ArrayBuffer of the Uint8Array, cast explicitly
  const material = await crypto.subtle.importKey('raw', secret.buffer as ArrayBuffer, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ]);
  return material;
}

function readRawQueue(): EncryptedQueueItem[] {
  try {
    const raw = localStorage.getItem(QUEUE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as EncryptedQueueItem[]) : [];
  } catch {
    return [];
  }
}

function writeRawQueue(items: EncryptedQueueItem[]): void {
  localStorage.setItem(QUEUE_KEY, JSON.stringify(items.slice(-200)));
}

async function encryptPayload(payload: OfflinePatientPayload): Promise<{ iv: string; ciphertext: string }> {
  const key = await getAesKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(payload));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  return {
    iv: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(encrypted)),
  };
}

async function decryptPayload(item: EncryptedQueueItem): Promise<OfflinePatientPayload | null> {
  try {
    const key = await getAesKey();
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(item.iv as any) },
      key,
      (fromBase64(item.ciphertext) as any)
    );
    return JSON.parse(new TextDecoder().decode(decrypted)) as OfflinePatientPayload;
  } catch {
    return null;
  }
}

export function offlineQueueSupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof localStorage !== 'undefined' &&
    !!window.crypto?.subtle
  );
}

export async function queueOfflinePatient(payload: OfflinePatientPayload): Promise<QueuedPatient> {
  const id =
    typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const createdAt = new Date().toISOString();
  const encrypted = await encryptPayload(payload);
  const items = readRawQueue();
  items.push({ id, createdAt, ...encrypted });
  writeRawQueue(items);
  return { id, createdAt, payload };
}

export function getOfflineQueueCount(): number {
  return readRawQueue().length;
}

export async function getOfflineQueue(): Promise<QueuedPatient[]> {
  const result: QueuedPatient[] = [];
  for (const item of readRawQueue()) {
    const payload = await decryptPayload(item);
    if (payload) result.push({ id: item.id, createdAt: item.createdAt, payload });
  }
  return result;
}

export async function clearOfflineQueue(): Promise<void> {
  localStorage.removeItem(QUEUE_KEY);
}

export interface SyncQueueResult {
  synced: number;
  pending: number;
  failed: number;
  authError: boolean;
  networkError: boolean;
}

/**
 * Reenvía la cola al backend. Devuelve el resumen para mostrar al usuario.
 * No reintenta indefinidamente: deja los pendientes para el próximo evento
 * `online` o el próximo intervalo de sincronización.
 */
export async function syncOfflineQueue(token: string, endpoint = '/api/pacientes'): Promise<SyncQueueResult> {
  const result: SyncQueueResult = {
    synced: 0,
    pending: 0,
    failed: 0,
    authError: false,
    networkError: false,
  };
  if (!token || !offlineQueueSupported()) {
    result.pending = getOfflineQueueCount();
    return result;
  }

  const rawItems = readRawQueue();
  const remaining: EncryptedQueueItem[] = [];

  for (const item of rawItems) {
    const payload = await decryptPayload(item);
    if (!payload) {
      // Elemento corrupto o cifrado con otra clave: se descarta.
      result.failed += 1;
      continue;
    }
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        result.synced += 1;
        continue;
      }
      if (res.status === 401 || res.status === 403) {
        result.authError = true;
        remaining.push(item);
        break;
      }
      result.failed += 1;
      remaining.push(item);
    } catch {
      result.networkError = true;
      remaining.push(item);
      break;
    }
  }

  writeRawQueue(remaining);
  result.pending = remaining.length;
  return result;
}
