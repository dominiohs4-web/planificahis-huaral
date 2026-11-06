import express, { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import zlib from 'zlib';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import {
  ESTABLECIMIENTOS_RED,
  ESTABLECIMIENTOS_POR_DISTRITO,
  TOTAL_ESTABLECIMIENTOS,
  getEstablecimiento,
  nombreEstablecimiento,
  codigoEstablecimientoCanonico,
} from './src/data/establecimientos';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================================================
// 1. CRYPTOGRAPHIC ENGINE: AES-256-GCM, TOTP 2FA (RFC 6238), SHA-256 AUDIT CHAIN
// ============================================================================
const MASTER_KEY_SECRET = process.env.ENCRYPTION_SECRET || 'hospital-san-juan-bautista-huaral-aes256-key-2026';
// Misma derivación que db.php: SHA-256 de la clave maestra. Permite descifrar
// los datos capturados indistintamente desde Node o PHP.
const AES_KEY = crypto.createHash('sha256').update(MASTER_KEY_SECRET).digest(); // 256-bit key
const SESSION_HMAC_KEY = crypto.scryptSync(MASTER_KEY_SECRET, 'huaral-session-hmac-v1', 32);

export function encryptFieldAES256(plaintext: string | null | undefined): string {
  if (!plaintext) return '';
  if (plaintext.startsWith('enc:gcm:')) return plaintext;
  const iv = crypto.randomBytes(12); // 96-bit IV recommended for AES-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `enc:gcm:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

export function decryptFieldAES256(ciphertext: string | null | undefined): string {
  if (!ciphertext) return '';
  if (!ciphertext.startsWith('enc:gcm:')) return ciphertext;
  try {
    const parts = ciphertext.split(':');
    if (parts.length !== 5) return '[ERROR_FORMATO_CIFRADO]';
    const iv = Buffer.from(parts[2], 'hex');
    const authTag = Buffer.from(parts[3], 'hex');
    const encryptedText = Buffer.from(parts[4], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', AES_KEY, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
    return decrypted.toString('utf8');
  } catch {
    return '[DATO_PROTEGIDO_TAG_INVALIDO]';
  }
}

export function hashPasswordScrypt(password: string, salt = 'hsjb-huaral-2026'): string {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

// TOTP 6-digit generator (RFC 6238 - 30s step)
export function generateTOTP(secret: string, windowOffset = 0): { code: string; remainingSeconds: number } {
  const step = 30;
  const nowSec = Math.floor(Date.now() / 1000);
  const counter = Math.floor(nowSec / step) + windowOffset;
  const remainingSeconds = step - (nowSec % step);

  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigInt64BE(BigInt(counter), 0);

  const hmac = crypto.createHmac('sha1', Buffer.from(secret, 'utf8')).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const otp = (binary % 1000000).toString().padStart(6, '0');
  return { code: otp, remainingSeconds };
}

export function verifyTOTP(secret: string, inputCode: string): boolean {
  const clean = String(inputCode).trim();
  if (!/^\d{6}$/.test(clean)) return false;
  for (const offset of [-1, 0, 1]) {
    if (generateTOTP(secret, offset).code === clean) {
      return true;
    }
  }
  return false;
}

// ============================================================================
// 2. PROGRAMMATIC PNG ICON GENERATOR FOR PWA COMPLIANCE (iOS & Android)
// ============================================================================
function createValidPngIcon(width: number, height: number, isMaskable = false): Buffer {
  const rawData = Buffer.alloc(height * (1 + width * 4));
  const cx = width / 2;
  const cy = height / 2;
  const crossArmLength = width * (isMaskable ? 0.22 : 0.28);
  const crossThickness = width * (isMaskable ? 0.08 : 0.1);
  const ringRadius = width * (isMaskable ? 0.31 : 0.37);

  for (let y = 0; y < height; y++) {
    const rowStart = y * (1 + width * 4);
    rawData[rowStart] = 0;
    for (let x = 0; x < width; x++) {
      const pxOffset = rowStart + 1 + x * 4;
      const dx = x - cx;
      const dy = y - cy;
      const dist = Math.sqrt(dx * dx + dy * dy);

      const t = (x + y) / (width + height);
      let r = Math.round(15 * (1 - t) + 15 * t);
      let g = Math.round(23 * (1 - t) + 118 * t);
      let b = Math.round(42 * (1 - t) + 110 * t);

      if (Math.abs(dist - ringRadius) < width * 0.018) {
        r = 45;
        g = 212;
        b = 191;
      }

      const inVerticalBar = Math.abs(dx) <= crossThickness / 2 && Math.abs(dy) <= crossArmLength;
      const inHorizontalBar = Math.abs(dy) <= crossThickness / 2 && Math.abs(dx) <= crossArmLength;
      if (inVerticalBar || inHorizontalBar) {
        r = 255;
        g = 255;
        b = 255;
      }

      rawData[pxOffset] = r;
      rawData[pxOffset + 1] = g;
      rawData[pxOffset + 2] = b;
      rawData[pxOffset + 3] = 255;
    }
  }

  const crcTable = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    crcTable[n] = c >>> 0;
  }

  function crc32(buf: Buffer): number {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) {
      c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    }
    return (c ^ 0xffffffff) >>> 0;
  }

  function makeChunk(type: string, data: Buffer): Buffer {
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(data.length, 0);
    const typeBuf = Buffer.from(type, 'ascii');
    const crcBuf = Buffer.alloc(4);
    crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
    return Buffer.concat([lenBuf, typeBuf, data, crcBuf]);
  }

  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const compressed = zlib.deflateSync(rawData);
  return Buffer.concat([
    signature,
    makeChunk('IHDR', ihdr),
    makeChunk('IDAT', compressed),
    makeChunk('IEND', Buffer.alloc(0)),
  ]);
}

function ensurePwaIconsExist() {
  const publicDir = path.resolve(__dirname, 'public');
  if (!fs.existsSync(publicDir)) {
    fs.mkdirSync(publicDir, { recursive: true });
  }
  const icons: Array<{ name: string; size: number; maskable: boolean }> = [
    { name: 'apple-touch-icon.png', size: 180, maskable: false },
    { name: 'pwa-192x192.png', size: 192, maskable: false },
    { name: 'pwa-512x512.png', size: 512, maskable: false },
    { name: 'pwa-maskable-512x512.png', size: 512, maskable: true },
  ];
  for (const icon of icons) {
    const targetPath = path.join(publicDir, icon.name);
    if (!fs.existsSync(targetPath)) {
      fs.writeFileSync(targetPath, createValidPngIcon(icon.size, icon.size, icon.maskable));
    }
  }
}

// ============================================================================
// 3. HOSPITAL SAN JUAN BAUTISTA HUARAL DATABASE SCHEMA (`app` - 10.4.32-MariaDB)
//    Strictly preserves hospital schema (`his_dl`, `his_dl_dt`, `mstrpers`,
//    `establec`, `dist`, `usuario`, `enfermedades`) + `pacientes_sin_metodo`
// ============================================================================

export interface PacienteSinMetodoRow {
  id: number;
  dni: string;
  apellido_paterno: string;
  apellido_materno: string;
  nombres: string;
  edad: number;
  celular: string; // Stored encrypted at rest (AES-256-GCM)
  correo: string; // Stored encrypted at rest (AES-256-GCM)
  distrito: string;
  direccion: string; // Stored encrypted at rest (AES-256-GCM)
  sector: string;
  estado_paciente:
    | 'INSATISFECHA_SIN_METODO'
    | 'CAPTADA_CON_METODO'
    | 'SEGUIMIENTO_DOMICILIARIO'
    | 'CONSEJERIA_REALIZADA'
    | 'RECHAZA_METODO';
  codpsal_obstetra: string;
  cod_estab?: string;
  atencion_99208?: boolean;
  fecha_registro: string;
}

export interface HisDlRow {
  ID: string;
  id_cita: string;
  COD_ESTAB: string;
  ANO: number;
  MES: number;
  DIA: number;
  NOM_LOTE: string;
  NUM_PAG: number;
  NUM_REG: number;
  FICHAFAM: string;
  UBIGEO: string;
  EDAD: number;
  TIP_EDAD: string;
  SEXO: string;
  CODPSAL: string;
  DIGITA: string;
  COD_SERVSA: string;
  DNI: string;
  Apellido_p: string;
  Apellido_m: string;
  Pnombre: string;
  Dnombres: string;
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
}

export interface HisDlDtRow {
  ID: string;
  ID_CITA: string;
  num: number;
  DX: string;
  TDX: 'D' | 'P' | 'R';
  LDX: string;
  cod_estab: string;
  dia: number;
  mes: number;
  ano: number;
  id_dosis: string | null;
  Alerta: string | null;
  fecha_reg: string;
}

export interface MstrPersRow {
  CODPSAL: string;
  NOMBRE: string;
  COD_ESTAB: string;
  COD_PROF: string;
  COD_COND: string;
  COD_COL: string;
  COD_DOC: string;
  FECHA_ING: string;
  ESTADO: string;
}

export interface UsuarioHospitalRow {
  dni: string;
  nombre1: string;
  nombre2: string;
  apaterno: string;
  amaterno: string;
  passwordx: string;
  email: string;
  celular: string;
  nivelid: number;
  nivelcd: string;
  tipo: number;
  estado: number;
  fechacreacion: string;
  totp_secret: string;
  rol_descripcion: string;
  cod_estab: string;
}

export interface AuditLogEntry {
  id: number;
  timestamp: string;
  actor_dni: string;
  actor_estab: string;
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

// Establishments of Red de Salud Huaral - Chancay (DIRESA Lima)
const ESTABLECIMIENTOS_DB_LEGACY = [
  {
    COD_ESTAB: '000005481',
    DESC_ESTAB: 'HOSPITAL SAN JUAN BAUTISTA HUARAL (II-2)',
    DESC_RED: 'RED DE SALUD HUARAL - CHANCAY',
    DESC_MICRO: 'MICRORED HUARAL',
    COD_DISA: '15',
    COD_RED: '06',
    COD_MIC: '01',
    UBIGEO: '150601',
  },
  {
    COD_ESTAB: '000005482',
    DESC_ESTAB: 'C.S. BASE HUARAL (I-3)',
    DESC_RED: 'RED DE SALUD HUARAL - CHANCAY',
    DESC_MICRO: 'MICRORED HUARAL',
    COD_DISA: '15',
    COD_RED: '06',
    COD_MIC: '01',
    UBIGEO: '150601',
  },
  {
    COD_ESTAB: '000005485',
    DESC_ESTAB: 'C.S. PERALVILLO (I-3)',
    DESC_RED: 'RED DE SALUD HUARAL - CHANCAY',
    DESC_MICRO: 'MICRORED PERALVILLO',
    COD_DISA: '15',
    COD_RED: '06',
    COD_MIC: '02',
    UBIGEO: '150605',
  },
  {
    COD_ESTAB: '000005489',
    DESC_ESTAB: 'C.S. AUCALLAMA (I-3)',
    DESC_RED: 'RED DE SALUD HUARAL - CHANCAY',
    DESC_MICRO: 'MICRORED AUCALLAMA',
    COD_DISA: '15',
    COD_RED: '06',
    COD_MIC: '03',
    UBIGEO: '150604',
  },
  {
    COD_ESTAB: '000005492',
    DESC_ESTAB: 'P.S. HUANDO (I-2)',
    DESC_RED: 'RED DE SALUD HUARAL - CHANCAY',
    DESC_MICRO: 'MICRORED HUARAL',
    COD_DISA: '15',
    COD_RED: '06',
    COD_MIC: '01',
    UBIGEO: '150601',
  },
];

// Catálogo oficial vigente: 53 IPRESS/RENIPRESS de la Red Huaral-Chancay.
// `ESTABLECIMIENTOS_DB_LEGACY` se conserva solo como referencia histórica.
const ESTABLECIMIENTOS_DB = ESTABLECIMIENTOS_RED;
const DISTRITOS_DB = [
  { UBIGEO: '150601', COD_DPTO: '15', COD_PROV: '06', COD_DIST: '01', DESC_DIST: 'HUARAL' },
  { UBIGEO: '150605', COD_DPTO: '15', COD_PROV: '06', COD_DIST: '05', DESC_DIST: 'CHANCAY' },
  { UBIGEO: '150604', COD_DPTO: '15', COD_PROV: '06', COD_DIST: '04', DESC_DIST: 'AUCALLAMA' },
  { UBIGEO: '150606', COD_DPTO: '15', COD_PROV: '06', COD_DIST: '06', DESC_DIST: 'IHUARI' },
  { UBIGEO: '150602', COD_DPTO: '15', COD_PROV: '06', COD_DIST: '02', DESC_DIST: 'ATAVILLOS ALTO' },
  { UBIGEO: '150603', COD_DPTO: '15', COD_PROV: '06', COD_DIST: '03', DESC_DIST: 'ATAVILLOS BAJO' },
  { UBIGEO: '150607', COD_DPTO: '15', COD_PROV: '06', COD_DIST: '07', DESC_DIST: 'LAMPIAN' },
  { UBIGEO: '150608', COD_DPTO: '15', COD_PROV: '06', COD_DIST: '08', DESC_DIST: 'PACARAOS' },
  { UBIGEO: '150609', COD_DPTO: '15', COD_PROV: '06', COD_DIST: '09', DESC_DIST: 'SAN MIGUEL DE ACOS' },
  { UBIGEO: '150610', COD_DPTO: '15', COD_PROV: '06', COD_DIST: '10', DESC_DIST: 'SANTA CRUZ DE ANDAMARCA' },
  { UBIGEO: '150611', COD_DPTO: '15', COD_PROV: '06', COD_DIST: '11', DESC_DIST: 'SUMBILCA' },
  { UBIGEO: '150612', COD_DPTO: '15', COD_PROV: '06', COD_DIST: '12', DESC_DIST: 'VEINTISIETE DE NOVIEMBRE' },
];

// Official MINSA / DIRESA Family Planning Codes (`enfermedades` / CIE-10 & CPMS)
// Includes cycle days (30 days monthly ampoule, 90 days trimestral ampoule, 1095 days implant) as explained in the video
export const ENFERMEDADES_CIE10_DB = [
  {
    Codigo: 101,
    COD_ENF: '90782',
    DESC_ENF: 'ADMINISTRACION DE INYECTABLE ANTICONCEPTIVO MENSUAL (AMPOLLA 30 DIAS)',
    SEXO: 'F',
    MIN_EDAD: 12,
    MAX_EDAD: 55,
    ESTA: 'A',
    CICLO_DIAS: 30,
    METODO_CORTO: 'Ampolla Mensual (Cada 30 días)',
  },
  {
    Codigo: 102,
    COD_ENF: 'Z304',
    DESC_ENF: 'SUPERVISION DE ANTICONCEPTIVO INYECTABLE TRIMESTRAL (MEDROXIPROGESTERONA 90 DIAS)',
    SEXO: 'F',
    MIN_EDAD: 12,
    MAX_EDAD: 55,
    ESTA: 'A',
    CICLO_DIAS: 90,
    METODO_CORTO: 'Ampolla Trimestral (Cada 90 días)',
  },
  {
    Codigo: 103,
    COD_ENF: 'Z301',
    DESC_ENF: 'INSERCION DE DISPOSITIVO ANTICONCEPTIVO (IMPLANTE SUBDERMICO / DIU)',
    SEXO: 'F',
    MIN_EDAD: 12,
    MAX_EDAD: 55,
    ESTA: 'A',
    CICLO_DIAS: 1095,
    METODO_CORTO: 'Implante Subdérmico / DIU LARC',
  },
  {
    Codigo: 104,
    COD_ENF: '99208',
    DESC_ENF: 'ATENCION EN PLANIFICACION FAMILIAR Y SALUD REPRODUCTIVA',
    SEXO: 'B',
    MIN_EDAD: 10,
    MAX_EDAD: 65,
    ESTA: 'A',
    CICLO_DIAS: 30,
    METODO_CORTO: 'Control Planificación Familiar',
  },
  {
    Codigo: 105,
    COD_ENF: 'Z300',
    DESC_ENF: 'CONSEJO Y ASESORAMIENTO GENERAL SOBRE LA ANTICONCEPCION',
    SEXO: 'B',
    MIN_EDAD: 10,
    MAX_EDAD: 60,
    ESTA: 'A',
    CICLO_DIAS: 0,
    METODO_CORTO: 'Sólo Consejería (Sin método aplicado)',
  },
  {
    Codigo: 106,
    COD_ENF: 'Z391',
    DESC_ENF: 'ATENCION Y EXAMEN DE MADRE EN PERIODO DE LACTANCIA (PUERPERIO)',
    SEXO: 'F',
    MIN_EDAD: 12,
    MAX_EDAD: 55,
    ESTA: 'A',
    CICLO_DIAS: 0,
    METODO_CORTO: 'Puérpera sin método activo',
  },
];

let MSTRPERS_DB: MstrPersRow[] = [
  {
    CODPSAL: '41829304',
    NOMBRE: 'LIC. OBST. ROXANA (COORDINADORA PLANIFICACION FAMILIAR HUARAL)',
    COD_ESTAB: '000005481',
    COD_PROF: '04',
    COD_COND: '01',
    COD_COL: '04',
    COD_DOC: '1',
    FECHA_ING: '2018-04-10',
    ESTADO: 'A',
  },
  {
    CODPSAL: '44910283',
    NOMBRE: 'OBST. CARMEN ROSA MENDOZA (CAPTACION CAMPO HUARAL)',
    COD_ESTAB: '000005481',
    COD_PROF: '04',
    COD_COND: '01',
    COD_COL: '04',
    COD_DOC: '1',
    FECHA_ING: '2020-02-15',
    ESTADO: 'A',
  },
  {
    CODPSAL: '46109284',
    NOMBRE: 'OBST. MILAGROS PINEDO (C.S. PERALVILLO - HUARAL)',
    COD_ESTAB: '000005485',
    COD_PROF: '04',
    COD_COND: '01',
    COD_COL: '04',
    COD_DOC: '1',
    FECHA_ING: '2021-06-01',
    ESTADO: 'A',
  },
  {
    CODPSAL: '70192834',
    NOMBRE: 'ING. LUIS SANTISTEBAN / UNIDAD ESTADISTICA E INFORMATICA HUARAL',
    COD_ESTAB: '000005481',
    COD_PROF: '01',
    COD_COND: '01',
    COD_COL: '01',
    COD_DOC: '1',
    FECHA_ING: '2022-01-10',
    ESTADO: 'A',
  },
];

let USUARIOS_DB: UsuarioHospitalRow[] = [
  {
    dni: '41829304',
    nombre1: 'ROXANA',
    nombre2: 'ELIZABETH',
    apaterno: 'VILLANUEVA',
    amaterno: 'RAMOS',
    passwordx: hashPasswordScrypt('Obstetra2026!'),
    email: 'roxana.obstetricia@hospitalhuaral.gob.pe',
    celular: '987112233',
    nivelid: 2,
    nivelcd: '000005481',
    tipo: 2,
    estado: 1,
    fechacreacion: '2026-01-15 08:30:00',
    totp_secret: 'HUARAL-ROXANA-41829304',
    rol_descripcion: 'Coordinadora Planificación Familiar — Hosp. San Juan Bautista Huaral',
    cod_estab: '000005481',
  },
  {
    dni: '44910283',
    nombre1: 'CARMEN',
    nombre2: 'ROSA',
    apaterno: 'MENDOZA',
    amaterno: 'VARGAS',
    passwordx: hashPasswordScrypt('Obstetra2026!'),
    email: 'cmendoza@hospitalhuaral.gob.pe',
    celular: '944819201',
    nivelid: 2,
    nivelcd: '000005481',
    tipo: 2,
    estado: 1,
    fechacreacion: '2026-02-10 09:00:00',
    totp_secret: 'HUARAL-CARMEN-44910283',
    rol_descripcion: 'Obstetra de Campo — Hospital San Juan Bautista Huaral',
    cod_estab: '000005481',
  },
  {
    dni: '70192834',
    nombre1: 'LUIS',
    nombre2: 'ALBERTO',
    apaterno: 'SANTISTEBAN',
    amaterno: 'ROJAS',
    passwordx: hashPasswordScrypt('AdminHIS2026!'),
    email: 'luissantisteban005@gmail.com',
    celular: '987654321',
    nivelid: 1,
    nivelcd: '1506',
    tipo: 1,
    estado: 1,
    fechacreacion: '2026-01-01 08:00:00',
    totp_secret: 'HUARAL-ADMIN-70192834',
    rol_descripcion: 'Estadística y Cómputo (Ing. Alex / Luis) — Hosp. Huaral',
    cod_estab: '000005481',
  },
];

// Existing Hospital Attendance Records (`his_dl` and `his_dl_dt`) shared by DIRESA / MINSA on the Statistics PC
const HIS_DL_DB: HisDlRow[] = [
  // 1. Paciente GERALDINE (Ejemplo del video min 00:56: "Paciente Gerald, su ampolla mensual le toca tal fecha")
  {
    ID: '000005481202609000101',
    id_cita: 'CITA00981201',
    COD_ESTAB: '000005481',
    ANO: 2026,
    MES: 9,
    DIA: 18,
    NOM_LOTE: 'H01',
    NUM_PAG: 12,
    NUM_REG: 4,
    FICHAFAM: 'FF-20918',
    UBIGEO: '150601',
    EDAD: 25,
    TIP_EDAD: 'A',
    SEXO: 'F',
    CODPSAL: '41829304',
    DIGITA: '80192011',
    COD_SERVSA: '302304',
    DNI: '72910485',
    Apellido_p: 'RODRIGUEZ',
    Apellido_m: 'COLLANTES',
    Pnombre: 'GERALDINE',
    Dnombres: 'GERALDINE PAOLA',
    HCLFAM: 'HC-48210',
    hmb: 12.6,
    Fecha_Ultima_Regla: '2026-09-10',
    PESO: '57.2',
    TALLA: '156',
    IMC: '23.5',
    FECHA_NAC: '2001-05-14',
    condicion_gestante: 'NO GESTANTE',
    gruporiesgo_desc: 'USUARIA ACTIVA AMPOLLA MENSUAL (CADA 30 DIAS)',
    fecha_reg: '2026-09-18',
  },
  // 2. Paciente con Ampolla Mensual que le toca MAÑANA (para el reporte diario de la Lic. Roxana)
  {
    ID: '000005481202609000102',
    id_cita: 'CITA00981202',
    COD_ESTAB: '000005481',
    ANO: 2026,
    MES: 9,
    DIA: 19,
    NOM_LOTE: 'H02',
    NUM_PAG: 8,
    NUM_REG: 11,
    FICHAFAM: 'FF-31044',
    UBIGEO: '150601',
    EDAD: 28,
    TIP_EDAD: 'A',
    SEXO: 'F',
    CODPSAL: '41829304',
    DIGITA: '80192011',
    COD_SERVSA: '302304',
    DNI: '47829103',
    Apellido_p: 'CHAVEZ',
    Apellido_m: ' BUSTAMANTE',
    Pnombre: 'MARIA',
    Dnombres: 'MARIA FERNANDA',
    HCLFAM: 'HC-51023',
    hmb: 12.8,
    Fecha_Ultima_Regla: '2026-09-08',
    PESO: '61.0',
    TALLA: '158',
    IMC: '24.4',
    FECHA_NAC: '1998-07-22',
    condicion_gestante: 'NO GESTANTE',
    gruporiesgo_desc: 'USUARIA ACTIVA AMPOLLA MENSUAL (CADA 30 DIAS)',
    fecha_reg: '2026-09-19',
  },
  // 3. Paciente en HIS con Abandono de Inyectable Trimestral (> 90 días) -> Insatisfecha / Requiere seguimiento
  {
    ID: '000005485202607000103',
    id_cita: 'CITA00981203',
    COD_ESTAB: '000005485',
    ANO: 2026,
    MES: 7,
    DIA: 10,
    NOM_LOTE: 'P04',
    NUM_PAG: 3,
    NUM_REG: 2,
    FICHAFAM: 'FF-10492',
    UBIGEO: '150605',
    EDAD: 31,
    TIP_EDAD: 'A',
    SEXO: 'F',
    CODPSAL: '46109284',
    DIGITA: '80192011',
    COD_SERVSA: '302304',
    DNI: '46920183',
    Apellido_p: 'HUAMAN',
    Apellido_m: 'QUISPE',
    Pnombre: 'ROSA',
    Dnombres: 'ROSA ANGELICA',
    HCLFAM: 'HC-44912',
    hmb: 12.1,
    Fecha_Ultima_Regla: '2026-07-02',
    PESO: '63.5',
    TALLA: '155',
    IMC: '26.4',
    FECHA_NAC: '1995-02-19',
    condicion_gestante: 'NO GESTANTE',
    gruporiesgo_desc: 'AMPOLLA TRIMESTRAL VENCIDA (NO ACUDIO A SU CITA)',
    fecha_reg: '2026-07-10',
  },
  // 4. Paciente Puérpera atendida en Hospital Huaral SIN método elegido (para captar en campo)
  {
    ID: '000005481202610000105',
    id_cita: 'CITA00981205',
    COD_ESTAB: '000005481',
    ANO: 2026,
    MES: 10,
    DIA: 14,
    NOM_LOTE: 'H05',
    NUM_PAG: 4,
    NUM_REG: 9,
    FICHAFAM: 'FF-61209',
    UBIGEO: '150601',
    EDAD: 22,
    TIP_EDAD: 'A',
    SEXO: 'F',
    CODPSAL: '44910283',
    DIGITA: '80192011',
    COD_SERVSA: '302304',
    DNI: '74501928',
    Apellido_p: 'GARAY',
    Apellido_m: 'SOLORZANO',
    Pnombre: 'KAREN',
    Dnombres: 'KAREN LIZBETH',
    HCLFAM: 'HC-66301',
    hmb: 11.4,
    Fecha_Ultima_Regla: '2026-09-14',
    PESO: '54.2',
    TALLA: '153',
    IMC: '23.1',
    FECHA_NAC: '2004-06-30',
    condicion_gestante: 'NO GESTANTE - PUERPERA',
    gruporiesgo_desc: 'PUERPERA SIN METODO ACTIVO (INSATISFECHA)',
    fecha_reg: '2026-10-14',
  },
  // 5. Paciente Usuaria Satisfecha con Implante Subdérmico vigente en HIS
  {
    ID: '000005481202608000104',
    id_cita: 'CITA00981204',
    COD_ESTAB: '000005481',
    ANO: 2026,
    MES: 8,
    DIA: 15,
    NOM_LOTE: 'H03',
    NUM_PAG: 15,
    NUM_REG: 7,
    FICHAFAM: 'FF-50291',
    UBIGEO: '150601',
    EDAD: 27,
    TIP_EDAD: 'A',
    SEXO: 'F',
    CODPSAL: '41829304',
    DIGITA: '80192011',
    COD_SERVSA: '302304',
    DNI: '71928374',
    Apellido_p: 'TORRES',
    Apellido_m: 'DEL AGUILA',
    Pnombre: 'DIANA',
    Dnombres: 'DIANA CAROLINA',
    HCLFAM: 'HC-77419',
    hmb: 13.1,
    Fecha_Ultima_Regla: '2026-08-05',
    PESO: '59.0',
    TALLA: '160',
    IMC: '23.0',
    FECHA_NAC: '1999-11-05',
    condicion_gestante: 'NO GESTANTE',
    gruporiesgo_desc: 'USUARIA SATISFECHA CON IMPLANTE SUBDERMICO ACTIVO',
    fecha_reg: '2026-08-15',
  },
];

const HIS_DL_DT_DB: HisDlDtRow[] = [
  // Geraldine Rodriguez (72910485): Ampolla mensual aplicada el 18/09/2026 -> Próxima cita a los 30 días: 18/10/2026 (HOY)
  {
    ID: '000005481202609000101',
    ID_CITA: 'CITA00981201',
    num: 1,
    DX: '90782',
    TDX: 'D',
    LDX: '1',
    cod_estab: '000005481',
    dia: 18,
    mes: 9,
    ano: 2026,
    id_dosis: '1',
    Alerta: 'Ampolla Mensual — Próxima dosis a los 30 días (18/10/2026)',
    fecha_reg: '2026-09-18',
  },
  // Geraldine Rodriguez (72910485): además de su ampolla mensual, registra la
  // atención 99208 de Planificación Familiar y Salud Reproductiva. Este caso
  // permite demostrar el Banner Clínico Destacado del validador.
  {
    ID: '000005481202609000101',
    ID_CITA: 'CITA00981201',
    num: 2,
    DX: '99208',
    TDX: 'D',
    LDX: '2',
    cod_estab: '000005481',
    dia: 18,
    mes: 9,
    ano: 2026,
    id_dosis: null,
    Alerta: 'Atención en Planificación Familiar y Salud Reproductiva (99208)',
    fecha_reg: '2026-09-18',
  },
  // Maria Chavez (47829103): Ampolla mensual aplicada el 19/09/2026 -> Próxima cita a los 30 días: 19/10/2026 (MAÑANA)
  {
    ID: '000005481202609000102',
    ID_CITA: 'CITA00981202',
    num: 1,
    DX: '90782',
    TDX: 'D',
    LDX: '2',
    cod_estab: '000005481',
    dia: 19,
    mes: 9,
    ano: 2026,
    id_dosis: '2',
    Alerta: 'Ampolla Mensual — Próxima dosis a los 30 días (19/10/2026)',
    fecha_reg: '2026-09-19',
  },
  // Rosa Huaman (46920183): Ampolla trimestral aplicada el 10/07/2026 -> Debió acudir el 08/10/2026 (VENCIDA)
  {
    ID: '000005485202607000103',
    ID_CITA: 'CITA00981203',
    num: 1,
    DX: 'Z304',
    TDX: 'D',
    LDX: '1',
    cod_estab: '000005485',
    dia: 10,
    mes: 7,
    ano: 2026,
    id_dosis: '1',
    Alerta: 'Ampolla Trimestral Vencida (Pasaron > 90 días sin reinyección)',
    fecha_reg: '2026-07-10',
  },
  // Karen Garay (74501928): Puérpera Z391 + Consejería Z300, pero NO eligió método
  {
    ID: '000005481202610000105',
    ID_CITA: 'CITA00981205',
    num: 1,
    DX: 'Z391',
    TDX: 'D',
    LDX: '1',
    cod_estab: '000005481',
    dia: 14,
    mes: 10,
    ano: 2026,
    id_dosis: null,
    Alerta: 'Puérpera sin método anticonceptivo activo (Insatisfecha)',
    fecha_reg: '2026-10-14',
  },
  // Diana Torres (71928374): Usuaria Satisfecha con Implante Subdérmico (Z301)
  {
    ID: '000005481202608000104',
    ID_CITA: 'CITA00981204',
    num: 1,
    DX: 'Z301',
    TDX: 'D',
    LDX: 'IMP',
    cod_estab: '000005481',
    dia: 15,
    mes: 8,
    ano: 2026,
    id_dosis: '1',
    Alerta: null,
    fecha_reg: '2026-08-15',
  },
];

// Initial rows in `pacientes_sin_metodo` for Hospital San Juan Bautista Huaral
let PACIENTES_SIN_METODO_DB: PacienteSinMetodoRow[] = [
  {
    id: 1,
    dni: '73819204',
    apellido_paterno: 'BALCAZAR',
    apellido_materno: 'MENDOZA',
    nombres: 'LUCIA MARIBEL',
    edad: 24,
    celular: encryptFieldAES256('984781920'),
    correo: encryptFieldAES256('lucia.balcazar@correo.pe'),
    distrito: 'HUARAL',
    direccion: encryptFieldAES256('Av. Solar 418 - Urb. Aparicio, Huaral'),
    sector: 'SECTOR 28 - APARICIO HUARAL',
    estado_paciente: 'INSATISFECHA_SIN_METODO',
    codpsal_obstetra: '41829304',
    fecha_registro: '2026-10-15 09:15:22',
  },
  {
    id: 2,
    dni: '76109482',
    apellido_paterno: 'PACHECO',
    apellido_materno: 'VILLAFUERTE',
    nombres: 'FIORELLA',
    edad: 19,
    celular: encryptFieldAES256('968392014'),
    correo: encryptFieldAES256('fiorella.pacheco@correo.pe'),
    distrito: 'AUCALLAMA',
    direccion: encryptFieldAES256('Centro Poblado Palpa Mz. D Lt. 8'),
    sector: 'SECTOR 04 - PALPA AUCALLAMA',
    estado_paciente: 'SEGUIMIENTO_DOMICILIARIO',
    codpsal_obstetra: '44910283',
    fecha_registro: '2026-10-16 11:42:10',
  },
  {
    id: 3,
    dni: '46920183',
    apellido_paterno: 'HUAMAN',
    apellido_materno: 'QUISPE',
    nombres: 'ROSA ANGELICA',
    edad: 31,
    celular: encryptFieldAES256('942556019'),
    correo: encryptFieldAES256('rosa.huaman@correo.pe'),
    distrito: 'CHANCAY',
    direccion: encryptFieldAES256('AA.HH. Peralvillo Alto Calle Los Olivos 214'),
    sector: 'SECTOR 12 - PERALVILLO',
    estado_paciente: 'INSATISFECHA_SIN_METODO',
    codpsal_obstetra: '46109284',
    fecha_registro: '2026-10-17 16:05:40',
  },
  {
    id: 4,
    dni: '75019283',
    apellido_paterno: 'RAMIREZ',
    apellido_materno: 'SOTELO',
    nombres: 'VALERIA',
    edad: 26,
    celular: encryptFieldAES256('951829301'),
    correo: encryptFieldAES256('valeria.ramirez@correo.pe'),
    distrito: 'OTROS: HUACHO (HUAURA)',
    direccion: encryptFieldAES256('Jr. La Merced 302 (De paso en Huaral)'),
    sector: 'SECTOR EXTERNO - FUERA DE JURISDICCION',
    estado_paciente: 'CONSEJERIA_REALIZADA',
    codpsal_obstetra: '41829304',
    fecha_registro: '2026-10-18 08:10:00',
  },
];

// ============================================================================
// 4. TAMPER-EVIDENT AUDIT LOGGING SYSTEM (SHA-256 HASH CHAIN)
// ============================================================================
const AUDIT_LOGS_DB: AuditLogEntry[] = [];
let securityMetrics = {
  sqliBlockedCount: 3,
  xssBlockedCount: 2,
  totpVerifiedCount: 16,
  encryptedRecordsCount: PACIENTES_SIN_METODO_DB.length,
  failedLoginsBlocked: 1,
};

function detectPlatform(userAgent = ''): 'Android' | 'iOS (iPhone/iPad)' | 'Web Desktop' {
  const ua = userAgent.toLowerCase();
  if (ua.includes('android')) return 'Android';
  if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ipod')) return 'iOS (iPhone/iPad)';
  return 'Web Desktop';
}

function appendAuditLog(params: {
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
  timestampOverride?: string;
}): AuditLogEntry {
  const id = AUDIT_LOGS_DB.length + 1;
  const timestamp = params.timestampOverride || new Date().toISOString().replace('T', ' ').slice(0, 19);
  const prev_hash = AUDIT_LOGS_DB.length > 0 ? AUDIT_LOGS_DB[AUDIT_LOGS_DB.length - 1].record_hash : '0'.repeat(64);
  const actor_estab = codigoEstablecimientoCanonico(params.actor_estab || '');

  const payloadToHash = `${id}|${timestamp}|${params.actor_dni}|${actor_estab}|${params.action}|${params.resource}|${params.status}|${params.details}|${prev_hash}`;
  const record_hash = crypto.createHash('sha256').update(payloadToHash).digest('hex');

  const entry: AuditLogEntry = {
    id,
    timestamp,
    actor_dni: params.actor_dni,
    actor_estab,
    actor_nombre: params.actor_nombre,
    actor_rol: params.actor_rol,
    ip_address: params.ip_address,
    platform: params.platform,
    action: params.action,
    resource: params.resource,
    severity: params.severity,
    status: params.status,
    details: params.details,
    prev_hash,
    record_hash,
  };
  AUDIT_LOGS_DB.push(entry);
  return entry;
}

appendAuditLog({
  actor_dni: '41829304',
  actor_nombre: 'LIC. OBST. ROXANA VILLANUEVA RAMOS',
  actor_rol: 'Coordinadora Planificación Familiar Huaral',
  ip_address: '192.168.1.45',
  platform: 'iOS (iPhone/iPad)',
  action: 'AUTH_2FA_VERIFIED',
  resource: 'session/totp',
  severity: 'INFO',
  status: 'SUCCESS',
  details: 'Inicio de sesión con 2FA TOTP desde iPhone (Hospital San Juan Bautista Huaral).',
  timestampOverride: '2026-10-18 07:40:12',
});

appendAuditLog({
  actor_dni: '41829304',
  actor_nombre: 'LIC. OBST. ROXANA VILLANUEVA RAMOS',
  actor_rol: 'Coordinadora Planificación Familiar Huaral',
  ip_address: '192.168.1.45',
  platform: 'iOS (iPhone/iPad)',
  action: 'AGENDA_AMPOLLAS_QUERY',
  resource: 'his_dl / his_dl_dt (Código 90782 / Z304)',
  severity: 'INFO',
  status: 'SUCCESS',
  details: 'Generación de reporte diario de pacientes citadas para ampolla mensual (30 días) y trimestral (90 días).',
  timestampOverride: '2026-10-18 07:48:04',
});

appendAuditLog({
  actor_dni: 'ANONIMO_EXT',
  actor_nombre: 'IP Externa No Autenticada',
  actor_rol: 'Desconocido',
  ip_address: '181.65.112.94',
  platform: 'Web Desktop',
  action: 'WAF_SQLI_BLOCKED',
  resource: 'POST /api/pacientes',
  severity: 'CRITICAL',
  status: 'BLOCKED',
  details: "Intento de Inyección SQL bloqueado en campo 'dni': payload [73819204' OR '1'='1 --] neutralizado antes de tocar el servidor local de Estadística.",
  timestampOverride: '2026-10-18 08:05:39',
});

// ============================================================================
// 5. WAF (SQLi & XSS DETECTION) + INPUT SANITIZATION UTILITIES
// ============================================================================
const SQLI_PATTERNS: RegExp[] = [
  /(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|EXEC|EXECUTE|SLEEP|BENCHMARK)\b\s+)/i,
  /('|\b)(OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,
  /(--|\/\*|\*\/|;\s*(DROP|DELETE|UPDATE|INSERT))/i,
  /\b(sp_query_set|information_schema|xp_cmdshell|load_file)\b/i,
];

const XSS_PATTERNS: RegExp[] = [
  /<\s*script\b[^>]*>/i,
  /javascript\s*:/i,
  /\bon(error|load|click|mouseover|focus|blur)\s*=/i,
  /<\s*(iframe|object|embed|svg|img)\b[^>]*\b(onload|onerror|src\s*=\s*['"]?javascript:)/i,
  /alert\s*\(/i,
];

export function detectMaliciousPayload(input: unknown): { type: 'SQLI' | 'XSS' | null; matched: string } {
  const serialized = typeof input === 'string' ? input : JSON.stringify(input || '');
  for (const regex of SQLI_PATTERNS) {
    const match = serialized.match(regex);
    if (match) {
      return { type: 'SQLI', matched: match[0] };
    }
  }
  for (const regex of XSS_PATTERNS) {
    const match = serialized.match(regex);
    if (match) {
      return { type: 'XSS', matched: match[0] };
    }
  }
  return { type: null, matched: '' };
}

export function sanitizeText(value: unknown, maxLen = 200): string {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/[&<>"'`]/g, (char) => {
      const map: Record<string, string> = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '`': '&#x60;',
      };
      return map[char] || char;
    })
    .trim()
    .slice(0, maxLen);
}

// Helper to add days to YYYY-MM-DD
function addDaysToDate(dateStr: string, daysToAdd: number): string {
  const d = new Date(`${dateStr}T12:00:00Z`);
  d.setUTCDate(d.getUTCDate() + daysToAdd);
  return d.toISOString().slice(0, 10);
}

// Formato oficial solicitado por la Dirección Regional: DD/MM/AAAA.
function formatDateDDMMYYYY(value: string | null | undefined): string {
  const raw = String(value || '').trim();
  if (!raw) return '';
  const iso = raw.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (iso) return `${iso[3]}/${iso[2]}/${iso[1]}`;
  const dmy = raw.match(/^(\d{1,2})[/-](\d{1,2})[/-](\d{4})/);
  if (dmy) return `${dmy[1].padStart(2, '0')}/${dmy[2].padStart(2, '0')}/${dmy[3]}`;
  return raw;
}

function fechaDesdeFilaHis(row: { ANO?: number; MES?: number; DIA?: number; fecha_reg?: string }): string {
  if (row.ANO && row.MES && row.DIA) {
    return `${String(row.DIA).padStart(2, '0')}/${String(row.MES).padStart(2, '0')}/${row.ANO}`;
  }
  return formatDateDDMMYYYY(row.fecha_reg);
}

// ============================================================================
// 5.b EXPORTACIÓN NUBE -> BASE LOCAL (solo tablas espejo del hospital)
// ============================================================================
const TABLAS_SYNC_PERMITIDAS = [
  'usuario',
  'mstrpers',
  'his_mstrpers',
  'his_dl',
  'his_dl_dt',
  'r_his_dl',
  'r_his_dl_dt',
] as const;

function sqlIdentificadorSeguro(name: string): boolean {
  return /^[A-Za-z0-9_]{1,64}$/.test(name);
}

function sqlValorLiteral(value: unknown): string {
  if (value === null || value === undefined) return 'NULL';
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'boolean') return value ? '1' : '0';
  return `'${String(value).replace(/\\/g, '\\\\').replace(/'/g, "''").replace(/\r?\n/g, ' ')}'`;
}

function construirUpsertSql(
  tabla: string,
  rows: Array<Record<string, unknown>>,
  pk: string[]
): string {
  if (!rows.length || !sqlIdentificadorSeguro(tabla)) return '';
  const columns = Object.keys(rows[0]).filter(sqlIdentificadorSeguro);
  if (!columns.length) return '';
  const colList = columns.map((c) => `\`${c}\``).join(', ');
  const tuples = rows.map(
    (row) => `(${columns.map((col) => sqlValorLiteral(row[col])).join(', ')})`
  );
  const updateCols = columns.filter((c) => !pk.includes(c));
  const updates = (updateCols.length ? updateCols : columns)
    .map((c) => `\`${c}\` = VALUES(\`${c}\`)`)
    .join(', ');
  return `INSERT INTO \`${tabla}\` (${colList})\nVALUES\n  ${tuples.join(
    ',\n  '
  )}\nON DUPLICATE KEY UPDATE ${updates};\n`;
}

function generarSqlSync(modo: 'directo' | 'puente'): {
  sql: string;
  tablas: string[];
  filas: number;
  batch: number;
} {
  const batch = 300;
  const tablasConDatos: Record<string, Array<Record<string, unknown>>> = {
    usuario: USUARIOS_DB as unknown as Array<Record<string, unknown>>,
    mstrpers: MSTRPERS_DB as unknown as Array<Record<string, unknown>>,
    his_dl: HIS_DL_DB as unknown as Array<Record<string, unknown>>,
    his_dl_dt: HIS_DL_DT_DB as unknown as Array<Record<string, unknown>>,
  };
  const pk: Record<string, string[]> = {
    usuario: ['dni'],
    mstrpers: ['CODPSAL'],
    his_mstrpers: ['CODPSAL'],
    his_dl: ['ID'],
    his_dl_dt: ['ID', 'num'],
    r_his_dl: ['ID'],
    r_his_dl_dt: ['ID', 'num'],
  };

  let sql = `-- =====================================================================\n`;
  sql += `-- PlanificaSalud HIS · Exportación Nube -> Base Local\n`;
  sql += `-- Hospital San Juan Bautista Huaral · Red de Salud Huaral-Chancay\n`;
  sql += `-- Generado: ${new Date().toISOString().replace('T', ' ').slice(0, 19)} · Modo: ${modo} · Lote: ${batch}\n`;
  sql += `-- SOLO tablas espejo existentes en el servidor local del hospital.\n`;
  sql += `-- NO contiene pacientes_sin_metodo ni auditoria_seguridad_app (tablas propias de la nube).\n`;
  sql += `-- NO elimina datos históricos: usa INSERT ... ON DUPLICATE KEY UPDATE.\n`;
  sql += `-- =====================================================================\n\n`;
  sql += `SET NAMES utf8mb4;\nSET @OLD_SQL_MODE=@@SQL_MODE;\nSET SQL_MODE='STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION';\nSTART TRANSACTION;\n\n`;

  const exportadas: string[] = [];
  let filas = 0;
  for (const tabla of TABLAS_SYNC_PERMITIDAS) {
    const rows = (tablasConDatos[tabla] || []).slice(0, batch);
    if (!rows.length) {
      sql += `-- [SIN DATOS EN MEMORIA] \`${tabla}\` no tiene registros en este lote.\n\n`;
      continue;
    }
    sql += `-- ---------------------------------------------------------------------\n-- Tabla: \`${tabla}\` (${rows.length} filas, LIMIT ${batch})\n-- ---------------------------------------------------------------------\n`;
    sql += construirUpsertSql(tabla, rows, pk[tabla] || ['id']);
    sql += `\n`;
    exportadas.push(tabla);
    filas += rows.length;
  }

  sql += `-- =====================================================================\n`;
  sql += `-- Flujo de tablas puente (si su servidor local usa sp_get_recepcion)\n`;
  sql += `-- =====================================================================\n`;
  if (modo === 'puente') {
    sql += `-- Puente: los registros se cargan en r_his_dl / r_his_dl_dt y luego\n`;
    sql += `-- el procedimiento del hospital los integra sin borrar historial.\n`;
    sql += `CALL sp_get_recepcion();\n\n`;
  } else {
    sql += `-- En modo directo NO se ejecuta sp_get_recepcion para evitar doble inserción.\n`;
    sql += `-- Para usar el flujo puente ejecute: php sync_cloud_to_local.php --mode=bridge\n`;
    sql += `-- CALL sp_get_recepcion();\n\n`;
  }
  sql += `COMMIT;\nSET SQL_MODE=@OLD_SQL_MODE;\n\n`;
  sql += `-- Fin del script. Ejecutar en Navicat sobre la base local del hospital.\n`;
  return { sql, tablas: exportadas, filas, batch };
}

// ============================================================================
// 6. RATE LIMITING (anti-scraping / anti-fuerza bruta) Y SESIONES
// ============================================================================
interface RateBucket {
  hits: number;
  resetAt: number;
}
const RATE_LIMIT_BUCKETS = new Map<string, RateBucket>();

function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  const raw = Array.isArray(forwarded) ? forwarded[0] : forwarded;
  const ip = raw ? raw.split(',')[0].trim() : req.socket.remoteAddress || '127.0.0.1';
  return ip;
}

function rateLimitStatus(key: string, max: number, windowMs: number): {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
} {
  const now = Date.now();
  const bucket = RATE_LIMIT_BUCKETS.get(key);
  if (!bucket || bucket.resetAt <= now) {
    return { allowed: true, remaining: max, retryAfterSeconds: 0 };
  }
  return {
    allowed: bucket.hits < max,
    remaining: Math.max(0, max - bucket.hits),
    retryAfterSeconds: Math.ceil((bucket.resetAt - now) / 1000),
  };
}

function rateLimitHit(key: string, windowMs: number): void {
  const now = Date.now();
  const bucket = RATE_LIMIT_BUCKETS.get(key);
  if (!bucket || bucket.resetAt <= now) {
    RATE_LIMIT_BUCKETS.set(key, { hits: 1, resetAt: now + windowMs });
  } else {
    bucket.hits += 1;
  }
  // Limpieza preventiva para no crecer indefinidamente.
  if (RATE_LIMIT_BUCKETS.size > 5000) {
    for (const [k, v] of RATE_LIMIT_BUCKETS) {
      if (v.resetAt <= now) RATE_LIMIT_BUCKETS.delete(k);
    }
  }
}

function rateLimitReset(key: string): void {
  RATE_LIMIT_BUCKETS.delete(key);
}

interface ActiveSession {
  token: string;
  dni: string;
  nombreCompleto: string;
  rol: string;
  nivelid: number;
  cod_estab: string;
  estab_nombre: string;
  verified2FA: boolean;
  createdAt: number;
  lastActivityAt: number;
  expiresAt: number;
  platform: 'Android' | 'iOS (iPhone/iPad)' | 'Web Desktop';
}

const PRE_AUTH_CHALLENGES = new Map<
  string,
  { dni: string; expiresAt: number; platform: 'Android' | 'iOS (iPhone/iPad)' | 'Web Desktop' }
>();
const ACTIVE_SESSIONS = new Map<string, ActiveSession>();

function createSignedToken(dni: string): string {
  const nonce = crypto.randomBytes(16).toString('hex');
  const payload = `${dni}.${Date.now()}.${nonce}`;
  const sig = crypto.createHmac('sha256', SESSION_HMAC_KEY).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function isValidSignedToken(token: string): boolean {
  const parts = token.split('.');
  if (parts.length !== 4) return false;
  const [dni, issuedAt, nonce, sig] = parts;
  if (!/^\d{8,11}$/.test(dni) || !/^\d+$/.test(issuedAt) || !/^[a-f0-9]{32}$/.test(nonce)) return false;
  if (!/^[a-f0-9]{64}$/.test(sig)) return false;
  const expected = crypto.createHmac('sha256', SESSION_HMAC_KEY).update(`${dni}.${issuedAt}.${nonce}`).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(sig, 'hex'));
}

// No existe sesión demo implícita: todo endpoint clínico exige Bearer Token
// emitido tras verificar TOTP (2FA). Esto cierra la fuga por acceso anónimo.

// ============================================================================
// 7. EXPRESS SERVER & REST API ROUTES
// ============================================================================
async function startServer() {
  ensurePwaIconsExist();

  const app = express();
  app.use(express.json({ limit: '256kb' }));

  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    );
    if (req.path.startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
    }
    next();
  });

  // Active WAF Middleware
  app.use('/api', (req: Request, res: Response, next: NextFunction) => {
    if (req.path === '/security/test-waf') {
      return next();
    }
    const queryCheck = detectMaliciousPayload(req.query);
    const bodyCheck = detectMaliciousPayload(req.body);
    const detected = queryCheck.type ? queryCheck : bodyCheck;

    if (detected.type) {
      const platform = detectPlatform(req.headers['user-agent']);
      const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
      if (detected.type === 'SQLI') securityMetrics.sqliBlockedCount++;
      if (detected.type === 'XSS') securityMetrics.xssBlockedCount++;

      const logEntry = appendAuditLog({
        actor_dni: 'WAF_INTERCEPTOR',
        actor_nombre: 'Firewall Hospital Huaral (WAF)',
        actor_rol: 'Seguridad Perimetral',
        ip_address: String(ip),
        platform,
        action: detected.type === 'SQLI' ? 'WAF_SQLI_BLOCKED' : 'WAF_XSS_BLOCKED',
        resource: `${req.method} /api${req.path}`,
        severity: 'CRITICAL',
        status: 'BLOCKED',
        details: `Ataque ${detected.type} neutralizado automáticamente. Patrón detectado: [${detected.matched}]. La PC Servidor de Estadística permanece intacta.`,
      });

      return res.status(403).json({
        error: `Solicitud bloqueada por el Firewall de Seguridad Clínica (${detected.type} detectado).`,
        code: `WAF_${detected.type}_BLOCKED`,
        matchedPattern: detected.matched,
        auditId: logEntry.id,
        auditHash: logEntry.record_hash,
      });
    }
    next();
  });

  function getSessionFromReq(req: Request): ActiveSession | null {
    const authHeader = req.headers.authorization || '';
    if (!authHeader.startsWith('Bearer ')) return null;
    const token = authHeader.slice(7).trim();
    if (!token || !isValidSignedToken(token)) return null;
    const session = ACTIVE_SESSIONS.get(token);
    if (!session || !session.verified2FA) return null;
    const now = Date.now();
    // Expiración absoluta (8 h) y por inactividad (30 min).
    if (session.expiresAt <= now || now - session.lastActivityAt > 30 * 60 * 1000) {
      ACTIVE_SESSIONS.delete(token);
      return null;
    }
    session.lastActivityAt = now;
    return session;
  }

  function requireSession(req: Request, res: Response): ActiveSession | null {
    const session = getSessionFromReq(req);
    if (!session) {
      res.status(401).json({
        error: 'Sesión no válida, expirada o sin segundo factor 2FA. Inicie sesión nuevamente.',
        code: 'AUTH_REQUIRED_2FA',
      });
      return null;
    }
    return session;
  }

  // --- AUTH, SELF-REGISTRATION FOR OBSTETRAS & 2FA ENDPOINTS ---
  // Catálogo público (sin PII): alimenta el selector obligatorio de las 53 IPRESS.
  app.get('/api/establecimientos', (_req: Request, res: Response) => {
    res.json({
      total: TOTAL_ESTABLECIMIENTOS,
      establecimientos: ESTABLECIMIENTOS_DB,
      porDistrito: ESTABLECIMIENTOS_POR_DISTRITO,
    });
  });

  // Self-registration for Obstetricians (Video min 06:18: "que cada obstetra se cree su acceso vinculado a su correo y DNI")
  app.post('/api/auth/register-obstetra', (req: Request, res: Response) => {
    const dni = sanitizeText(req.body?.dni, 11).replace(/\D/g, '');
    const nombre1 = sanitizeText(req.body?.nombre1, 90).toUpperCase();
    const apaterno = sanitizeText(req.body?.apaterno, 90).toUpperCase();
    const amaterno = sanitizeText(req.body?.amaterno, 90).toUpperCase();
    const email = sanitizeText(req.body?.email, 190).toLowerCase();
    const celular = sanitizeText(req.body?.celular, 9).replace(/\D/g, '');
    const codEstabSolicitado = codigoEstablecimientoCanonico(
      sanitizeText(req.body?.cod_estab || '000005481', 9)
    );
    const password = String(req.body?.password || '');
    const platform = detectPlatform(req.headers['user-agent']);
    const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

    if (dni.length !== 8 || !nombre1 || !apaterno || !email || password.length < 8) {
      return res.status(400).json({
        error: 'Complete DNI (8 dígitos), nombres, apellidos, correo institucional y contraseña de al menos 8 caracteres.',
      });
    }

    if (USUARIOS_DB.some((u) => u.dni === dni)) {
      return res.status(409).json({
        error: `La obstetra con DNI ${dni} ya cuenta con acceso registrado. Puede iniciar sesión directamente.`,
      });
    }

    const estab = ESTABLECIMIENTOS_DB.find((e) => e.COD_ESTAB === codEstabSolicitado);
    if (!estab) {
      return res.status(400).json({
        error: 'Seleccione un establecimiento válido de la Red Huaral-Chancay (53 IPRESS).',
        code: 'ESTABLECIMIENTO_INVALIDO',
      });
    }
    const totp_secret = `HUARAL-OBST-${dni}`;
    const nowStr = new Date().toISOString().replace('T', ' ').slice(0, 19);

    const newUser: UsuarioHospitalRow = {
      dni,
      nombre1,
      nombre2: '',
      apaterno,
      amaterno,
      passwordx: hashPasswordScrypt(password),
      email,
      celular: celular || '999000111',
      nivelid: 2,
      nivelcd: estab.COD_ESTAB,
      tipo: 2,
      estado: 1,
      fechacreacion: nowStr,
      totp_secret,
      rol_descripcion: `Obstetra Captadora — ${estab.DESC_ESTAB}`,
      cod_estab: estab.COD_ESTAB,
    };
    USUARIOS_DB.push(newUser);

    if (!MSTRPERS_DB.some((m) => m.CODPSAL === dni)) {
      MSTRPERS_DB.push({
        CODPSAL: dni,
        NOMBRE: `OBST. ${nombre1} ${apaterno} ${amaterno}`,
        COD_ESTAB: estab.COD_ESTAB,
        COD_PROF: '04',
        COD_COND: '01',
        COD_COL: '04',
        COD_DOC: '1',
        FECHA_ING: nowStr.slice(0, 10),
        ESTADO: 'A',
      });
    }

    appendAuditLog({
      actor_dni: dni,
      actor_estab: estab.COD_ESTAB,
      actor_nombre: `OBST. ${nombre1} ${apaterno} ${amaterno}`,
      actor_rol: newUser.rol_descripcion,
      ip_address: String(ip),
      platform,
      action: 'OBSTETRA_ACCOUNT_CREATED',
      resource: `usuario / mstrpers (DNI:${dni})`,
      severity: 'INFO',
      status: 'SUCCESS',
      details: `Creación de acceso individual para Obstetra DNI ${dni} (${email}) en ${estab.DESC_ESTAB} con secreto 2FA asignado.`,
    });

    const challengeId = crypto.randomBytes(16).toString('hex');
    PRE_AUTH_CHALLENGES.set(challengeId, {
      dni: newUser.dni,
      expiresAt: Date.now() + 5 * 60 * 1000,
      platform,
    });
    const totpPreview = generateTOTP(newUser.totp_secret);

    return res.status(201).json({
      requires2FA: true,
      challengeId,
      userPreview: {
        dni: newUser.dni,
        nombreCompleto: `${newUser.nombre1} ${newUser.apaterno} ${newUser.amaterno}`,
        email: newUser.email,
        celularMasked: `***-***-${newUser.celular.slice(-3)}`,
        rol: newUser.rol_descripcion,
        totpSecret: newUser.totp_secret,
        demoCurrentCode: totpPreview.code,
        remainingSeconds: totpPreview.remainingSeconds,
      },
    });
  });

  app.post('/api/auth/login', (req: Request, res: Response) => {
    const dni = String(req.body?.dni || '').trim();
    const password = String(req.body?.password || '');
    const platform = detectPlatform(req.headers['user-agent']);
    const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

    if (!/^\d{8,11}$/.test(dni)) {
      return res.status(400).json({ error: 'El DNI / Código Obstetra debe contener entre 8 y 11 dígitos numéricos.' });
    }

    // Fuerza bruta: 5 intentos fallidos por DNI+IP en una ventana de 15 minutos.
    const loginBucket = `login_fail:${ip}|${dni}`;
    const loginLimit = rateLimitStatus(loginBucket, 5, 15 * 60 * 1000);
    if (!loginLimit.allowed) {
      appendAuditLog({
        actor_dni: dni,
        actor_nombre: 'Intento Bloqueado por Rate Limit',
        actor_rol: 'No Autenticado',
        ip_address: String(ip),
        platform,
        action: 'LOGIN_RATE_LIMITED',
        resource: 'POST /api/auth/login',
        severity: 'CRITICAL',
        status: 'BLOCKED',
        details: `Límite de 5 intentos fallidos alcanzado para DNI ${dni}. Bloqueo temporal de 15 minutos.`,
      });
      return res.status(429).json({
        error: 'Demasiados intentos fallidos. Espere 15 minutos antes de volver a intentar.',
        code: 'LOGIN_RATE_LIMITED',
        retryAfter: loginLimit.retryAfterSeconds,
      });
    }

    const user = USUARIOS_DB.find((u) => u.dni === dni && u.estado === 1);
    const inputHash = hashPasswordScrypt(password);

    if (!user || user.passwordx !== inputHash) {
      rateLimitHit(loginBucket, 15 * 60 * 1000);
      securityMetrics.failedLoginsBlocked++;
      appendAuditLog({
        actor_dni: dni || 'DESCONOCIDO',
        actor_nombre: 'Intento Fallido',
        actor_rol: 'No Autenticado',
        ip_address: String(ip),
        platform,
        action: 'AUTH_LOGIN_FAILED',
        resource: 'POST /api/auth/login',
        severity: 'WARNING',
        status: 'FAILED',
        details: `Credenciales inválidas para DNI ${dni}. Contraseña verificada con Scrypt/PBKDF2.`,
      });
      return res.status(401).json({ error: 'DNI o contraseña incorrectos.' });
    }

    rateLimitReset(loginBucket);
    const challengeId = crypto.randomBytes(16).toString('hex');
    PRE_AUTH_CHALLENGES.set(challengeId, {
      dni: user.dni,
      expiresAt: Date.now() + 5 * 60 * 1000,
      platform,
    });

    const totpPreview = generateTOTP(user.totp_secret);

    appendAuditLog({
      actor_dni: user.dni,
      actor_estab: user.cod_estab,
      actor_nombre: `${user.nombre1} ${user.apaterno} ${user.amaterno}`,
      actor_rol: user.rol_descripcion,
      ip_address: String(ip),
      platform,
      action: 'AUTH_STEP1_PASSED',
      resource: 'POST /api/auth/login',
      severity: 'INFO',
      status: 'SUCCESS',
      details: `Paso 1 completado para DNI ${user.dni}. Esperando segundo factor de autenticación (2FA TOTP 6 dígitos).`,
    });

    return res.json({
      requires2FA: true,
      challengeId,
      userPreview: {
        dni: user.dni,
        nombreCompleto: `${user.nombre1} ${user.apaterno} ${user.amaterno}`,
        email: user.email,
        celularMasked: `***-***-${user.celular.slice(-3)}`,
        rol: user.rol_descripcion,
        totpSecret: user.totp_secret,
        demoCurrentCode: totpPreview.code,
        remainingSeconds: totpPreview.remainingSeconds,
      },
    });
  });

  app.post('/api/auth/verify-2fa', (req: Request, res: Response) => {
    const challengeId = String(req.body?.challengeId || '').trim();
    const code = String(req.body?.code || '').trim();
    const platform = detectPlatform(req.headers['user-agent']);
    const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

    const challenge = PRE_AUTH_CHALLENGES.get(challengeId);
    if (!challenge || challenge.expiresAt < Date.now()) {
      return res.status(401).json({ error: 'La sesión de verificación 2FA expiró. Inicie sesión nuevamente.' });
    }

    const user = USUARIOS_DB.find((u) => u.dni === challenge.dni);
    if (!user) {
      return res.status(401).json({ error: 'Usuario no encontrado.' });
    }

    if (!verifyTOTP(user.totp_secret, code)) {
      appendAuditLog({
        actor_dni: user.dni,
        actor_estab: user.cod_estab,
        actor_nombre: `${user.nombre1} ${user.apaterno} ${user.amaterno}`,
        actor_rol: user.rol_descripcion,
        ip_address: String(ip),
        platform,
        action: 'AUTH_2FA_FAILED',
        resource: 'POST /api/auth/verify-2fa',
        severity: 'WARNING',
        status: 'FAILED',
        details: `Código 2FA TOTP inválido (${code}) ingresado para DNI ${user.dni}.`,
      });
      return res.status(401).json({ error: 'Código 2FA de 6 dígitos incorrecto o expirado.' });
    }

    PRE_AUTH_CHALLENGES.delete(challengeId);
    securityMetrics.totpVerifiedCount++;

    const estab = ESTABLECIMIENTOS_DB.find((e) => e.COD_ESTAB === user.cod_estab) || ESTABLECIMIENTOS_DB[0];
    const token = createSignedToken(user.dni);
    const now = Date.now();
    const session: ActiveSession = {
      token,
      dni: user.dni,
      nombreCompleto: `${user.nombre1} ${user.apaterno} ${user.amaterno}`,
      rol: user.rol_descripcion,
      nivelid: user.nivelid,
      cod_estab: estab.COD_ESTAB,
      estab_nombre: estab.DESC_ESTAB,
      verified2FA: true,
      createdAt: now,
      lastActivityAt: now,
      expiresAt: now + 1000 * 60 * 60 * 8,
      platform,
    };
    ACTIVE_SESSIONS.set(token, session);

    appendAuditLog({
      actor_dni: user.dni,
      actor_estab: estab.COD_ESTAB,
      actor_nombre: session.nombreCompleto,
      actor_rol: session.rol,
      ip_address: String(ip),
      platform,
      action: 'AUTH_2FA_VERIFIED',
      resource: 'POST /api/auth/verify-2fa',
      severity: 'INFO',
      status: 'SUCCESS',
      details: `Autenticación de Dos Factores (2FA TOTP RFC 6238) verificada correctamente en Hospital Huaral.`,
    });

    return res.json({
      session: {
        token: session.token,
        dni: session.dni,
        nombreCompleto: session.nombreCompleto,
        rol: session.rol,
        nivelid: session.nivelid,
        cod_estab: session.cod_estab,
        estab_nombre: session.estab_nombre,
        verified2FA: session.verified2FA,
        platform: session.platform,
      },
    });
  });

  app.post('/api/auth/logout', (req: Request, res: Response) => {
    const session = requireSession(req, res);
    if (!session) return;
    ACTIVE_SESSIONS.delete(session.token);
    appendAuditLog({
      actor_dni: session.dni,
      actor_estab: session.cod_estab,
      actor_nombre: session.nombreCompleto,
      actor_rol: session.rol,
      ip_address: getClientIp(req),
      platform: session.platform,
      action: 'LOGOUT',
      resource: 'POST /api/auth/logout',
      severity: 'INFO',
      status: 'SUCCESS',
      details: 'Sesión Bearer revocada por la obstetra. El token queda inutilizado.',
    });
    res.json({ success: true });
  });

  // La obstetra puede seleccionar/cambiar su establecimiento en cualquier momento
  // (rotación o guardia). El DNI se busca luego solo en ese establecimiento.
  app.patch('/api/auth/session/establecimiento', (req: Request, res: Response) => {
    const session = requireSession(req, res);
    if (!session) return;
    const codEstab = codigoEstablecimientoCanonico(
      sanitizeText(req.body?.cod_estab || '', 9)
    );
    const estab = ESTABLECIMIENTOS_DB.find((e) => e.COD_ESTAB === codEstab);
    if (!estab) {
      return res.status(400).json({
        error: 'El establecimiento seleccionado no pertenece a la Red Huaral-Chancay.',
        code: 'ESTABLECIMIENTO_INVALIDO',
      });
    }
    const anterior = session.cod_estab;
    session.cod_estab = estab.COD_ESTAB;
    session.estab_nombre = estab.DESC_ESTAB;
    const user = USUARIOS_DB.find((u) => u.dni === session.dni);
    if (user) user.cod_estab = estab.COD_ESTAB;

    appendAuditLog({
      actor_dni: session.dni,
      actor_estab: estab.COD_ESTAB,
      actor_nombre: session.nombreCompleto,
      actor_rol: session.rol,
      ip_address: getClientIp(req),
      platform: session.platform,
      action: 'CAMBIO_ESTABLECIMIENTO',
      resource: `sesion / ${session.dni}`,
      severity: 'INFO',
      status: 'SUCCESS',
      details: `Establecimiento activo cambiado de ${nombreEstablecimiento(
        anterior
      )} a ${estab.DESC_ESTAB}. Las búsquedas de DNI quedan restringidas a la UPS de Planificación Familiar de esta IPRESS.`,
    });

    res.json({
      success: true,
      session: {
        dni: session.dni,
        cod_estab: session.cod_estab,
        estab_nombre: session.estab_nombre,
      },
    });
  });

  // --- DASHBOARD, AGENDA DE AMPOLLAS & HOSPITAL HUARAL HIS OVERVIEW ---
  app.get('/api/overview', (req: Request, res: Response) => {
    const session = requireSession(req, res);
    if (!session) return;

    const pacientes = PACIENTES_SIN_METODO_DB.map((row) => {
      const obstetra = MSTRPERS_DB.find((m) => m.CODPSAL === row.codpsal_obstetra);
      const hisRecords = HIS_DL_DB.filter((h) => h.DNI === row.dni);
      const hisDiagnoses = HIS_DL_DT_DB.filter((dt) => hisRecords.some((h) => h.ID === dt.ID)).map((dt) => {
        const cie = ENFERMEDADES_CIE10_DB.find((c) => c.COD_ENF === dt.DX);
        return {
          ...dt,
          DESC_ENF: cie ? cie.DESC_ENF : 'PROCEDIMIENTO / DIAGNOSTICO HIS',
          METODO_CORTO: cie ? cie.METODO_CORTO : 'Procedimiento HIS',
        };
      });

      return {
        id: row.id,
        dni: row.dni,
        apellido_paterno: row.apellido_paterno,
        apellido_materno: row.apellido_materno,
        nombres: row.nombres,
        edad: row.edad,
        celular: decryptFieldAES256(row.celular),
        correo: decryptFieldAES256(row.correo),
        distrito: row.distrito,
        direccion: decryptFieldAES256(row.direccion),
        encrypted_raw: {
          celular: row.celular,
          correo: row.correo,
          direccion: row.direccion,
        },
        sector: row.sector,
        estado_paciente: row.estado_paciente,
        codpsal_obstetra: row.codpsal_obstetra,
        cod_estab: row.cod_estab || '',
        atencion_99208: Boolean(row.atencion_99208),
        nombre_obstetra: obstetra ? obstetra.NOMBRE : `OBST. CODPSAL ${row.codpsal_obstetra}`,
        fecha_registro: row.fecha_registro,
        his_vinculado: hisRecords.length > 0,
        his_ultimo_control: hisRecords[0] || null,
        his_diagnosticos: hisDiagnoses,
      };
    });

    // Calculate Agenda de Ampollas y Controles Programados (30 días / 90 días) from `his_dl` + `his_dl_dt`
    // Video min 00:30 - 01:15: "Paciente Gerald, su ampolla mensual le toca tal fecha. Mañana qué pacientes deberían venir para su ampolla"
    const agendaAmpollas = HIS_DL_DB.map((h) => {
      const dts = HIS_DL_DT_DB.filter((d) => d.ID === h.ID);
      const estab = ESTABLECIMIENTOS_DB.find((e) => e.COD_ESTAB === h.COD_ESTAB);
      const mainDt = dts[0];
      const cie = mainDt ? ENFERMEDADES_CIE10_DB.find((c) => c.COD_ENF === mainDt.DX) : null;
      const cicloDias = cie?.CICLO_DIAS ?? 0;
      const fechaProximaCita = cicloDias > 0 ? addDaysToDate(h.fecha_reg, cicloDias) : null;

      let estadoCita: 'TOCA_HOY' | 'TOCA_MANANA' | 'VENCIDA_ABANDONO' | 'VIGENTE' | 'SIN_METODO_EN_HIS' = 'VIGENTE';
      if (cicloDias === 0) {
        estadoCita = 'SIN_METODO_EN_HIS';
      } else if (fechaProximaCita === '2026-10-18') {
        estadoCita = 'TOCA_HOY';
      } else if (fechaProximaCita === '2026-10-19') {
        estadoCita = 'TOCA_MANANA';
      } else if (fechaProximaCita && fechaProximaCita < '2026-10-18') {
        estadoCita = 'VENCIDA_ABANDONO';
      }

      const captadaRecord = pacientes.find((p) => p.dni === h.DNI);

      return {
        id_his: h.ID,
        dni: h.DNI,
        paciente_nombre: `${h.Apellido_p.trim()} ${h.Apellido_m.trim()}, ${h.Dnombres}`,
        edad: h.EDAD,
        historia_clinica: h.HCLFAM,
        ficha_familiar: h.FICHAFAM,
        establecimiento: estab?.DESC_ESTAB || h.COD_ESTAB,
        codigo_his: mainDt?.DX || 'S/C',
        metodo_descripcion: cie?.METODO_CORTO || 'Sin método activo',
        dosis_nro: mainDt?.id_dosis || '1',
        fecha_ultima_aplicacion: h.fecha_reg,
        ciclo_dias: cicloDias,
        fecha_proxima_cita: fechaProximaCita,
        estado_cita: estadoCita,
        celular_contacto: captadaRecord?.celular || 'Pendiente actualizar en campo',
        sector: captadaRecord?.sector || 'Cercado Huaral',
        alerta_his: mainDt?.Alerta || h.gruporiesgo_desc,
      };
    });

    // Production by Obstetrician (so Lic. Roxana can see who is capturing patients)
    const produccionObstetras = MSTRPERS_DB.map((o) => {
      const captadasPorObstetra = pacientes.filter((p) => p.codpsal_obstetra === o.CODPSAL);
      const estab = ESTABLECIMIENTOS_DB.find((e) => e.COD_ESTAB === o.COD_ESTAB);
      return {
        codpsal: o.CODPSAL,
        nombre: o.NOMBRE,
        establecimiento: estab?.DESC_ESTAB || o.COD_ESTAB,
        totalCaptadas: captadasPorObstetra.length,
        insatisfechasCaptadas: captadasPorObstetra.filter(
          (p) => p.estado_paciente === 'INSATISFECHA_SIN_METODO'
        ).length,
        conMetodoLogrado: captadasPorObstetra.filter(
          (p) => p.estado_paciente === 'CAPTADA_CON_METODO'
        ).length,
      };
    });

    const alertasHisPendientes = HIS_DL_DB.filter(
      (h) => !PACIENTES_SIN_METODO_DB.some((p) => p.dni === h.DNI)
    ).map((h) => {
      const dts = HIS_DL_DT_DB.filter((d) => d.ID === h.ID);
      const estab = ESTABLECIMIENTOS_DB.find((e) => e.COD_ESTAB === h.COD_ESTAB);
      return {
        ...h,
        Apellido_p: h.Apellido_p.trim(),
        DESC_ESTAB: estab?.DESC_ESTAB || h.COD_ESTAB,
        diagnosticos: dts,
      };
    });

    res.json({
      session: {
        dni: session.dni,
        nombreCompleto: session.nombreCompleto,
        rol: session.rol,
        cod_estab: session.cod_estab,
        estab_nombre: session.estab_nombre,
        verified2FA: session.verified2FA,
        platform: session.platform,
      },
      stats: {
        totalCaptadas: pacientes.length,
        insatisfechasSinMetodo: pacientes.filter((p) => p.estado_paciente === 'INSATISFECHA_SIN_METODO').length,
        captadasConMetodo: pacientes.filter((p) => p.estado_paciente === 'CAPTADA_CON_METODO').length,
        seguimientoDomiciliario: pacientes.filter((p) => p.estado_paciente === 'SEGUIMIENTO_DOMICILIARIO').length,
        citasAmpollaHoyManana: agendaAmpollas.filter(
          (a) => a.estado_cita === 'TOCA_HOY' || a.estado_cita === 'TOCA_MANANA'
        ).length,
        alertasHisPorCaptar: alertasHisPendientes.length,
        atenciones99208: pacientes.filter((p) => p.atencion_99208).length,
      },
      securityMetrics: {
        ...securityMetrics,
        encryptedRecordsCount: PACIENTES_SIN_METODO_DB.length,
        auditLogCount: AUDIT_LOGS_DB.length,
      },
      pacientes,
      agendaAmpollas,
      produccionObstetras,
      alertasHisPendientes,
      establecimientos: ESTABLECIMIENTOS_DB,
      distritos: DISTRITOS_DB,
      obstetras: MSTRPERS_DB,
      cie10Catalog: ENFERMEDADES_CIE10_DB,
    });
  });

  // --- HIS CROSS-REFERENCE LOOKUP BY DNI (Audio 3 & Video Field Validation) ---
  app.get('/api/his/lookup/:dni', (req: Request, res: Response) => {
    const session = requireSession(req, res);
    if (!session) return;
    const dni = String(req.params.dni || '').trim();
    const platform = detectPlatform(req.headers['user-agent']);
    const ip = getClientIp(req);

    if (!/^\d{8,15}$/.test(dni)) {
      return res.status(400).json({ error: 'Formato de DNI inválido. Use únicamente números (8 a 15 dígitos).' });
    }

    // Anti-scraping: 30 consultas por minuto por obstetra + IP.
    const lookupBucket = `lookup:${session.dni}|${ip}`;
    const lookupLimit = rateLimitStatus(lookupBucket, 30, 60 * 1000);
    if (!lookupLimit.allowed) {
      appendAuditLog({
        actor_dni: session.dni,
        actor_estab: session.cod_estab,
        actor_nombre: session.nombreCompleto,
        actor_rol: session.rol,
        ip_address: ip,
        platform,
        action: 'LOOKUP_RATE_LIMITED',
        resource: `his_dl / DNI:${dni}`,
        severity: 'CRITICAL',
        status: 'BLOCKED',
        details: 'Límite de 30 consultas de DNI por minuto excedido. Posible scraping bloqueado.',
      });
      return res.status(429).json({
        error: 'Límite de 30 consultas de DNI por minuto alcanzado. Espere y vuelva a intentar.',
        code: 'LOOKUP_RATE_LIMITED',
        retryAfter: lookupLimit.retryAfterSeconds,
      });
    }
    rateLimitHit(lookupBucket, 60 * 1000);

    const codEstab = session.cod_estab;
    const estab = ESTABLECIMIENTOS_DB.find((e) => e.COD_ESTAB === codEstab) || ESTABLECIMIENTOS_DB[0];
    const nombreEstab = estab?.DESC_ESTAB || codEstab;
    const UPS_DX_CODES = ['99208', '90782', 'Z304', 'Z301', 'Z300'];

    const registrosHis = HIS_DL_DB.filter((h) => h.DNI === dni).sort((a, b) =>
      `${b.ANO}${String(b.MES).padStart(2, '0')}${String(b.DIA).padStart(2, '0')}`.localeCompare(
        `${a.ANO}${String(a.MES).padStart(2, '0')}${String(a.DIA).padStart(2, '0')}`
      )
    );
    const hisRecord = registrosHis[0] || null;
    const hisDetails = hisRecord
      ? HIS_DL_DT_DB.filter((dt) => dt.ID === hisRecord.ID).map((dt) => {
          const cie = ENFERMEDADES_CIE10_DB.find((c) => c.COD_ENF === dt.DX);
          const ciclo = cie?.CICLO_DIAS ?? 0;
          return {
            ...dt,
            DESC_ENF: cie ? cie.DESC_ENF : 'DIAGNOSTICO / PROCEDIMIENTO HIS',
            METODO_CORTO: cie ? cie.METODO_CORTO : 'Atención HIS',
            CICLO_DIAS: ciclo,
            FECHA_PROXIMA_CITA: ciclo > 0 ? addDaysToDate(hisRecord.fecha_reg, ciclo) : null,
          };
        })
      : [];

    const hoy = new Date().toISOString().slice(0, 10);
    const hasActiveMethodInHis = hisDetails.some(
      (d) => d.CICLO_DIAS > 0 && d.FECHA_PROXIMA_CITA && d.FECHA_PROXIMA_CITA >= hoy
    );

    // 99208: revisa TODOS los registros del DNI, no solo el último.
    const historial99208: Array<{
      establecimiento: string;
      cod_estab: string;
      fecha: string;
      fecha_iso: string;
      profesional: string;
      dx: string;
      tdx: string;
      ldx: string;
    }> = [];
    for (const registro of registrosHis) {
      const detalles = HIS_DL_DT_DB.filter((dt) => dt.ID === registro.ID);
      for (const dt of detalles) {
        if (dt.DX !== '99208') continue;
        historial99208.push({
          establecimiento: nombreEstablecimiento(registro.COD_ESTAB),
          cod_estab: codigoEstablecimientoCanonico(registro.COD_ESTAB),
          fecha: fechaDesdeFilaHis(registro),
          fecha_iso: dt.fecha_reg || registro.fecha_reg,
          profesional: registro.CODPSAL || '',
          dx: dt.DX,
          tdx: dt.TDX || '',
          ldx: dt.LDX || '',
        });
      }
    }
    const tieneCodigo99208 = historial99208.length > 0;
    const primer99208 = historial99208[0] || null;
    const mensajeOficial99208 = tieneCodigo99208
      ? `La paciente con DNI ${dni} recibió atención con el código 99208 en el establecimiento ${primer99208?.establecimiento} en la fecha ${primer99208?.fecha}.`
      : `La paciente con DNI ${dni} no registra atención con el código 99208 en la Red Huaral-Chancay.`;

    // UPS Planificación Familiar del establecimiento seleccionado por la obstetra.
    const atencionesUps: Array<Record<string, unknown>> = [];
    for (const registro of registrosHis) {
      if (codigoEstablecimientoCanonico(registro.COD_ESTAB) !== codEstab) continue;
      const detalles = HIS_DL_DT_DB.filter((dt) => dt.ID === registro.ID);
      const cumpleUps =
        registro.COD_SERVSA === '302304' ||
        detalles.some((dt) => UPS_DX_CODES.includes(dt.DX));
      if (!cumpleUps) continue;
      const detallePrincipal = detalles.find((dt) => UPS_DX_CODES.includes(dt.DX)) || detalles[0];
      atencionesUps.push({
        id_his: registro.ID,
        fecha: fechaDesdeFilaHis(registro),
        cod_servsa: registro.COD_SERVSA,
        dx: detallePrincipal?.DX || '',
        profesional: registro.CODPSAL,
        id_dosis: detallePrincipal?.id_dosis || '',
        alerta: detallePrincipal?.Alerta || '',
      });
    }
    const tieneAtencionPreviaUps = atencionesUps.length > 0;
    const mensajeUps = tieneAtencionPreviaUps
      ? `Paciente YA REGISTRADA en la UPS de Planificación Familiar del establecimiento ${nombreEstab}. Pase directo habilitado.`
      : `Paciente no registra atención previa en la UPS de Planificación Familiar de ${nombreEstab}. Complete el registro de captación.`;

    const existingCaptacion = PACIENTES_SIN_METODO_DB.find((p) => p.dni === dni);
    const dist = hisRecord ? DISTRITOS_DB.find((d) => d.UBIGEO === hisRecord.UBIGEO) : null;

    appendAuditLog({
      actor_dni: session.dni,
      actor_estab: codEstab,
      actor_nombre: session.nombreCompleto,
      actor_rol: session.rol,
      ip_address: ip,
      platform,
      action: 'HIS_DNI_LOOKUP',
      resource: `his_dl / DNI:${dni}`,
      severity: 'INFO',
      status: 'SUCCESS',
      details: `Validación de DNI ${dni} en ${nombreEstab}. 99208: ${
        tieneCodigo99208 ? 'SÍ' : 'NO'
      }. UPS PF previa: ${tieneAtencionPreviaUps ? 'SÍ (Caso A)' : 'NO (Caso B)'}.`,
    });

    if (tieneCodigo99208) {
      appendAuditLog({
        actor_dni: session.dni,
        actor_estab: codEstab,
        actor_nombre: session.nombreCompleto,
        actor_rol: session.rol,
        ip_address: ip,
        platform,
        action: 'VERIFICACION_99208',
        resource: `his_dl_dt / DNI:${dni} / DX:99208`,
        severity: 'WARNING',
        status: 'SUCCESS',
        details: mensajeOficial99208,
      });
    }

    res.json({
      foundInHis: !!hisRecord,
      foundInEstablecimiento: hisRecord
        ? codigoEstablecimientoCanonico(hisRecord.COD_ESTAB) === codEstab
        : false,
      hasActiveMethodInHis,
      alreadyInPacientesSinMetodo: !!existingCaptacion,
      hisRecord: hisRecord
        ? {
            ...hisRecord,
            Apellido_p: hisRecord.Apellido_p.trim(),
            DESC_DIST: dist ? dist.DESC_DIST : 'HUARAL',
            DESC_ESTAB: nombreEstablecimiento(hisRecord.COD_ESTAB),
          }
        : null,
      hisDetails,
      existingCaptacion: existingCaptacion
        ? {
            ...existingCaptacion,
            celular: decryptFieldAES256(existingCaptacion.celular),
            correo: decryptFieldAES256(existingCaptacion.correo),
            direccion: decryptFieldAES256(existingCaptacion.direccion),
          }
        : null,
      establecimiento: {
        codigo: codEstab,
        nombre: nombreEstab,
        categoria: estab?.CATEGORIA || '',
        distrito: estab?.DISTRITO || '',
      },
      atencion99208: {
        tieneCodigo99208,
        mensajeOficial99208,
        historial99208,
      },
      upsPlanificacionFamiliar: {
        establecimiento: { codigo: codEstab, nombre: nombreEstab },
        codigosUps: ['302304'],
        tieneAtencionPrevia: tieneAtencionPreviaUps,
        caso: tieneAtencionPreviaUps ? 'A' : 'B',
        mensaje: mensajeUps,
        atenciones: atencionesUps,
      },
    });
  });

  // --- REGISTER OR UPDATE PATIENT IN `pacientes_sin_metodo` ---
  app.post('/api/pacientes', (req: Request, res: Response) => {
    const session = requireSession(req, res);
    if (!session) return;
    const platform = detectPlatform(req.headers['user-agent']);
    const ip = getClientIp(req);
    const paseUps = Boolean(req.body?.pase_ups);
    const atencion99208 = Boolean(req.body?.atencion_99208);

    const dni = sanitizeText(req.body?.dni, 15).replace(/\D/g, '');
    let apellido_paterno = sanitizeText(req.body?.apellido_paterno, 50).toUpperCase();
    let apellido_materno = sanitizeText(req.body?.apellido_materno, 50).toUpperCase();
    let nombres = sanitizeText(req.body?.nombres, 80).toUpperCase();
    let edad = Number(req.body?.edad);
    let celularPlain = sanitizeText(req.body?.celular, 15);
    let correoPlain = sanitizeText(req.body?.correo, 150);
    let distrito = sanitizeText(req.body?.distrito, 80).toUpperCase();
    let direccionPlain = sanitizeText(req.body?.direccion, 200);
    let sector = sanitizeText(req.body?.sector, 50).toUpperCase();
    const estadosValidos: PacienteSinMetodoRow['estado_paciente'][] = [
      'INSATISFECHA_SIN_METODO',
      'CAPTADA_CON_METODO',
      'SEGUIMIENTO_DOMICILIARIO',
      'CONSEJERIA_REALIZADA',
      'RECHAZA_METODO',
    ];
    const estadoSolicitado = sanitizeText(
      req.body?.estado_paciente || 'INSATISFECHA_SIN_METODO',
      30
    ) as PacienteSinMetodoRow['estado_paciente'];
    const estado_paciente = estadosValidos.includes(estadoSolicitado)
      ? estadoSolicitado
      : 'INSATISFECHA_SIN_METODO';
    const codpsal_obstetra = sanitizeText(req.body?.codpsal_obstetra || session.dni, 11);

    // Caso A: "Confirmar Pase / Control en UPS" puede enviar solo el DNI.
    // Se autocompleta con la captación previa o con el registro HIS sin redigitar.
    if (paseUps && (!apellido_paterno || !apellido_materno || !nombres || !direccionPlain || !sector || !edad)) {
      const existente = PACIENTES_SIN_METODO_DB.find((p) => p.dni === dni);
      const his = HIS_DL_DB.find((h) => h.DNI === dni);
      apellido_paterno = apellido_paterno || existente?.apellido_paterno || his?.Apellido_p.trim() || 'SIN DATO';
      apellido_materno = apellido_materno || existente?.apellido_materno || his?.Apellido_m.trim() || 'SIN DATO';
      nombres = nombres || existente?.nombres || his?.Dnombres || his?.Pnombre || 'SIN DATO';
      if (!edad || Number.isNaN(edad)) edad = existente?.edad || his?.EDAD || 18;
      celularPlain = celularPlain || (existente ? decryptFieldAES256(existente.celular) : '');
      correoPlain = correoPlain || (existente ? decryptFieldAES256(existente.correo) : '');
      distrito = distrito || existente?.distrito || 'HUARAL';
      direccionPlain = direccionPlain || (existente ? decryptFieldAES256(existente.direccion) : '') || 'NO REGISTRADA - ACTUALIZAR EN CAMPO';
      sector = sector || existente?.sector || 'UPS PLANIFICACION FAMILIAR';
    }

    if (!/^\d{8,15}$/.test(dni)) {
      return res.status(400).json({ error: 'El DNI de la paciente debe contener entre 8 y 15 dígitos numéricos.' });
    }
    if (!apellido_paterno || !apellido_materno || !nombres || !distrito || !direccionPlain || !sector) {
      return res.status(400).json({ error: 'Complete todos los campos requeridos de pacientes_sin_metodo (incluyendo dirección y sector).' });
    }
    if (isNaN(edad) || edad < 10 || edad > 65) {
      return res.status(400).json({ error: 'La edad en planificación familiar debe estar entre 10 y 65 años.' });
    }

    const existingIdx = PACIENTES_SIN_METODO_DB.findIndex((p) => p.dni === dni);

    const encryptedCelular = encryptFieldAES256(celularPlain);
    const encryptedCorreo = encryptFieldAES256(correoPlain);
    const encryptedDireccion = encryptFieldAES256(direccionPlain);
    const nowTimestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);

    if (existingIdx >= 0) {
      const anterior = PACIENTES_SIN_METODO_DB[existingIdx];
      PACIENTES_SIN_METODO_DB[existingIdx] = {
        ...anterior,
        apellido_paterno,
        apellido_materno,
        nombres,
        edad,
        celular: encryptedCelular,
        correo: encryptedCorreo,
        distrito,
        direccion: encryptedDireccion,
        sector,
        estado_paciente,
        codpsal_obstetra,
        cod_estab: session.cod_estab,
        atencion_99208: Boolean(anterior.atencion_99208 || atencion99208),
      };

      appendAuditLog({
        actor_dni: session.dni,
        actor_estab: session.cod_estab,
        actor_nombre: session.nombreCompleto,
        actor_rol: session.rol,
        ip_address: String(ip),
        platform,
        action: paseUps ? 'PASE_UPS_CONFIRMADO' : 'PACIENTE_UPDATE',
        resource: `pacientes_sin_metodo / DNI:${dni}`,
        severity: 'INFO',
        status: 'SUCCESS',
        details: `Paciente existente DNI ${dni} (${apellido_paterno} ${apellido_materno}) ${
          paseUps ? 'con pase directo confirmado en la UPS de Planificación Familiar' : 'actualizada'
        } en ${session.estab_nombre}, sin duplicar registro (uk_dni_paciente). Estado: ${estado_paciente}.`,
      });

      return res.json({
        mode: paseUps ? 'PASE_UPS' : 'UPDATED',
        message: paseUps
          ? 'Pase directo confirmado en la UPS de Planificación Familiar.'
          : 'La paciente ya existía en el padrón: se actualizaron sus datos sin duplicar el registro (uk_dni_paciente).',
        id: PACIENTES_SIN_METODO_DB[existingIdx].id,
        atencion_99208: Boolean(PACIENTES_SIN_METODO_DB[existingIdx].atencion_99208),
      });
    }

    const newId = PACIENTES_SIN_METODO_DB.length > 0 ? Math.max(...PACIENTES_SIN_METODO_DB.map((p) => p.id)) + 1 : 1;
    const newRow: PacienteSinMetodoRow = {
      id: newId,
      dni,
      apellido_paterno,
      apellido_materno,
      nombres,
      edad,
      celular: encryptedCelular,
      correo: encryptedCorreo,
      distrito,
      direccion: encryptedDireccion,
      sector,
      estado_paciente,
      codpsal_obstetra,
      cod_estab: session.cod_estab,
      atencion_99208: atencion99208,
      fecha_registro: nowTimestamp,
    };

    PACIENTES_SIN_METODO_DB.unshift(newRow);
    securityMetrics.encryptedRecordsCount = PACIENTES_SIN_METODO_DB.length;

    appendAuditLog({
      actor_dni: session.dni,
      actor_estab: session.cod_estab,
      actor_nombre: session.nombreCompleto,
      actor_rol: session.rol,
      ip_address: String(ip),
      platform,
      action: paseUps ? 'PASE_UPS_CONFIRMADO' : 'NUEVA_PACIENTE_INGRESADA',
      resource: `pacientes_sin_metodo / ID:${newId} (DNI:${dni})`,
      severity: 'INFO',
      status: 'SUCCESS',
      details: paseUps
        ? `Pase directo confirmado en la UPS de Planificación Familiar de ${session.estab_nombre} para DNI ${dni} (${apellido_paterno} ${apellido_materno}, ${nombres}).`
        : `[NUEVA PACIENTE INGRESADA EN CAMPO] DNI ${dni} (${apellido_paterno} ${apellido_materno}, ${nombres}) en Distrito: ${distrito}, Sector: ${sector}. Captada por Obstetra CODPSAL: ${codpsal_obstetra}.`,
    });

    return res.status(201).json({
      mode: paseUps ? 'PASE_UPS' : 'INSERTED',
      message: paseUps
        ? 'Pase directo confirmado en la UPS de Planificación Familiar.'
        : 'Nueva paciente insatisfecha ingresada exitosamente en pacientes_sin_metodo (Cifrado AES-256-GCM activo).',
      id: newId,
      atencion_99208: atencion99208,
    });
  });

  app.patch('/api/pacientes/:id/estado', (req: Request, res: Response) => {
    const session = requireSession(req, res);
    if (!session) return;
    const id = Number(req.params.id);
    const nuevoEstado = sanitizeText(req.body?.estado_paciente, 30) as PacienteSinMetodoRow['estado_paciente'];
    const platform = detectPlatform(req.headers['user-agent']);
    const ip = getClientIp(req);

    const estadosValidos: PacienteSinMetodoRow['estado_paciente'][] = [
      'INSATISFECHA_SIN_METODO',
      'CAPTADA_CON_METODO',
      'SEGUIMIENTO_DOMICILIARIO',
      'CONSEJERIA_REALIZADA',
      'RECHAZA_METODO',
    ];
    if (!estadosValidos.includes(nuevoEstado)) {
      return res.status(400).json({ error: 'Estado clínico inválido.' });
    }

    const row = PACIENTES_SIN_METODO_DB.find((p) => p.id === id);
    if (!row) {
      return res.status(404).json({ error: 'Registro no encontrado en pacientes_sin_metodo.' });
    }

    const estadoAnterior = row.estado_paciente;
    row.estado_paciente = nuevoEstado;

    appendAuditLog({
      actor_dni: session.dni,
      actor_estab: session.cod_estab,
      actor_nombre: session.nombreCompleto,
      actor_rol: session.rol,
      ip_address: String(ip),
      platform,
      action: 'PACIENTE_STATUS_CHANGE',
      resource: `pacientes_sin_metodo / ID:${id} (DNI:${row.dni})`,
      severity: 'INFO',
      status: 'SUCCESS',
      details: `Cambio de estado clínico en Huaral: [${estadoAnterior}] -> [${nuevoEstado}] por Obstetra CODPSAL ${session.dni}.`,
    });

    res.json({ success: true, id, estado_paciente: nuevoEstado });
  });

  // --- AUDIT LOGS & CRYPTOGRAPHIC INTEGRITY VERIFICATION ---
  app.get('/api/audit/logs', (req: Request, res: Response) => {
    const session = requireSession(req, res);
    if (!session) return;
    const requested = Number(req.query.limit || 200);
    const limit = Number.isFinite(requested) ? Math.min(Math.max(requested, 1), 500) : 200;
    res.json({
      logs: [...AUDIT_LOGS_DB].reverse().slice(0, limit),
      total: AUDIT_LOGS_DB.length,
    });
  });

  app.post('/api/audit/verify-chain', (req: Request, res: Response) => {
    const session = requireSession(req, res);
    if (!session) return;
    const platform = detectPlatform(req.headers['user-agent']);
    const ip = getClientIp(req);

    let valid = true;
    let brokenAtId: number | null = null;

    for (let i = 0; i < AUDIT_LOGS_DB.length; i++) {
      const entry = AUDIT_LOGS_DB[i];
      const expectedPrev = i === 0 ? '0'.repeat(64) : AUDIT_LOGS_DB[i - 1].record_hash;
      const payloadToHash = `${entry.id}|${entry.timestamp}|${entry.actor_dni}|${entry.actor_estab}|${entry.action}|${entry.resource}|${entry.status}|${entry.details}|${expectedPrev}`;
      const recalculated = crypto.createHash('sha256').update(payloadToHash).digest('hex');

      if (entry.prev_hash !== expectedPrev || entry.record_hash !== recalculated) {
        valid = false;
        brokenAtId = entry.id;
        break;
      }
    }

    appendAuditLog({
      actor_dni: session.dni,
      actor_estab: session.cod_estab,
      actor_nombre: session.nombreCompleto,
      actor_rol: session.rol,
      ip_address: String(ip),
      platform,
      action: 'AUDIT_CHAIN_VERIFICATION',
      resource: 'audit_logs / SHA-256',
      severity: 'INFO',
      status: 'SUCCESS',
      details: `Verificación criptográfica de cadena de auditoría ejecutada en Hospital Huaral (${AUDIT_LOGS_DB.length} registros verificados, integridad: ${valid ? '100% INTACTA' : 'ALTERADA'}).`,
    });

    res.json({
      valid,
      verifiedRecords: AUDIT_LOGS_DB.length,
      brokenAtId,
      latestHash: AUDIT_LOGS_DB.length > 0 ? AUDIT_LOGS_DB[AUDIT_LOGS_DB.length - 1].record_hash : null,
    });
  });

  // --- INTERACTIVE WAF & ENCRYPTION PENETRATION TEST SIMULATOR ---
  app.post('/api/security/test-waf', (req: Request, res: Response) => {
    const session = requireSession(req, res);
    if (!session) return;
    const rawPayload = String(req.body?.payload || '');
    const targetField = String(req.body?.targetField || 'dni');
    const platform = detectPlatform(req.headers['user-agent']);
    const ip = getClientIp(req);

    const check = detectMaliciousPayload(rawPayload);
    const sanitized = sanitizeText(rawPayload, 200);
    const sampleEncrypted = encryptFieldAES256(sanitized || 'Dato Clínico Sensible');

    if (check.type) {
      if (check.type === 'SQLI') securityMetrics.sqliBlockedCount++;
      if (check.type === 'XSS') securityMetrics.xssBlockedCount++;

      const audit = appendAuditLog({
        actor_dni: session.dni,
        actor_estab: session.cod_estab,
        actor_nombre: `${session.nombreCompleto} (Simulador Seguridad)`,
        actor_rol: session.rol,
        ip_address: String(ip),
        platform,
        action: check.type === 'SQLI' ? 'WAF_SQLI_BLOCKED' : 'WAF_XSS_BLOCKED',
        resource: `SIMULADOR_SEGURIDAD / campo:${targetField}`,
        severity: 'CRITICAL',
        status: 'BLOCKED',
        details: `Prueba de penetración bloqueada en Huaral: vector ${check.type} [${check.matched}] interceptado antes de llegar a la PC Servidor de Estadística.`,
      });

      return res.json({
        blocked: true,
        attackType: check.type,
        matchedPattern: check.matched,
        sanitizedOutput: sanitized,
        preparedStatementPreview: `INSERT INTO pacientes_sin_metodo (${targetField}) VALUES (?) -- Bound param: ${JSON.stringify(sanitized)} (No ejecutable como SQL)`,
        aes256Preview: sampleEncrypted,
        auditEntry: audit,
      });
    }

    return res.json({
      blocked: false,
      attackType: null,
      matchedPattern: null,
      sanitizedOutput: sanitized,
      preparedStatementPreview: `SELECT * FROM pacientes_sin_metodo WHERE ${targetField} = ? -- Bound param: ${JSON.stringify(sanitized)}`,
      aes256Preview: sampleEncrypted,
    });
  });

  // --- EXPORTACIÓN NUBE -> LOCAL, ÍNDICES 5 GB Y PAQUETE PHP ---
  app.get('/api/sync/export-local-sql', (req: Request, res: Response) => {
    const session = requireSession(req, res);
    if (!session) return;
    const modoSolicitado = String(req.query.modo || 'directo');
    const modo: 'directo' | 'puente' = modoSolicitado === 'puente' ? 'puente' : 'directo';
    const { sql, tablas, filas, batch } = generarSqlSync(modo);
    const indexSql = fs.existsSync(path.join(__dirname, 'optimizar_indices_5gb.sql'))
      ? fs.readFileSync(path.join(__dirname, 'optimizar_indices_5gb.sql'), 'utf8')
      : '';

    appendAuditLog({
      actor_dni: session.dni,
      actor_estab: session.cod_estab,
      actor_nombre: session.nombreCompleto,
      actor_rol: session.rol,
      ip_address: getClientIp(req),
      platform: session.platform,
      action: 'SYNC_EXPORT_LOCAL_SQL',
      resource: 'sync_cloud_to_local / INSERT ON DUPLICATE KEY UPDATE',
      severity: 'INFO',
      status: 'SUCCESS',
      details: `Exportación Nube -> Local generada en modo ${modo} para tablas: ${tablas.join(
        ', '
      )} (${filas} filas, LIMIT ${batch}). Sin DROP/DELETE.`,
    });

    res.json({
      success: true,
      filename: `sync_nube_a_local_${new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14)}.sql`,
      generatedAt: new Date().toISOString(),
      mode: modo,
      batchLimit: batch,
      tables: tablas,
      rows: filas,
      sql,
      indexSql,
      warnings: [
        'Las tablas pacientes_sin_metodo y auditoria_seguridad_app son exclusivas de la nube y NO se exportan.',
        'Ejecute siempre dentro de una transacción y con respaldo previo de la base local de 5 GB.',
        'El script no incluye DROP/TRUNCATE/DELETE: no borra datos históricos.',
      ],
    });
  });

  app.get('/api/sync/optimizar-indices.sql', (req: Request, res: Response) => {
    const session = requireSession(req, res);
    if (!session) return;
    const filePath = path.join(__dirname, 'optimizar_indices_5gb.sql');
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'No se encontró optimizar_indices_5gb.sql.' });
    }
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="optimizar_indices_5gb.sql"');
    res.send(fs.readFileSync(filePath, 'utf8'));
  });

  // --- EXPORT PRODUCTION PHP / MARIADB HARDENED FILES FOR HOSPITAL HUARAL (PC ESTADÍSTICA + SERVIDOR CÓMPUTO ING. ALEX) ---
  app.get('/api/export/php-bundle', (req: Request, res: Response) => {
    const session = requireSession(req, res);
    if (!session) return;
    const dbPhp = `<?php
/**
 * db.php — Conexión Blindada PDO para Hospital San Juan Bautista Huaral
 * Arquitectura:
 *  - Servidor Web / Dominio Institucional: Unidad de Cómputo (Ing. Alex)
 *  - Servidor de Base de Datos Local (10.4.32-MariaDB, esquema "app"): PC Servidor de Estadística (DIRESA / MINSA)
 *  - Mantiene 100% intactas las tablas his_dl, his_dl_dt, mstrpers, usuario, establec, dist
 *  - Aplica cifrado AES-256-GCM en pacientes_sin_metodo sin alterar sus columnas
 */
declare(strict_types=1);

class HospitalHuaralDatabase {
    private static ?PDO $pdo = null;

    public static function getConnection(): PDO {
        if (self::$pdo === null) {
            // IP de la PC que sirve como servidor en el Área de Estadística (o 127.0.0.1 si se aloja en la misma PC)
            $host = getenv('DB_HOST_ESTADISTICA') ?: '192.168.1.100'; // Cambiar por IP LAN de la PC de Estadística o localhost
            $port = getenv('DB_PORT') ?: '3306';
            $dbname = getenv('DB_NAME') ?: 'app';
            $user = getenv('DB_USER') ?: 'app_obstetricia_huaral';
            $pass = getenv('DB_PASS') ?: 'CLAVE_SEGURA_ESTADISTICA_2026';

            $dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset=utf8mb4";
            $options = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                // BLOQUEO NATIVO DE INYECCIÓN SQL EN MARIADB 10.4.32
                PDO::ATTR_EMULATE_PREPARES   => false,
                PDO::ATTR_TIMEOUT            => 5,
            ];
            self::$pdo = new PDO($dsn, $user, $pass, $options);
        }
        return self::$pdo;
    }

    // Cifrado autenticado AES-256-GCM para proteger celular, correo y dirección de las pacientes de Huaral
    public static function encryptPII(string $plaintext): string {
        if ($plaintext === '') return '';
        $key = hash('sha256', getenv('HUARAL_AES_SECRET') ?: 'CLAVE_MAESTRA_HOSPITAL_HUARAL_256', true);
        $iv = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        return 'enc:gcm:' . bin2hex($iv) . ':' . bin2hex($tag) . ':' . bin2hex($ciphertext);
    }

    public static function decryptPII(?string $stored): string {
        if (!$stored || !str_starts_with($stored, 'enc:gcm:')) return (string)$stored;
        $parts = explode(':', $stored);
        if (count($parts) !== 5) return '[FORMATO_INVALIDO]';
        $key = hash('sha256', getenv('HUARAL_AES_SECRET') ?: 'CLAVE_MAESTRA_HOSPITAL_HUARAL_256', true);
        $iv = hex2bin($parts[2]);
        $tag = hex2bin($parts[3]);
        $ciphertext = hex2bin($parts[4]);
        $decrypted = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        return $decrypted !== false ? $decrypted : '[DATO_PROTEGIDO]';
    }
}
`;

    const apiPhp = `<?php
/**
 * api.php — API REST Blindada para Hospital San Juan Bautista Huaral (iPhone iOS, Android y Web)
 * - Conecta el aplicativo móvil de las Obstetras (Lic. Roxana y equipo) con la BD "app" de Estadística
 * - Valida DNI en vivo contra his_dl y his_dl_dt (detecta si ya recibe método o si es insatisfecha)
 * - Calcula agenda de próximas citas de ampolla mensual (30 días) y trimestral (90 días)
 * - Inserta/Actualiza en pacientes_sin_metodo sin duplicar registros (ON DUPLICATE KEY UPDATE sobre uk_dni_paciente)
 */
declare(strict_types=1);
require_once __DIR__ . '/db.php';

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';");

$pdo = HospitalHuaralDatabase::getConnection();

function sanitizeInput(?string $val, int $maxLen = 150): string {
    if ($val === null) return '';
    $clean = trim(strip_tags($val));
    return mb_substr(htmlspecialchars($clean, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'), 0, $maxLen);
}

$action = $_GET['action'] ?? '';

// 1. VALIDAR PACIENTE POR DNI EN CAMPO (Cruza con his_dl, his_dl_dt y pacientes_sin_metodo)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && $action === 'validar_dni_campo') {
    $dni = preg_replace('/[^0-9]/', '', $_GET['dni'] ?? '');
    if (strlen($dni) < 8 || strlen($dni) > 15) {
        http_response_code(400);
        echo json_encode(['error' => 'DNI inválido']);
        exit;
    }

    $stmtHis = $pdo->prepare("
        SELECT h.ID, h.DNI, TRIM(h.Apellido_p) AS Apellido_p, h.Apellido_m, h.Pnombre, h.Dnombres,
               h.EDAD, h.SEXO, h.UBIGEO, h.FICHAFAM, h.HCLFAM, h.Fecha_Ultima_Regla,
               h.condicion_gestante, h.COD_ESTAB, h.CODPSAL, h.fecha_reg
        FROM his_dl h
        WHERE h.DNI = :dni
        ORDER BY h.ANO DESC, h.MES DESC, h.DIA DESC
        LIMIT 1
    ");
    $stmtHis->execute([':dni' => $dni]);
    $his = $stmtHis->fetch();

    $diagnosticos = [];
    if ($his) {
        $stmtDt = $pdo->prepare("
            SELECT dt.DX, dt.TDX, dt.LDX, dt.id_dosis, dt.Alerta, dt.fecha_reg,
                   DATE_ADD(dt.fecha_reg, INTERVAL 30 DAY) AS proxima_cita_30d
            FROM his_dl_dt dt
            WHERE dt.ID = :id
        ");
        $stmtDt->execute([':id' => $his['ID']]);
        $diagnosticos = $stmtDt->fetchAll();
    }

    echo json_encode([
        'encontrada_en_his' => (bool)$his,
        'paciente_his' => $his,
        'controles_his' => $diagnosticos
    ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    exit;
}

// 2. REGISTRAR PACIENTE INSATISFECHA DESDE CELULAR (iPhone / Android) SIN DUPLICAR
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'registrar_paciente_sin_metodo') {
    $raw = json_decode(file_get_contents('php://input'), true) ?? [];
    $dni = preg_replace('/[^0-9]/', '', (string)($raw['dni'] ?? ''));
    $apPaterno = sanitizeInput($raw['apellido_paterno'] ?? '', 50);
    $apMaterno = sanitizeInput($raw['apellido_materno'] ?? '', 50);
    $nombres   = sanitizeInput($raw['nombres'] ?? '', 80);
    $edad      = (int)($raw['edad'] ?? 0);
    $distrito  = sanitizeInput($raw['distrito'] ?? 'HUARAL', 80);
    $sector    = sanitizeInput($raw['sector'] ?? '', 50);
    $estado    = sanitizeInput($raw['estado_paciente'] ?? 'INSATISFECHA_SIN_METODO', 30);
    $obstetra  = preg_replace('/[^0-9]/', '', (string)($raw['codpsal_obstetra'] ?? ''));

    $celularEnc   = HospitalHuaralDatabase::encryptPII(sanitizeInput($raw['celular'] ?? '', 15));
    $correoEnc    = HospitalHuaralDatabase::encryptPII(sanitizeInput($raw['correo'] ?? '', 150));
    $direccionEnc = HospitalHuaralDatabase::encryptPII(sanitizeInput($raw['direccion'] ?? '', 200));

    $stmt = $pdo->prepare("
        INSERT INTO pacientes_sin_metodo
            (dni, apellido_paterno, apellido_materno, nombres, edad, celular, correo, distrito, direccion, sector, estado_paciente, codpsal_obstetra)
        VALUES
            (:dni, :ap_p, :ap_m, :nom, :edad, :cel, :cor, :dist, :dir, :sec, :est, :obst)
        ON DUPLICATE KEY UPDATE
            celular = VALUES(celular),
            correo = VALUES(correo),
            distrito = VALUES(distrito),
            direccion = VALUES(direccion),
            sector = VALUES(sector),
            estado_paciente = VALUES(estado_paciente),
            codpsal_obstetra = VALUES(codpsal_obstetra)
    ");
    $stmt->execute([
        ':dni'  => $dni,
        ':ap_p' => $apPaterno,
        ':ap_m' => $apMaterno,
        ':nom'  => $nombres,
        ':edad' => $edad,
        ':cel'  => $celularEnc,
        ':cor'  => $correoEnc,
        ':dist' => $distrito,
        ':dir'  => $direccionEnc,
        ':sec'  => $sector,
        ':est'  => $estado,
        ':obst' => $obstetra,
    ]);

    echo json_encode(['status' => 'ok', 'hospital' => 'San Juan Bautista Huaral', 'encrypted' => 'AES-256-GCM']);
    exit;
}
`;

    res.json({ dbPhp, apiPhp });
  });

  // Descargas operativas para el equipo de Estadística (sin PII).
  app.get('/optimizar_indices_5gb.sql', (_req: Request, res: Response) => {
    const filePath = path.join(__dirname, 'optimizar_indices_5gb.sql');
    if (!fs.existsSync(filePath)) return res.status(404).send('Archivo no encontrado.');
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(fs.readFileSync(filePath, 'utf8'));
  });
  app.get('/sync_cloud_to_local.php', (_req: Request, res: Response) => {
    const filePath = path.join(__dirname, 'sync_cloud_to_local.php');
    if (!fs.existsSync(filePath)) return res.status(404).send('Archivo no encontrado.');
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(fs.readFileSync(filePath, 'utf8'));
  });

  // PWA: el mismo manifest y Service Worker sirven tanto al shell React (Vite)
  // como a la variante PHP/Apache de XAMPP. Se sirven antes de Vite para que
  // existan en desarrollo y en producción sin depender del plugin de Vite.
  const manifestCandidates = [
    path.join(__dirname, 'manifest.webmanifest'),
    path.join(__dirname, 'public', 'manifest.webmanifest'),
  ];
  app.get(['/manifest.webmanifest', '/manifest.json'], (_req: Request, res: Response) => {
    const manifestPath = manifestCandidates.find((candidate) => fs.existsSync(candidate));
    if (!manifestPath) return res.status(404).json({ error: 'Manifest PWA no encontrado.' });
    res.setHeader('Content-Type', 'application/manifest+json; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.send(fs.readFileSync(manifestPath, 'utf8'));
  });

  app.get('/sw.js', (_req: Request, res: Response) => {
    const swCandidates = [
      path.join(__dirname, 'sw.js'),
      path.join(__dirname, 'public', 'sw.js'),
    ];
    const swPath = swCandidates.find((candidate) => fs.existsSync(candidate));
    if (!swPath) return res.status(404).send('// Service Worker no encontrado');
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.setHeader('Service-Worker-Allowed', '/');
    res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
    res.send(fs.readFileSync(swPath, 'utf8'));
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        allowedHosts: true,
        hmr: false,
        watch: null,
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const PORT = 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`PlanificaSalud HIS Huaral Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
