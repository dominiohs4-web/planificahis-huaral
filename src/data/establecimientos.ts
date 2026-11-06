/**
 * Catálogo oficial IPRESS / RENIPRESS — Red de Salud Huaral-Chancay (DIRESA Lima)
 * Fuente: Establecimientos.xlsx (53 establecimientos).
 *
 * `COD_ESTAB` es el código HIS histórico usado en `his_dl.COD_ESTAB`.
 * `COD_IPRESS` es el código IPRESS/RENIPRESS oficial. Cuando el Excel trae dos
 * códigos, el segundo se conserva en `COD_IPRESS_ALT` para no romper registros
 * históricos. NUNCA se modifica la tabla `his_dl` del hospital.
 */
export const RED_HUARAL_CHANCAY = 'RED DE SALUD HUARAL - CHANCAY';

export type CategoriaIPRESS = 'I-1' | 'I-2' | 'I-3' | 'II-2';

export interface EstablecimientoRed {
  COD_ESTAB: string;
  COD_IPRESS: string;
  COD_IPRESS_ALT?: string;
  DESC_ESTAB: string;
  CATEGORIA: CategoriaIPRESS;
  DISTRITO: string;
  UBIGEO: string;
  DESC_RED: string;
  DESC_MICRO: string;
  COD_DISA: string;
  COD_RED: string;
  COD_MIC: string;
}

const BASE = {
  DESC_RED: RED_HUARAL_CHANCAY,
  COD_DISA: '15',
  COD_RED: '06',
} as const;

const UBIGEO: Record<string, string> = {
  HUARAL: '150601',
  'ATAVILLOS ALTO': '150602',
  'ATAVILLOS BAJO': '150603',
  AUCALLAMA: '150604',
  CHANCAY: '150605',
  IHUARI: '150606',
  LAMPIAN: '150607',
  PACARAOS: '150608',
  'SAN MIGUEL DE ACOS': '150609',
  'SANTA CRUZ DE ANDAMARCA': '150610',
  SUMBILCA: '150611',
  'VEINTISIETE DE NOVIEMBRE': '150612',
};

function e(
  COD_ESTAB: string,
  DESC_ESTAB: string,
  CATEGORIA: CategoriaIPRESS,
  DISTRITO: string,
  COD_IPRESS: string,
  COD_MIC: string,
  COD_IPRESS_ALT?: string
): EstablecimientoRed {
  return {
    COD_ESTAB,
    COD_IPRESS,
    ...(COD_IPRESS_ALT ? { COD_IPRESS_ALT } : {}),
    DESC_ESTAB,
    CATEGORIA,
    DISTRITO,
    UBIGEO: UBIGEO[DISTRITO],
    DESC_RED: BASE.DESC_RED,
    DESC_MICRO: `MICRORED ${DISTRITO}`,
    COD_DISA: BASE.COD_DISA,
    COD_RED: BASE.COD_RED,
    COD_MIC,
  };
}

export const ESTABLECIMIENTOS_RED: EstablecimientoRed[] = [
  // ======================= HUARAL (12) =======================
  e('000005481', 'HOSPITAL DE APOYO HUARAL / SAN JUAN BAUTISTA', 'II-2', 'HUARAL', '000007637', '01', '000005481'),
  e('000005831', 'C.S. BASE HUARAL', 'I-3', 'HUARAL', '000005831', '01'),
  e('000005833', 'C.S. EL TRÉBOL', 'I-3', 'HUARAL', '000005833', '01'),
  e('000005826', 'C.S. LA QUERENCIA', 'I-3', 'HUARAL', '000005826', '01'),
  e('000005827', 'P.S. TÚPAC AMARU', 'I-2', 'HUARAL', '000005827', '01'),
  e('000005828', 'P.S. CABUYAL', 'I-2', 'HUARAL', '000005828', '01'),
  e('000005829', 'P.S. HUERTA MARGARET', 'I-2', 'HUARAL', '000005829', '01'),
  e('000005832', 'P.S. JECUÁN', 'I-2', 'HUARAL', '000005832', '01'),
  e('000005830', 'P.S. CENTENARIO HUACHO CHICO', 'I-2', 'HUARAL', '000005830', '01'),
  e('000007188', 'P.S. LUMBRA', 'I-1', 'HUARAL', '000007188', '01'),
  e('000007189', 'P.S. CUYO', 'I-1', 'HUARAL', '000007189', '01'),
  e('000010937', 'P.S. CONTIGO PERÚ', 'I-2', 'HUARAL', '000010937', '01'),

  // =================== ATAVILLOS ALTO (5) ====================
  e('000005586', 'C.S. PIRCA', 'I-2', 'ATAVILLOS ALTO', '000005586', '02'),
  e('000005587', 'P.S. PASAC', 'I-1', 'ATAVILLOS ALTO', '000005587', '02'),
  e('000007195', 'P.S. CHISQUE', 'I-1', 'ATAVILLOS ALTO', '000007195', '02'),
  e('000005588', 'P.S. BAÑOS', 'I-1', 'ATAVILLOS ALTO', '000005588', '02'),
  e('000005589', 'P.S. HUAROQUÍN', 'I-1', 'ATAVILLOS ALTO', '000005589', '02'),

  // =================== ATAVILLOS BAJO (4) ====================
  e('000005578', 'C.S. HUAYOPAMPA', 'I-3', 'ATAVILLOS BAJO', '000005578', '03'),
  e('000005579', 'P.S. LA PERLA', 'I-2', 'ATAVILLOS BAJO', '000005579', '03'),
  e('000007208', 'P.S. PALLAC', 'I-1', 'ATAVILLOS BAJO', '000007208', '03'),
  e('000005580', 'P.S. LA FLORIDA', 'I-1', 'ATAVILLOS BAJO', '000005580', '03'),

  // ======================= IHUARI (5) ========================
  e('000005593', 'P.S. HUACHINGA', 'I-1', 'IHUARI', '000005593', '04'),
  e('000005594', 'P.S. OTEC', 'I-1', 'IHUARI', '000005594', '04'),
  e('000005595', 'P.S. IHUARÍ', 'I-2', 'IHUARI', '000005595', '04'),
  e('000005596', 'P.S. YUNGUY', 'I-3', 'IHUARI', '000005596', '04'),
  e('000005597', 'P.S. ÑAUPAY', 'I-2', 'IHUARI', '000005597', '04'),

  // ======================= LAMPIAN (2) =======================
  e('000005581', 'P.S. LAMPIÁN', 'I-1', 'LAMPIAN', '000005581', '05'),
  e('000010936', 'P.S. CANCHAPILCA', 'I-1', 'LAMPIAN', '000010936', '05'),

  // ======================= PACARAOS (4) ======================
  e('000005590', 'C.S. PACARAOS', 'I-3', 'PACARAOS', '000005590', '06'),
  e('000007190', 'P.S. VISCAS', 'I-1', 'PACARAOS', '000007190', '06'),
  e('000007193', 'P.S. RAVIRA', 'I-1', 'PACARAOS', '000007193', '06'),
  e('000005591', 'P.S. VICHAYCOCHA', 'I-2', 'PACARAOS', '000005591', '06'),

  // ================== SAN MIGUEL DE ACOS (2) =================
  e('000005582', 'C.S. ACOS', 'I-3', 'SAN MIGUEL DE ACOS', '000005582', '07'),
  e('000005583', 'P.S. HUASCOY', 'I-1', 'SAN MIGUEL DE ACOS', '000005583', '07'),

  // =============== SANTA CRUZ DE ANDAMARCA (3) ===============
  e('000005592', 'C.S. SANTA CRUZ DE ANDAMARCA', 'I-2', 'SANTA CRUZ DE ANDAMARCA', '000005592', '08'),
  e('000007194', 'P.S. SANTA CATALINA', 'I-1', 'SANTA CRUZ DE ANDAMARCA', '000007194', '08'),
  e('000007196', 'P.S. CHAUCA', 'I-1', 'SANTA CRUZ DE ANDAMARCA', '000007196', '08'),

  // ======================= SUMBILCA (4) ======================
  e('000005584', 'C.S. SUMBILCA', 'I-1', 'SUMBILCA', '000005584', '09'),
  e('000007191', 'P.S. RAUMA', 'I-1', 'SUMBILCA', '000007191', '09'),
  e('000007192', 'P.S. HUÁNDARO', 'I-1', 'SUMBILCA', '000007192', '09'),
  e('000010938', 'P.S. PISCOCOTO', 'I-1', 'SUMBILCA', '000010938', '09'),

  // ============ VEINTISIETE DE NOVIEMBRE (2) =================
  e('000005585', 'P.S. CARAC', 'I-1', 'VEINTISIETE DE NOVIEMBRE', '000005585', '10'),
  e('000007209', 'P.S. COTO', 'I-1', 'VEINTISIETE DE NOVIEMBRE', '000007209', '10'),

  // ======================= CHANCAY (6) =======================
  e('000007638', 'HOSPITAL DE CHANCAY', 'II-2', 'CHANCAY', '000007638', '11'),
  e('000005485', 'C.S. PERALVILLO', 'I-3', 'CHANCAY', '000005729', '11', '000005485'),
  e('000005731', 'C.S. PEDRO CANEVARO GARAY - CHANCAYLLO', 'I-3', 'CHANCAY', '000005731', '11'),
  e('000005730', 'P.S. PAMPA LIBRE', 'I-3', 'CHANCAY', '000005730', '11'),
  e('000005733', 'C.S. QUEPEPAMPA', 'I-3', 'CHANCAY', '000005733', '11'),
  e('000005732', 'P.S. CERRO LA CULEBRA', 'I-2', 'CHANCAY', '000005732', '11'),

  // ======================= AUCALLAMA (4) =====================
  e('000005489', 'C.S. AUCALLAMA', 'I-3', 'AUCALLAMA', '000005726', '12', '000005489'),
  e('000005727', 'P.S. PALPA', 'I-3', 'AUCALLAMA', '000005727', '12'),
  e('000005728', 'P.S. PASAMAYO', 'I-2', 'AUCALLAMA', '000005728', '12'),
  e('000010990', 'P.S. CAQUI', 'I-3', 'AUCALLAMA', '000010990', '12'),
];

/** Alias de compatibilidad con datos antiguos de la app (no se envían al HIS). */
const ALIAS_COD_ESTAB: Record<string, string> = {
  '000005482': '000005831', // C.S. Base Huaral (código antiguo de la app)
};

export const TOTAL_ESTABLECIMIENTOS = ESTABLECIMIENTOS_RED.length; // 53

export function getEstablecimiento(codigo: string | null | undefined): EstablecimientoRed | null {
  const clean = String(codigo || '').trim();
  if (!clean) return null;
  const canonical = ALIAS_COD_ESTAB[clean] || clean;
  return (
    ESTABLECIMIENTOS_RED.find(
      (est) =>
        est.COD_ESTAB === canonical ||
        est.COD_IPRESS === canonical ||
        est.COD_IPRESS_ALT === canonical
    ) || null
  );
}

export function nombreEstablecimiento(codigo: string | null | undefined): string {
  return getEstablecimiento(codigo)?.DESC_ESTAB || String(codigo || 'SIN ESTABLECIMIENTO');
}

export function codigoEstablecimientoCanonico(codigo: string | null | undefined): string {
  return getEstablecimiento(codigo)?.COD_ESTAB || String(codigo || '');
}

export const ESTABLECIMIENTOS_POR_DISTRITO: Record<string, EstablecimientoRed[]> =
  ESTABLECIMIENTOS_RED.reduce((acc, est) => {
    acc[est.DISTRITO] = acc[est.DISTRITO] || [];
    acc[est.DISTRITO].push(est);
    return acc;
  }, {} as Record<string, EstablecimientoRed[]>);
