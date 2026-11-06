import React, { useEffect, useState } from 'react';
import { Share, PlusSquare, X, Smartphone, ChevronRight } from 'lucide-react';

const DISMISS_KEY = 'planificahis.ios-install-dismissed.v1';

/**
 * Banner interactivo de instalación para Safari iOS.
 * iOS no dispara `beforeinstallprompt`, por lo que se explican los 2 pasos
 * oficiales: Compartir -> Agregar a pantalla de inicio.
 */
export const IOSInstallBanner: React.FC = () => {
  const [visible, setVisible] = useState(false);
  const [step, setStep] = useState<1 | 2>(1);

  useEffect(() => {
    try {
      if (localStorage.getItem(DISMISS_KEY) === '1') return;
    } catch {
      // localStorage puede estar deshabilitado en modo privado.
    }
    const ua = window.navigator.userAgent.toLowerCase();
    const isIOS = /iphone|ipad|ipod/.test(ua);
    const standalone =
      window.matchMedia('(display-mode: standalone)').matches ||
      (window.navigator as unknown as { standalone?: boolean }).standalone === true;
    if (isIOS && !standalone) setVisible(true);
  }, []);

  const dismiss = () => {
    setVisible(false);
    try {
      localStorage.setItem(DISMISS_KEY, '1');
    } catch {
      // Ignorar.
    }
  };

  if (!visible) return null;

  return (
    <div className="fixed inset-x-0 bottom-16 z-50 px-3 pb-[env(safe-area-inset-bottom)] pointer-events-none">
      <div className="mx-auto max-w-[430px] rounded-2xl bg-slate-950 text-white shadow-2xl border border-slate-700 p-4 pointer-events-auto">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2">
            <Smartphone className="w-5 h-5 text-sky-400 shrink-0" />
            <div>
              <div className="text-sm font-bold">Instalar PlanificaHIS en iPhone</div>
              <div className="text-[11px] text-slate-300">
                Paso {step} de 2 · Safari iOS
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={dismiss}
            aria-label="Cerrar instalación iOS"
            className="min-h-[36px] min-w-[36px] flex items-center justify-center rounded-lg text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {step === 1 ? (
          <div className="mt-3 flex items-start gap-3 text-xs text-slate-200">
            <div className="w-8 h-8 rounded-xl bg-sky-500/20 flex items-center justify-center shrink-0">
              <Share className="w-4 h-4 text-sky-300" />
            </div>
            <p>
              1. Toca el botón <strong className="text-white">Compartir</strong> en la barra
              inferior de Safari (el cuadro con la flecha hacia arriba).
            </p>
          </div>
        ) : (
          <div className="mt-3 flex items-start gap-3 text-xs text-slate-200">
            <div className="w-8 h-8 rounded-xl bg-sky-500/20 flex items-center justify-center shrink-0">
              <PlusSquare className="w-4 h-4 text-sky-300" />
            </div>
            <p>
              2. Desliza y elige{' '}
              <strong className="text-white">Agregar a pantalla de inicio</strong>, luego confirma
              con <strong className="text-white">Agregar</strong>. La app se abrirá a pantalla
              completa.
            </p>
          </div>
        )}

        <div className="mt-3 flex items-center justify-between gap-2">
          <button
            type="button"
            onClick={dismiss}
            className="min-h-[40px] px-3 rounded-xl text-xs font-semibold text-slate-300 hover:text-white"
          >
            Ahora no
          </button>
          {step === 1 ? (
            <button
              type="button"
              onClick={() => setStep(2)}
              className="min-h-[40px] px-4 rounded-xl bg-sky-600 hover:bg-sky-500 text-xs font-bold flex items-center gap-1.5"
            >
              <span>Siguiente paso</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          ) : (
            <button
              type="button"
              onClick={dismiss}
              className="min-h-[40px] px-4 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-xs font-bold"
            >
              Entendido
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
