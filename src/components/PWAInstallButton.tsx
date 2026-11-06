import React, { useState } from 'react';
import { Download, Smartphone, Share, PlusSquare, CheckCircle2, X } from 'lucide-react';
import { usePWAInstall, useOnlineStatus } from '../hooks/usePWAInstall';

export const PWAInstallButton: React.FC = () => {
  const { isInstallable, isInstalled, isIOS, install } = usePWAInstall();
  const [showGuideModal, setShowGuideModal] = useState(false);

  if (isInstalled) {
    return null;
  }

  return (
    <>
      <button
        type="button"
        onClick={async () => {
          if (isInstallable) {
            await install();
          } else {
            setShowGuideModal(true);
          }
        }}
        className="min-h-[44px] px-3.5 py-2 rounded-xl bg-teal-700 hover:bg-teal-800 text-white text-xs font-semibold flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer shadow-xs"
      >
        <Download className="w-4 h-4 shrink-0" />
        <span>{isIOS ? 'Instalar en iPhone' : 'Instalar App Móvil'}</span>
      </button>

      {showGuideModal && (
        <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-slate-950/60 backdrop-blur-xs p-4">
          <div className="w-full max-w-md rounded-2xl bg-white border border-slate-200 p-6 shadow-xl">
            <div className="flex items-center justify-between pb-4 border-b border-slate-100">
              <div className="flex items-center gap-2.5">
                <Smartphone className="w-5 h-5 text-teal-700" />
                <h3 className="text-base font-bold text-slate-900">
                  Instalación en Android y iPhone (iOS)
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowGuideModal(false)}
                className="min-h-[44px] min-w-[44px] flex items-center justify-center text-slate-400 hover:text-slate-700 rounded-lg"
                aria-label="Cerrar guía"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="mt-4 space-y-4 text-sm text-slate-600">
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200/80">
                <p className="font-semibold text-slate-900">En iPhone / iPad (Safari iOS)</p>
                <ol className="mt-2 space-y-1.5 text-xs text-slate-600 list-decimal list-inside">
                  <li className="flex items-center gap-1.5">
                    <span>1. Toca el botón</span>
                    <Share className="w-3.5 h-3.5 text-teal-700 inline" />
                    <strong className="text-slate-800">Compartir</strong> en la barra inferior de Safari.
                  </li>
                  <li className="flex items-center gap-1.5">
                    <span>2. Selecciona</span>
                    <PlusSquare className="w-3.5 h-3.5 text-teal-700 inline" />
                    <strong className="text-slate-800">Agregar a pantalla de inicio</strong>.
                  </li>
                  <li>3. Abre PlanificaHIS desde tu inicio a pantalla completa sin barras.</li>
                </ol>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200/80">
                <p className="font-semibold text-slate-900">En Android (Chrome / Edge)</p>
                <ol className="mt-2 space-y-1.5 text-xs text-slate-600 list-decimal list-inside">
                  <li>1. Toca el menú de 3 puntos arriba a la derecha en Chrome.</li>
                  <li>
                    2. Elige <strong className="text-slate-800">Instalar aplicación</strong> o{' '}
                    <strong className="text-slate-800">Añadir a pantalla de inicio</strong>.
                  </li>
                  <li className="flex items-center gap-1.5 text-teal-700 font-medium pt-1">
                    <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                    <span>Incluye Service Worker con caché offline para zonas sin señal.</span>
                  </li>
                </ol>
              </div>
            </div>

            <button
              type="button"
              onClick={() => setShowGuideModal(false)}
              className="mt-5 w-full min-h-[44px] rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-sm font-semibold transition-colors cursor-pointer"
            >
              Entendido
            </button>
          </div>
        </div>
      )}
    </>
  );
};

export const OfflineBanner: React.FC = () => {
  const isOnline = useOnlineStatus();
  if (isOnline) return null;

  return (
    <div className="bg-amber-600 text-white px-4 py-2 text-xs font-medium flex items-center justify-center gap-2">
      <span>Modo sin conexión activo (Offline) — Trabajando con caché local seguro en dispositivo móvil.</span>
    </div>
  );
};
