import {createRoot} from 'react-dom/client';
import {registerSW} from 'virtual:pwa-register';
import App from './App.tsx';
import './index.css';

// Service Worker: caché de la app y funcionamiento en zonas rurales sin señal.
registerSW({immediate: true});

createRoot(document.getElementById('root')!).render(<App />);
