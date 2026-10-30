import React from 'react';
import { Header } from './components/Header';

export const App: React.FC = () => {
  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100">
      <Header />
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 flex flex-col items-center justify-center text-center">
        <div className="max-w-2xl bg-slate-900 border border-slate-800 rounded-xl p-8 shadow-2xl">
          <div className="inline-flex items-center justify-center p-3 bg-blue-600/10 text-blue-500 rounded-lg mb-4">
            <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-white mb-2">
            Sentinel-EDR SOC Console Scaffold
          </h2>
          <p className="text-sm text-slate-400 mb-6">
            Frontend foundation established with React, TypeScript, Vite, and Tailwind CSS.
            Security telemetry, incident queues, and real-time WebSocket monitors will connect in subsequent phases.
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
            <div className="bg-slate-800/60 p-3 rounded border border-slate-700/50">
              <span className="text-slate-400 block mb-1">Framework</span>
              <span className="text-white font-semibold">React 18</span>
            </div>
            <div className="bg-slate-800/60 p-3 rounded border border-slate-700/50">
              <span className="text-slate-400 block mb-1">Language</span>
              <span className="text-white font-semibold">TypeScript</span>
            </div>
            <div className="bg-slate-800/60 p-3 rounded border border-slate-700/50">
              <span className="text-slate-400 block mb-1">Bundler</span>
              <span className="text-white font-semibold">Vite</span>
            </div>
            <div className="bg-slate-800/60 p-3 rounded border border-slate-700/50">
              <span className="text-slate-400 block mb-1">Styling</span>
              <span className="text-white font-semibold">Tailwind CSS</span>
            </div>
          </div>
        </div>
      </main>
      <footer className="border-t border-slate-800/80 py-4 text-center text-xs text-slate-500">
        Sentinel-EDR &copy; 2026 &bull; Hybrid Endpoint Detection and Response System
      </footer>
    </div>
  );
};

export default App;
