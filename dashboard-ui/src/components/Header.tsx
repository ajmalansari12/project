import React from 'react';

interface HeaderProps {
  statusText?: string;
}

export const Header: React.FC<HeaderProps> = ({ statusText = 'Foundation Ready' }) => {
  return (
    <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur px-6 py-4">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="h-8 w-8 rounded bg-blue-600 flex items-center justify-center font-bold text-white shadow-lg shadow-blue-500/20">
            S
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight text-white">Sentinel-EDR</h1>
            <p className="text-xs text-slate-400">Endpoint Detection &amp; Response Console</p>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-950 text-emerald-400 border border-emerald-800">
            <span className="w-1.5 h-1.5 mr-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            {statusText}
          </span>
        </div>
      </div>
    </header>
  );
};
