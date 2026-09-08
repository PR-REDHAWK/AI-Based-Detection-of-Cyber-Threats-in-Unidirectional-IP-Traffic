import React from 'react';
import { ShieldAlert, Eye, Lock, Radio } from 'lucide-react';

interface HeaderProps {
  isConnected: boolean;
}

export const Header: React.FC<HeaderProps> = ({ isConnected }) => {
  return (
    <header className="bg-gray-900 border-b border-gray-800 px-6 py-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
      <div className="flex items-center gap-3">
        <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg">
          <ShieldAlert className="w-8 h-8 text-cyan-400" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-white tracking-wider flex items-center gap-2">
            OracleShield
            <span className="text-xs font-semibold px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
              PROTOTYPE v1.0
            </span>
          </h1>
          <p className="text-xs text-gray-400">Passive AI Network Threat Detection Engine</p>
        </div>
      </div>

      {/* Security Status Badges */}
      <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
        {/* Connection Badge */}
        <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full border ${
          isConnected 
            ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-400' 
            : 'bg-amber-950/60 border-amber-500/40 text-amber-400'
        }`}>
          <Radio className="w-3.5 h-3.5 animate-pulse" />
          <span>{isConnected ? 'STREAMING ACTIVE' : 'CONNECTING...'}</span>
        </div>

        {/* Read-Only Badge */}
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-blue-950/60 border border-blue-500/40 text-blue-400">
          <Eye className="w-3.5 h-3.5" />
          <span>READ-ONLY INGEST</span>
        </div>

        {/* Unidirectional Constraint Badge */}
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-purple-950/60 border border-purple-500/40 text-purple-400">
          <Lock className="w-3.5 h-3.5" />
          <span>NO ACTIVE RESPONSE</span>
        </div>
      </div>
    </header>
  );
};
