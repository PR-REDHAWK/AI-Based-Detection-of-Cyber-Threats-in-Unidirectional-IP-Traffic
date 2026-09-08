import React from 'react';
import { Activity, Zap, ShieldAlert, AlertTriangle, Clock, Layers } from 'lucide-react';
import { Statistics } from '../types';

interface KPICardsProps {
  stats: Statistics | null;
}

export const KPICards: React.FC<KPICardsProps> = ({ stats }) => {
  const flowsPerSec = stats?.flows_per_sec ?? 0;
  const pktsPerSec = stats?.packets_per_sec ?? 0;
  const critCount = stats?.severity_counts?.CRITICAL ?? 0;
  const highCount = stats?.severity_counts?.HIGH ?? 0;
  const medCount = stats?.severity_counts?.MEDIUM ?? 0;
  const totalAlerts = stats?.total_alerts ?? 0;
  const latency = stats?.avg_latency_ms ?? 1.2;

  const cards = [
    {
      title: 'Flow Throughput',
      value: `${flowsPerSec.toLocaleString()} /s`,
      subtitle: `${pktsPerSec.toLocaleString()} pkts/s`,
      icon: Activity,
      color: 'text-cyan-400',
      border: 'border-cyan-500/20'
    },
    {
      title: 'Critical Threats',
      value: critCount.toString(),
      subtitle: 'Immediate Risk',
      icon: ShieldAlert,
      color: 'text-red-500',
      border: 'border-red-500/30',
      bg: 'bg-red-500/5'
    },
    {
      title: 'High Threats',
      value: highCount.toString(),
      subtitle: 'Elevated Risk',
      icon: AlertTriangle,
      color: 'text-orange-400',
      border: 'border-orange-500/20'
    },
    {
      title: 'Medium Threats',
      value: medCount.toString(),
      subtitle: 'Suspicious Behavior',
      icon: AlertTriangle,
      color: 'text-amber-400',
      border: 'border-amber-500/20'
    },
    {
      title: 'Active Detections',
      value: totalAlerts.toString(),
      subtitle: 'Total Raised Alerts',
      icon: Layers,
      color: 'text-purple-400',
      border: 'border-purple-500/20'
    },
    {
      title: 'Processing Latency',
      value: `${latency} ms`,
      subtitle: 'Stream Inference',
      icon: Clock,
      color: 'text-emerald-400',
      border: 'border-emerald-500/20'
    }
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={`bg-gray-900 border ${card.border} ${card.bg || ''} rounded-xl p-4 flex flex-col justify-between shadow-lg`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs text-gray-400 font-medium">{card.title}</span>
              <Icon className={`w-4 h-4 ${card.color}`} />
            </div>
            <div className="mt-3">
              <div className={`text-2xl font-bold font-mono tracking-tight text-white`}>
                {card.value}
              </div>
              <div className="text-[10px] text-gray-500 mt-0.5">{card.subtitle}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
};
