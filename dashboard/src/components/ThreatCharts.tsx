import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Cell
} from 'recharts';
import { Alert, Statistics } from '../types';

interface ThreatChartsProps {
  alerts: Alert[];
  stats: Statistics | null;
}

export const ThreatCharts: React.FC<ThreatChartsProps> = ({ alerts, stats }) => {
  // Build time series data (alerts in 10-second buckets)
  const timeSeriesData = React.useMemo(() => {
    const buckets: Record<string, number> = {};
    const now = Date.now();
    for (let i = 9; i >= 0; i--) {
      const t = new Date(now - i * 10000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      buckets[t] = 0;
    }

    alerts.forEach((alert) => {
      try {
        const t = new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        if (buckets[t] !== undefined) {
          buckets[t] += 1;
        }
      } catch (e) {}
    });

    return Object.entries(buckets).map(([time, count]) => ({ time, count }));
  }, [alerts]);

  // Build threat class distribution
  const distributionData = React.useMemo(() => {
    const counts: Record<string, number> = stats?.threat_distribution || {};
    if (Object.keys(counts).length === 0) {
      alerts.forEach((a) => {
        counts[a.threat_class] = (counts[a.threat_class] || 0) + 1;
      });
    }

    const COLORS: Record<string, string> = {
      SYN_FLOOD: '#EF4444',
      UDP_FLOOD: '#F97316',
      UDP_AMPLIFICATION: '#DC2626',
      C2_BEACONING: '#F59E0B',
      PORT_SCAN: '#3B82F6',
      HOST_SCAN: '#6366F1',
      DGA_DOMAIN: '#8B5CF6',
      DNS_TUNNELING: '#EC4899',
      EXFILTRATION: '#10B981',
      UNKNOWN_ANOMALY: '#64748B'
    };

    return Object.entries(counts).map(([name, count]) => ({
      name,
      count,
      color: COLORS[name] || '#3B82F6'
    }));
  }, [alerts, stats]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Real-time Threat Activity Line Chart */}
      <div className="lg:col-span-2 bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-gray-200 tracking-wide uppercase">
            Live Threat Frequency Over Time
          </h2>
          <span className="text-xs font-mono text-cyan-400">10s Aggregation</span>
        </div>
        <div className="h-56 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeSeriesData}>
              <defs>
                <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00F0FF" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#00F0FF" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" />
              <XAxis dataKey="time" stroke="#6B7280" fontSize={11} />
              <YAxis stroke="#6B7280" fontSize={11} allowDecimals={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', color: '#F3F4F6' }}
              />
              <Area
                type="monotone"
                dataKey="count"
                stroke="#00F0FF"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#threatGradient)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Threat Distribution Chart */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-gray-200 tracking-wide uppercase">
            Threat Class Distribution
          </h2>
          <span className="text-xs font-mono text-gray-400">Categories</span>
        </div>
        <div className="h-56 w-full">
          {distributionData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={distributionData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" />
                <XAxis type="number" stroke="#6B7280" fontSize={11} />
                <YAxis dataKey="name" type="category" stroke="#6B7280" fontSize={10} width={90} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', color: '#F3F4F6' }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {distributionData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-gray-500">
              Awaiting threat telemetry...
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
