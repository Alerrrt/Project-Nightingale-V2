import React from 'react';
import { motion } from 'framer-motion';
import { Shield, AlertTriangle, Clock, CheckCircle } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const StatCard = ({ title, value, icon: Icon, trend, className }) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.3 }}
  >
    <Card className={className}>
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-neutral-500 dark:text-neutral-400">{title}</p>
            <h3 className="text-2xl font-bold mt-1">{value}</h3>
            {trend && (
              <p className={`text-sm mt-2 ${trend > 0 ? 'text-success' : 'text-danger'}`}>
                {trend > 0 ? '+' : ''}{trend}% from last month
              </p>
            )}
          </div>
          <div className="p-3 rounded-full bg-primary-50 dark:bg-primary-900">
            <Icon className="w-6 h-6 text-primary-600 dark:text-primary-400" />
          </div>
        </div>
      </CardContent>
    </Card>
  </motion.div>
);

const Dashboard = () => {
  // Sample data - replace with real data from your API
  const stats = {
    totalScans: 156,
    vulnerabilitiesFound: 42,
    averageScanTime: '4m 23s',
    successRate: '98%',
  };

  const scanHistory = [
    { date: '2024-01', scans: 12, vulnerabilities: 8 },
    { date: '2024-02', scans: 15, vulnerabilities: 6 },
    { date: '2024-03', scans: 18, vulnerabilities: 4 },
    { date: '2024-04', scans: 20, vulnerabilities: 3 },
    { date: '2024-05', scans: 25, vulnerabilities: 2 },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors">
          New Scan
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Scans"
          value={stats.totalScans}
          icon={Shield}
          trend={12}
        />
        <StatCard
          title="Vulnerabilities Found"
          value={stats.vulnerabilitiesFound}
          icon={AlertTriangle}
          trend={-8}
        />
        <StatCard
          title="Average Scan Time"
          value={stats.averageScanTime}
          icon={Clock}
        />
        <StatCard
          title="Success Rate"
          value={stats.successRate}
          icon={CheckCircle}
          trend={2}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Scan History</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-[400px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={scanHistory}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis yAxisId="left" />
                <YAxis yAxisId="right" orientation="right" />
                <Tooltip />
                <Line
                  yAxisId="left"
                  type="monotone"
                  dataKey="scans"
                  stroke="#0ea5e9"
                  strokeWidth={2}
                  dot={{ r: 4 }}
                  activeDot={{ r: 6 }}
                />
                <Line
                  yAxisId="right"
                  type="monotone"
                  dataKey="vulnerabilities"
                  stroke="#ef4444"
                  strokeWidth={2}
                  dot={{ r: 4 }}
                  activeDot={{ r: 6 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Dashboard; 