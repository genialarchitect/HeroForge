import React, { useState } from 'react';
import { DollarSign, TrendingUp, Users, Calendar, Target, PieChart, BarChart3, ArrowUpRight } from 'lucide-react';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Area, AreaChart } from 'recharts';

const FinancialModelPage: React.FC = () => {
  const [view, setView] = useState<'summary' | 'revenue' | 'economics' | 'pl' | 'cashflow'>('summary');

  // Revenue Projections (from INVESTOR_STRATEGY_2025.md)
  const revenueData = [
    {
      period: 'Q4 2025',
      mrr: 83000,
      arr: 996000,
      customers: { solo: 300, professional: 200, team: 30, enterprise: 2 },
      cac: 300,
      ltv: 6000,
    },
    {
      period: 'Q1 2026',
      mrr: 100000,
      arr: 1200000,
      customers: { solo: 380, professional: 250, team: 40, enterprise: 3 },
      cac: 350,
      ltv: 6200,
    },
    {
      period: 'Q2 2026',
      mrr: 125000,
      arr: 1500000,
      customers: { solo: 450, professional: 310, team: 55, enterprise: 5 },
      cac: 400,
      ltv: 6500,
    },
    {
      period: 'Q3 2026',
      mrr: 150000,
      arr: 1800000,
      customers: { solo: 520, professional: 380, team: 70, enterprise: 7 },
      cac: 450,
      ltv: 7000,
    },
    {
      period: 'Q4 2026',
      mrr: 180000,
      arr: 2160000,
      customers: { solo: 600, professional: 450, team: 85, enterprise: 10 },
      cac: 500,
      ltv: 7500,
    },
    {
      period: 'Year 2',
      mrr: 542000,
      arr: 6500000,
      customers: { solo: 1200, professional: 900, team: 180, enterprise: 25 },
      cac: 600,
      ltv: 8000,
    },
    {
      period: 'Year 3',
      mrr: 1275000,
      arr: 15300000,
      customers: { solo: 2500, professional: 2000, team: 400, enterprise: 60 },
      cac: 700,
      ltv: 9000,
    },
  ];

  // Revenue by tier breakdown
  const tierBreakdown = [
    { tier: 'Solo ($99)', q4_2025: 29700, year_1: 60000, year_2: 120000, year_3: 247500 },
    { tier: 'Professional ($299)', q4_2025: 59800, year_1: 119600, year_2: 269100, year_3: 598000 },
    { tier: 'Team ($599)', q4_2025: 17970, year_1: 35940, year_2: 107820, year_3: 239600 },
    { tier: 'Enterprise ($5000)', q4_2025: 10000, year_1: 30000, year_2: 125000, year_3: 300000 },
  ];

  // P&L Projections
  const plData = [
    {
      year: 'Year 1 (2026)',
      revenue: 1400000,
      cogs: 140000, // 10% (cloud hosting, infrastructure)
      grossMargin: 1260000,
      salesMarketing: 720000, // 51% of revenue
      rd: 560000, // 40% of revenue
      ga: 280000, // 20% of revenue
      ebitda: -300000,
      netIncome: -300000,
    },
    {
      year: 'Year 2 (2027)',
      revenue: 6500000,
      cogs: 650000, // 10%
      grossMargin: 5850000,
      salesMarketing: 2600000, // 40% of revenue
      rd: 1950000, // 30% of revenue
      ga: 975000, // 15% of revenue
      ebitda: 325000,
      netIncome: 325000,
    },
    {
      year: 'Year 3 (2028)',
      revenue: 15300000,
      cogs: 1530000, // 10%
      grossMargin: 13770000,
      salesMarketing: 4590000, // 30% of revenue
      rd: 3825000, // 25% of revenue
      ga: 2295000, // 15% of revenue
      ebitda: 3060000,
      netIncome: 3060000,
    },
  ];

  // Cash Flow & Runway
  const cashFlowData = [
    { month: 'Jan 26', cash: 6000000, burn: -150000, runway: 40 },
    { month: 'Apr 26', cash: 5550000, burn: -140000, runway: 40 },
    { month: 'Jul 26', cash: 5130000, burn: -120000, runway: 43 },
    { month: 'Oct 26', cash: 4770000, burn: -100000, runway: 48 },
    { month: 'Jan 27', cash: 4470000, burn: -80000, runway: 56 },
    { month: 'Apr 27', cash: 4230000, burn: -50000, runway: 85 },
    { month: 'Jul 27', cash: 4080000, burn: -20000, runway: 204 },
    { month: 'Oct 27', cash: 4020000, burn: 20000, runway: Infinity }, // Profitable
    { month: 'Jan 28', cash: 4380000, burn: 60000, runway: Infinity },
  ];

  // Unit Economics Chart
  const unitEconomicsChart = revenueData.slice(0, 5).map((d) => ({
    period: d.period,
    CAC: d.cac,
    LTV: d.ltv,
    ratio: (d.ltv / d.cac).toFixed(1),
  }));

  const StatCard: React.FC<{
    icon: React.ReactNode;
    label: string;
    value: string;
    subtext?: string;
    trend?: 'up' | 'down';
  }> = ({ icon, label, value, subtext, trend }) => (
    <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
      <div className="flex items-center justify-between mb-2">
        <div className="p-2 bg-cyan-500/10 rounded-lg">{icon}</div>
        {trend && (
          <span
            className={`text-sm font-medium ${
              trend === 'up' ? 'text-green-400' : 'text-red-400'
            }`}
          >
            <ArrowUpRight className="w-4 h-4 inline" />
          </span>
        )}
      </div>
      <p className="text-gray-400 text-sm mb-1">{label}</p>
      <p className="text-2xl font-bold text-white">{value}</p>
      {subtext && <p className="text-gray-500 text-xs mt-1">{subtext}</p>}
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <div className="bg-gradient-to-r from-cyan-600 to-blue-600 px-8 py-12">
        <div className="max-w-7xl mx-auto">
          <h1 className="text-4xl font-bold mb-4">Financial Model & Projections</h1>
          <p className="text-cyan-100 text-lg max-w-3xl">
            5-year financial projections for HeroForge, showcasing revenue growth, unit economics,
            and path to profitability. Based on conservative market penetration and proven
            SaaS metrics.
          </p>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-8">
          <div className="flex space-x-8">
            {[
              { key: 'summary', label: 'Executive Summary', icon: TrendingUp },
              { key: 'revenue', label: 'Revenue Model', icon: DollarSign },
              { key: 'economics', label: 'Unit Economics', icon: Target },
              { key: 'pl', label: 'P&L Projection', icon: BarChart3 },
              { key: 'cashflow', label: 'Cash Flow', icon: PieChart },
            ].map((tab) => (
              <button
                key={tab.key}
                onClick={() => setView(tab.key as any)}
                className={`flex items-center gap-2 py-4 border-b-2 transition ${
                  view === tab.key
                    ? 'border-cyan-500 text-cyan-400'
                    : 'border-transparent text-gray-400 hover:text-gray-300'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto px-8 py-12">
        {/* Executive Summary */}
        {view === 'summary' && (
          <div className="space-y-8">
            <div>
              <h2 className="text-2xl font-bold mb-6">Key Metrics (Current → Year 3)</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatCard
                  icon={<DollarSign className="w-6 h-6 text-cyan-400" />}
                  label="ARR Growth"
                  value="$1M → $15.3M"
                  subtext="15x growth in 3 years"
                  trend="up"
                />
                <StatCard
                  icon={<Users className="w-6 h-6 text-cyan-400" />}
                  label="Total Customers"
                  value="532 → 4,960"
                  subtext="9.3x customer base expansion"
                  trend="up"
                />
                <StatCard
                  icon={<Target className="w-6 h-6 text-cyan-400" />}
                  label="LTV:CAC Ratio"
                  value="20:1 → 12.9:1"
                  subtext="Healthy unit economics"
                  trend="up"
                />
                <StatCard
                  icon={<Calendar className="w-6 h-6 text-cyan-400" />}
                  label="Payback Period"
                  value="3 → 5.2 months"
                  subtext="Still under 6 months (target)"
                  trend="up"
                />
              </div>
            </div>

            {/* ARR Growth Chart */}
            <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
              <h3 className="text-xl font-bold mb-4">ARR Growth Trajectory</h3>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={revenueData}>
                  <defs>
                    <linearGradient id="colorArr" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="period" stroke="#9ca3af" />
                  <YAxis stroke="#9ca3af" tickFormatter={(v) => `$${(v / 1000000).toFixed(1)}M`} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151' }}
                    formatter={(value: any) => [`$${(value / 1000).toFixed(0)}K`, 'ARR']}
                  />
                  <Area
                    type="monotone"
                    dataKey="arr"
                    stroke="#06b6d4"
                    strokeWidth={2}
                    fill="url(#colorArr)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            {/* Key Assumptions */}
            <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
              <h3 className="text-xl font-bold mb-4">Model Assumptions</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="font-semibold text-cyan-400 mb-2">Revenue Growth Drivers</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li>• Freemium conversion rate: 15% → 25% (Year 1)</li>
                    <li>• Average monthly churn: 1.5% → 0.8% (Year 3)</li>
                    <li>• Net revenue retention (NRR): 110% → 120%</li>
                    <li>• Expansion revenue: 30% of total by Year 2</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-semibold text-cyan-400 mb-2">Go-to-Market Mix</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li>• Content Marketing: 40% of new customers (organic)</li>
                    <li>• Paid Acquisition: 35% (LinkedIn + Google Ads)</li>
                    <li>• MSP Partnerships: 15% (referral program)</li>
                    <li>• Enterprise Outbound: 10% (high ACV deals)</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Revenue Model */}
        {view === 'revenue' && (
          <div className="space-y-8">
            <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
              <h2 className="text-2xl font-bold mb-6">Revenue by Tier</h2>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-3 px-4">Tier</th>
                      <th className="text-right py-3 px-4">Q4 2025 (MRR)</th>
                      <th className="text-right py-3 px-4">Year 1 (2026)</th>
                      <th className="text-right py-3 px-4">Year 2 (2027)</th>
                      <th className="text-right py-3 px-4">Year 3 (2028)</th>
                      <th className="text-right py-3 px-4">Growth (Y1→Y3)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tierBreakdown.map((tier, i) => (
                      <tr key={i} className="border-b border-gray-700/50">
                        <td className="py-3 px-4 font-medium">{tier.tier}</td>
                        <td className="text-right py-3 px-4">${tier.q4_2025.toLocaleString()}</td>
                        <td className="text-right py-3 px-4">${tier.year_1.toLocaleString()}</td>
                        <td className="text-right py-3 px-4">${tier.year_2.toLocaleString()}</td>
                        <td className="text-right py-3 px-4">${tier.year_3.toLocaleString()}</td>
                        <td className="text-right py-3 px-4 text-green-400">
                          {((tier.year_3 / tier.year_1) * 100 - 100).toFixed(0)}%
                        </td>
                      </tr>
                    ))}
                    <tr className="border-t-2 border-gray-700 font-bold">
                      <td className="py-3 px-4">Total MRR</td>
                      <td className="text-right py-3 px-4">
                        ${tierBreakdown.reduce((sum, t) => sum + t.q4_2025, 0).toLocaleString()}
                      </td>
                      <td className="text-right py-3 px-4">
                        ${tierBreakdown.reduce((sum, t) => sum + t.year_1, 0).toLocaleString()}
                      </td>
                      <td className="text-right py-3 px-4">
                        ${tierBreakdown.reduce((sum, t) => sum + t.year_2, 0).toLocaleString()}
                      </td>
                      <td className="text-right py-3 px-4">
                        ${tierBreakdown.reduce((sum, t) => sum + t.year_3, 0).toLocaleString()}
                      </td>
                      <td className="text-right py-3 px-4 text-green-400">412%</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* Customer Mix Chart */}
            <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
              <h3 className="text-xl font-bold mb-4">Customer Distribution Over Time</h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={revenueData.slice(0, 5)}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="period" stroke="#9ca3af" />
                  <YAxis stroke="#9ca3af" />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151' }}
                  />
                  <Legend />
                  <Bar dataKey="customers.solo" stackId="a" fill="#06b6d4" name="Solo ($99)" />
                  <Bar dataKey="customers.professional" stackId="a" fill="#3b82f6" name="Professional ($299)" />
                  <Bar dataKey="customers.team" stackId="a" fill="#8b5cf6" name="Team ($599)" />
                  <Bar dataKey="customers.enterprise" stackId="a" fill="#10b981" name="Enterprise ($5K+)" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* Unit Economics */}
        {view === 'economics' && (
          <div className="space-y-8">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <StatCard
                icon={<DollarSign className="w-6 h-6 text-cyan-400" />}
                label="Average CAC"
                value="$300 → $700"
                subtext="Increases with Enterprise focus"
              />
              <StatCard
                icon={<Target className="w-6 h-6 text-cyan-400" />}
                label="Average LTV"
                value="$6,000 → $9,000"
                subtext="50% growth from NRR + expansion"
              />
              <StatCard
                icon={<TrendingUp className="w-6 h-6 text-cyan-400" />}
                label="LTV:CAC Ratio"
                value="20:1 → 12.9:1"
                subtext="Well above 3:1 benchmark"
                trend="up"
              />
            </div>

            {/* LTV vs CAC Chart */}
            <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
              <h3 className="text-xl font-bold mb-4">LTV vs CAC Evolution</h3>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={unitEconomicsChart}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="period" stroke="#9ca3af" />
                  <YAxis stroke="#9ca3af" tickFormatter={(v) => `$${v}`} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151' }}
                    formatter={(value: any, name: string) => {
                      if (name === 'ratio') return [`${value}:1`, 'LTV:CAC Ratio'];
                      return [`$${value}`, name];
                    }}
                  />
                  <Legend />
                  <Line type="monotone" dataKey="LTV" stroke="#10b981" strokeWidth={2} name="LTV" />
                  <Line type="monotone" dataKey="CAC" stroke="#ef4444" strokeWidth={2} name="CAC" />
                </LineChart>
              </ResponsiveContainer>
            </div>

            {/* Economics Breakdown */}
            <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
              <h3 className="text-xl font-bold mb-4">Economics by Tier (Year 2)</h3>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-3 px-4">Tier</th>
                      <th className="text-right py-3 px-4">CAC</th>
                      <th className="text-right py-3 px-4">LTV</th>
                      <th className="text-right py-3 px-4">Ratio</th>
                      <th className="text-right py-3 px-4">Payback (mo)</th>
                      <th className="text-right py-3 px-4">Gross Margin</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-gray-700/50">
                      <td className="py-3 px-4 font-medium">Solo ($99/mo)</td>
                      <td className="text-right py-3 px-4">$150</td>
                      <td className="text-right py-3 px-4">$3,564</td>
                      <td className="text-right py-3 px-4 text-green-400">23.8:1</td>
                      <td className="text-right py-3 px-4">1.5</td>
                      <td className="text-right py-3 px-4">95%</td>
                    </tr>
                    <tr className="border-b border-gray-700/50">
                      <td className="py-3 px-4 font-medium">Professional ($299/mo)</td>
                      <td className="text-right py-3 px-4">$500</td>
                      <td className="text-right py-3 px-4">$10,764</td>
                      <td className="text-right py-3 px-4 text-green-400">21.5:1</td>
                      <td className="text-right py-3 px-4">1.7</td>
                      <td className="text-right py-3 px-4">92%</td>
                    </tr>
                    <tr className="border-b border-gray-700/50">
                      <td className="py-3 px-4 font-medium">Team ($599/mo)</td>
                      <td className="text-right py-3 px-4">$3,000</td>
                      <td className="text-right py-3 px-4">$21,564</td>
                      <td className="text-right py-3 px-4 text-green-400">7.2:1</td>
                      <td className="text-right py-3 px-4">5.0</td>
                      <td className="text-right py-3 px-4">88%</td>
                    </tr>
                    <tr className="border-b border-gray-700/50">
                      <td className="py-3 px-4 font-medium">Enterprise ($5,000/mo)</td>
                      <td className="text-right py-3 px-4">$25,000</td>
                      <td className="text-right py-3 px-4">$180,000</td>
                      <td className="text-right py-3 px-4 text-green-400">7.2:1</td>
                      <td className="text-right py-3 px-4">5.0</td>
                      <td className="text-right py-3 px-4">85%</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* P&L Projection */}
        {view === 'pl' && (
          <div className="space-y-8">
            <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
              <h2 className="text-2xl font-bold mb-6">Income Statement (3-Year Projection)</h2>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-3 px-4">Line Item</th>
                      <th className="text-right py-3 px-4">Year 1 (2026)</th>
                      <th className="text-right py-3 px-4">Year 2 (2027)</th>
                      <th className="text-right py-3 px-4">Year 3 (2028)</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-gray-700/50 bg-gray-700/20">
                      <td className="py-3 px-4 font-bold">Revenue</td>
                      <td className="text-right py-3 px-4 font-bold">
                        ${(plData[0].revenue / 1000).toFixed(0)}K
                      </td>
                      <td className="text-right py-3 px-4 font-bold">
                        ${(plData[1].revenue / 1000).toFixed(0)}K
                      </td>
                      <td className="text-right py-3 px-4 font-bold">
                        ${(plData[2].revenue / 1000).toFixed(0)}K
                      </td>
                    </tr>
                    <tr className="border-b border-gray-700/50">
                      <td className="py-3 px-4 pl-8">Cost of Goods Sold (10%)</td>
                      <td className="text-right py-3 px-4 text-red-400">
                        -${(plData[0].cogs / 1000).toFixed(0)}K
                      </td>
                      <td className="text-right py-3 px-4 text-red-400">
                        -${(plData[1].cogs / 1000).toFixed(0)}K
                      </td>
                      <td className="text-right py-3 px-4 text-red-400">
                        -${(plData[2].cogs / 1000).toFixed(0)}K
                      </td>
                    </tr>
                    <tr className="border-b border-gray-700/50 bg-gray-700/20">
                      <td className="py-3 px-4 font-semibold">Gross Margin (90%)</td>
                      <td className="text-right py-3 px-4 font-semibold">
                        ${(plData[0].grossMargin / 1000).toFixed(0)}K
                      </td>
                      <td className="text-right py-3 px-4 font-semibold">
                        ${(plData[1].grossMargin / 1000).toFixed(0)}K
                      </td>
                      <td className="text-right py-3 px-4 font-semibold">
                        ${(plData[2].grossMargin / 1000).toFixed(0)}K
                      </td>
                    </tr>
                    <tr className="border-b border-gray-700/50">
                      <td className="py-3 px-4 pl-8">Sales & Marketing</td>
                      <td className="text-right py-3 px-4 text-red-400">
                        -${(plData[0].salesMarketing / 1000).toFixed(0)}K
                      </td>
                      <td className="text-right py-3 px-4 text-red-400">
                        -${(plData[1].salesMarketing / 1000).toFixed(0)}K
                      </td>
                      <td className="text-right py-3 px-4 text-red-400">
                        -${(plData[2].salesMarketing / 1000).toFixed(0)}K
                      </td>
                    </tr>
                    <tr className="border-b border-gray-700/50">
                      <td className="py-3 px-4 pl-8">R&D</td>
                      <td className="text-right py-3 px-4 text-red-400">
                        -${(plData[0].rd / 1000).toFixed(0)}K
                      </td>
                      <td className="text-right py-3 px-4 text-red-400">
                        -${(plData[1].rd / 1000).toFixed(0)}K
                      </td>
                      <td className="text-right py-3 px-4 text-red-400">
                        -${(plData[2].rd / 1000).toFixed(0)}K
                      </td>
                    </tr>
                    <tr className="border-b border-gray-700/50">
                      <td className="py-3 px-4 pl-8">General & Admin</td>
                      <td className="text-right py-3 px-4 text-red-400">
                        -${(plData[0].ga / 1000).toFixed(0)}K
                      </td>
                      <td className="text-right py-3 px-4 text-red-400">
                        -${(plData[1].ga / 1000).toFixed(0)}K
                      </td>
                      <td className="text-right py-3 px-4 text-red-400">
                        -${(plData[2].ga / 1000).toFixed(0)}K
                      </td>
                    </tr>
                    <tr className="border-t-2 border-gray-700 bg-gray-700/30">
                      <td className="py-3 px-4 font-bold">EBITDA</td>
                      <td
                        className={`text-right py-3 px-4 font-bold ${
                          plData[0].ebitda < 0 ? 'text-red-400' : 'text-green-400'
                        }`}
                      >
                        ${(plData[0].ebitda / 1000).toFixed(0)}K
                      </td>
                      <td
                        className={`text-right py-3 px-4 font-bold ${
                          plData[1].ebitda < 0 ? 'text-red-400' : 'text-green-400'
                        }`}
                      >
                        ${(plData[1].ebitda / 1000).toFixed(0)}K
                      </td>
                      <td
                        className={`text-right py-3 px-4 font-bold ${
                          plData[2].ebitda < 0 ? 'text-red-400' : 'text-green-400'
                        }`}
                      >
                        ${(plData[2].ebitda / 1000).toFixed(0)}K
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* Operating Expenses Chart */}
            <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
              <h3 className="text-xl font-bold mb-4">Operating Expense Breakdown</h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={plData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="year" stroke="#9ca3af" />
                  <YAxis stroke="#9ca3af" tickFormatter={(v) => `$${(v / 1000000).toFixed(1)}M`} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151' }}
                    formatter={(value: any) => [`$${(value / 1000).toFixed(0)}K`]}
                  />
                  <Legend />
                  <Bar dataKey="salesMarketing" fill="#06b6d4" name="Sales & Marketing" />
                  <Bar dataKey="rd" fill="#3b82f6" name="R&D" />
                  <Bar dataKey="ga" fill="#8b5cf6" name="General & Admin" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* Cash Flow */}
        {view === 'cashflow' && (
          <div className="space-y-8">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <StatCard
                icon={<DollarSign className="w-6 h-6 text-cyan-400" />}
                label="Starting Cash (Series A)"
                value="$6.0M"
                subtext="January 2026"
              />
              <StatCard
                icon={<Calendar className="w-6 h-6 text-cyan-400" />}
                label="Runway at Launch"
                value="40 months"
                subtext="With $150K monthly burn"
              />
              <StatCard
                icon={<TrendingUp className="w-6 h-6 text-cyan-400" />}
                label="Cash Flow Positive"
                value="Q4 2027"
                subtext="24 months post-raise"
                trend="up"
              />
            </div>

            {/* Cash Burn Chart */}
            <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
              <h3 className="text-xl font-bold mb-4">Cash Balance & Monthly Burn</h3>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={cashFlowData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="month" stroke="#9ca3af" />
                  <YAxis stroke="#9ca3af" tickFormatter={(v) => `$${(v / 1000000).toFixed(1)}M`} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151' }}
                    formatter={(value: any, name: string) => {
                      if (name === 'Monthly Burn') return [`$${(value / 1000).toFixed(0)}K`, name];
                      return [`$${(value / 1000000).toFixed(2)}M`, name];
                    }}
                  />
                  <Legend />
                  <Line
                    type="monotone"
                    dataKey="cash"
                    stroke="#10b981"
                    strokeWidth={2}
                    name="Cash Balance"
                  />
                  <Line
                    type="monotone"
                    dataKey="burn"
                    stroke="#ef4444"
                    strokeWidth={2}
                    name="Monthly Burn"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>

            {/* Use of Funds */}
            <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
              <h3 className="text-xl font-bold mb-4">Use of Funds ($6M Series A)</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="font-semibold text-cyan-400 mb-3">Engineering (40% - $2.4M)</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li>• 4 backend engineers ($600K)</li>
                    <li>• 3 frontend engineers ($450K)</li>
                    <li>• 1 DevOps/SRE ($150K)</li>
                    <li>• 1 security researcher ($150K)</li>
                    <li>• Infrastructure & cloud costs ($600K)</li>
                    <li>• Tools & software licenses ($450K)</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-semibold text-cyan-400 mb-3">Go-to-Market (30% - $1.8M)</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li>• Sales team (2 AEs, 1 SE, 1 ISR) ($900K)</li>
                    <li>• Marketing (content, paid ads) ($600K)</li>
                    <li>• Partner program ($200K)</li>
                    <li>• Customer success ($100K)</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-semibold text-cyan-400 mb-3">Operations (15% - $900K)</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li>• Finance & legal ($300K)</li>
                    <li>• HR & recruiting ($250K)</li>
                    <li>• Office & facilities ($200K)</li>
                    <li>• Insurance & compliance ($150K)</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-semibold text-cyan-400 mb-3">Reserves (15% - $900K)</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li>• SOC2 audit & certifications ($200K)</li>
                    <li>• Contingency buffer ($400K)</li>
                    <li>• Strategic hires ($300K)</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Footer CTA */}
      <div className="bg-gray-800 border-t border-gray-700 px-8 py-8">
        <div className="max-w-7xl mx-auto text-center">
          <p className="text-gray-400 mb-4">
            Want to discuss these projections or learn more about our investment opportunity?
          </p>
          <a
            href="/investors"
            className="inline-flex items-center gap-2 bg-cyan-600 hover:bg-cyan-700 text-white px-6 py-3 rounded-lg font-semibold transition"
          >
            View Investor Materials
            <ArrowUpRight className="w-4 h-4" />
          </a>
        </div>
      </div>
    </div>
  );
};

export default FinancialModelPage;
