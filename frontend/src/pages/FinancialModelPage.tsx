import React, { useState } from 'react';
import { DollarSign, TrendingUp, Users, Calendar, Target, PieChart, BarChart3, ArrowUpRight } from 'lucide-react';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Area, AreaChart } from 'recharts';

const FinancialModelPage: React.FC = () => {
  const [view, setView] = useState<'summary' | 'revenue' | 'economics' | 'pl' | 'cashflow'>('summary');

  // Revenue Projections (Pre-Seed Reality - from INVESTOR_STRATEGY_2025.md)
  const revenueData = [
    {
      period: 'Now',
      mrr: 0,
      arr: 0,
      customers: { solo: 0, professional: 0, team: 0, enterprise: 0 },
      cac: 0,
      ltv: 0,
    },
    {
      period: 'M3 2026',
      mrr: 2000,
      arr: 24000,
      customers: { solo: 15, professional: 5, team: 0, enterprise: 0 },
      cac: 50,
      ltv: 1200,
    },
    {
      period: 'M6 2026',
      mrr: 5000,
      arr: 60000,
      customers: { solo: 35, professional: 12, team: 1, enterprise: 0 },
      cac: 70,
      ltv: 1500,
    },
    {
      period: 'M9 2026',
      mrr: 10000,
      arr: 120000,
      customers: { solo: 65, professional: 25, team: 3, enterprise: 0 },
      cac: 100,
      ltv: 1800,
    },
    {
      period: 'Year 1',
      mrr: 17000,
      arr: 200000,
      customers: { solo: 100, professional: 40, team: 5, enterprise: 1 },
      cac: 120,
      ltv: 2000,
    },
    {
      period: 'Year 2',
      mrr: 100000,
      arr: 1200000,
      customers: { solo: 500, professional: 200, team: 30, enterprise: 5 },
      cac: 200,
      ltv: 3000,
    },
    {
      period: 'Year 3',
      mrr: 417000,
      arr: 5000000,
      customers: { solo: 1200, professional: 500, team: 100, enterprise: 20 },
      cac: 300,
      ltv: 4000,
    },
  ];

  // Revenue by tier breakdown (MRR)
  const tierBreakdown = [
    { tier: 'Solo ($99)', now: 0, year_1: 9900, year_2: 49500, year_3: 118800 },
    { tier: 'Professional ($299)', now: 0, year_1: 11960, year_2: 59800, year_3: 149500 },
    { tier: 'Team ($599)', now: 0, year_1: 2995, year_2: 17970, year_3: 59900 },
    { tier: 'Enterprise ($5000)', now: 0, year_1: 5000, year_2: 25000, year_3: 100000 },
  ];

  // P&L Projections (Pre-Seed Reality - Solo Founder)
  const plData = [
    {
      year: 'Year 1 (2026)',
      revenue: 200000,
      cogs: 20000, // 10% (AWS, infrastructure)
      grossMargin: 180000,
      salesMarketing: 60000, // 30% (Reddit ads, YouTube production)
      rd: 60000, // 30% (founder time allocated to dev)
      ga: 60000, // 30% (founder living expenses, tools)
      ebitda: 0,
      netIncome: 0,
    },
    {
      year: 'Year 2 (2027)',
      revenue: 1200000,
      cogs: 120000, // 10%
      grossMargin: 1080000,
      salesMarketing: 360000, // 30% (community growth, content)
      rd: 300000, // 25% (first contractor hire)
      ga: 180000, // 15% (founder salary + ops)
      ebitda: 240000,
      netIncome: 240000,
    },
    {
      year: 'Year 3 (2028)',
      revenue: 5000000,
      cogs: 500000, // 10%
      grossMargin: 4500000,
      salesMarketing: 1500000, // 30% (sales team + marketing)
      rd: 1250000, // 25% (2-3 engineers)
      ga: 750000, // 15% (ops, admin, compliance)
      ebitda: 1000000,
      netIncome: 1000000,
    },
  ];

  // Cash Flow & Runway (Pre-Seed $1M Raise)
  const cashFlowData = [
    { month: 'Jan 26', cash: 1000000, burn: -15000, runway: 67 },
    { month: 'Apr 26', cash: 955000, burn: -12000, runway: 80 },
    { month: 'Jul 26', cash: 919000, burn: -10000, runway: 92 },
    { month: 'Oct 26', cash: 889000, burn: -8000, runway: 111 },
    { month: 'Jan 27', cash: 865000, burn: -5000, runway: 173 },
    { month: 'Apr 27', cash: 850000, burn: -2000, runway: 425 },
    { month: 'Jul 27', cash: 844000, burn: 0, runway: Infinity }, // Break-even
    { month: 'Oct 27', cash: 860000, burn: 20000, runway: Infinity }, // Profitable
    { month: 'Jan 28', cash: 920000, burn: 50000, runway: Infinity },
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
            3-year financial projections for HeroForge (pre-revenue to $5M ARR), showcasing realistic
            grassroots growth, unit economics, and path to profitability. Solo founder, bootstrap
            mindset, AI-assisted development speed.
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
              <h2 className="text-2xl font-bold mb-6">Key Metrics (Pre-Revenue → Year 3)</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatCard
                  icon={<DollarSign className="w-6 h-6 text-cyan-400" />}
                  label="ARR Growth"
                  value="$0 → $5M"
                  subtext="Pre-revenue to Series A-ready"
                  trend="up"
                />
                <StatCard
                  icon={<Users className="w-6 h-6 text-cyan-400" />}
                  label="Total Customers"
                  value="0 → 1,820"
                  subtext="Grassroots community growth"
                  trend="up"
                />
                <StatCard
                  icon={<Target className="w-6 h-6 text-cyan-400" />}
                  label="LTV:CAC Ratio"
                  value="N/A → 13.3:1"
                  subtext="Healthy unit economics by Y3"
                  trend="up"
                />
                <StatCard
                  icon={<Calendar className="w-6 h-6 text-cyan-400" />}
                  label="Break-Even"
                  value="Month 18"
                  subtext="Cash flow positive Q4 2027"
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
              <h3 className="text-xl font-bold mb-4">Model Assumptions (Grassroots GTM)</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="font-semibold text-cyan-400 mb-2">Revenue Growth Drivers</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li>• Free tier → paid conversion: 10% → 20% (Year 2)</li>
                    <li>• Average monthly churn: 2% → 1% (Year 3)</li>
                    <li>• Net revenue retention (NRR): 100% → 110%</li>
                    <li>• Expansion revenue: 15% of total by Year 3</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-semibold text-cyan-400 mb-2">Go-to-Market Mix</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li>• Reddit /r/netsec, /r/blueteamsec (50% organic)</li>
                    <li>• YouTube tutorials + demos (30% organic)</li>
                    <li>• Blog + SEO (15% organic)</li>
                    <li>• Minimal paid ads (5% - Reddit/HN sponsorship)</li>
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
                      <th className="text-right py-3 px-4">Now (MRR)</th>
                      <th className="text-right py-3 px-4">Year 1 (2026)</th>
                      <th className="text-right py-3 px-4">Year 2 (2027)</th>
                      <th className="text-right py-3 px-4">Year 3 (2028)</th>
                      <th className="text-right py-3 px-4">Growth</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tierBreakdown.map((tier, i) => (
                      <tr key={i} className="border-b border-gray-700/50">
                        <td className="py-3 px-4 font-medium">{tier.tier}</td>
                        <td className="text-right py-3 px-4">${tier.now.toLocaleString()}</td>
                        <td className="text-right py-3 px-4">${tier.year_1.toLocaleString()}</td>
                        <td className="text-right py-3 px-4">${tier.year_2.toLocaleString()}</td>
                        <td className="text-right py-3 px-4">${tier.year_3.toLocaleString()}</td>
                        <td className="text-right py-3 px-4 text-green-400">
                          {tier.year_1 > 0 ? ((tier.year_3 / tier.year_1) * 100 - 100).toFixed(0) + '%' : 'N/A'}
                        </td>
                      </tr>
                    ))}
                    <tr className="border-t-2 border-gray-700 font-bold">
                      <td className="py-3 px-4">Total MRR</td>
                      <td className="text-right py-3 px-4">
                        ${tierBreakdown.reduce((sum, t) => sum + t.now, 0).toLocaleString()}
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
                      <td className="text-right py-3 px-4 text-green-400">1,343%</td>
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
                value="$50 → $300"
                subtext="Low CAC via organic growth"
              />
              <StatCard
                icon={<Target className="w-6 h-6 text-cyan-400" />}
                label="Average LTV"
                value="$1,200 → $4,000"
                subtext="Growth from NRR + expansion"
              />
              <StatCard
                icon={<TrendingUp className="w-6 h-6 text-cyan-400" />}
                label="LTV:CAC Ratio"
                value="24:1 → 13.3:1"
                subtext="Excellent unit economics"
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
                label="Starting Cash (Pre-Seed)"
                value="$1.0M"
                subtext="January 2026 (assuming mid-range raise)"
              />
              <StatCard
                icon={<Calendar className="w-6 h-6 text-cyan-400" />}
                label="Runway at Launch"
                value="67 months"
                subtext="With $15K monthly burn"
              />
              <StatCard
                icon={<TrendingUp className="w-6 h-6 text-cyan-400" />}
                label="Cash Flow Positive"
                value="Month 18"
                subtext="Break-even Q3 2027"
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
              <h3 className="text-xl font-bold mb-4">Use of Funds ($1M Pre-Seed)</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="font-semibold text-cyan-400 mb-3">Product (40% - $400K)</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li>• Finish last 10% of features ($150K founder time)</li>
                    <li>• UX polish & user testing ($100K)</li>
                    <li>• Security audit & pentest ($50K)</li>
                    <li>• Infrastructure & cloud costs ($60K/year)</li>
                    <li>• Tools & software licenses ($40K)</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-semibold text-cyan-400 mb-3">Go-to-Market (30% - $300K)</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li>• Reddit community building ($50K ads)</li>
                    <li>• YouTube tutorial production ($100K equipment + editing)</li>
                    <li>• Blog content & SEO ($50K freelance writers)</li>
                    <li>• Conference sponsorships ($100K)</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-semibold text-cyan-400 mb-3">Founder Runway (20% - $200K)</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li>• 18 months at $60K/year ($90K total)</li>
                    <li>• Healthcare & benefits ($30K)</li>
                    <li>• Home office setup ($10K)</li>
                    <li>• Emergency buffer ($70K)</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-semibold text-cyan-400 mb-3">Infrastructure (10% - $100K)</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li>• AWS credits & cloud hosting ($40K)</li>
                    <li>• Domain & email services ($5K)</li>
                    <li>• Legal & incorporation ($25K)</li>
                    <li>• Accounting & bookkeeping ($30K)</li>
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
