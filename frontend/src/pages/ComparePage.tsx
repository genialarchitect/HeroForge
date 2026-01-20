import React from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  Shield,
  Check,
  X,
  Minus,
  DollarSign,
  Users,
  Zap,
  Clock,
  ArrowRight,
  Star,
  Building,
  Target,
} from 'lucide-react';

interface CompetitorData {
  name: string;
  logo: string;
  tagline: string;
  description: string;
  founded: string;
  headquarters: string;
  pricing: string;
  pricingNote: string;
  targetMarket: string;
  strengths: string[];
  weaknesses: string[];
}

interface FeatureComparison {
  category: string;
  features: {
    name: string;
    heroforge: boolean | 'partial';
    competitor: boolean | 'partial';
    notes?: string;
  }[];
}

const competitors: Record<string, CompetitorData> = {
  tenable: {
    name: 'Tenable Nessus',
    logo: 'T',
    tagline: 'Vulnerability Management Leader',
    description: 'Tenable is a leading vulnerability management vendor known for Nessus, the world\'s most deployed vulnerability scanner.',
    founded: '2002',
    headquarters: 'Columbia, MD',
    pricing: '$2,790+/year',
    pricingNote: 'Per scanner, limited to 65 assets for Nessus Pro',
    targetMarket: 'Large enterprises, compliance-focused organizations',
    strengths: [
      'Industry-leading vulnerability database',
      'Strong compliance reporting',
      'Mature, battle-tested product',
      'Large plugin library',
    ],
    weaknesses: [
      'No penetration testing capabilities',
      'No SIEM integration built-in',
      'Expensive at scale',
      'Complex licensing model',
      'No consultancy/CRM features',
    ],
  },
  qualys: {
    name: 'Qualys VMDR',
    logo: 'Q',
    tagline: 'Cloud-Native Security Platform',
    description: 'Qualys provides cloud-based IT security and compliance solutions including vulnerability management and web application scanning.',
    founded: '1999',
    headquarters: 'Foster City, CA',
    pricing: 'Contact for quote',
    pricingNote: 'Enterprise pricing, typically $50K+ annually',
    targetMarket: 'Large enterprises, cloud-first organizations',
    strengths: [
      'True cloud-native architecture',
      'Global AssetView visibility',
      'Strong compliance coverage',
      'Container security support',
    ],
    weaknesses: [
      'Very expensive for SMBs',
      'No offensive security tools',
      'Limited customization',
      'No CRM/consultancy features',
      'Complex deployment for on-prem',
    ],
  },
  rapid7: {
    name: 'Rapid7 InsightVM',
    logo: 'R7',
    tagline: 'Vulnerability Risk Management',
    description: 'Rapid7 offers InsightVM for vulnerability management and InsightIDR for SIEM, plus Metasploit for penetration testing.',
    founded: '2000',
    headquarters: 'Boston, MA',
    pricing: '$15K-$200K+/year',
    pricingNote: 'Per product, Metasploit Pro ~$15K/year separately',
    targetMarket: 'Mid-market to enterprise, security teams',
    strengths: [
      'Strong integration ecosystem',
      'Metasploit for pentesting (separate)',
      'Good cloud coverage',
      'Active community',
    ],
    weaknesses: [
      'Multiple products needed (VM + SIEM + Pentest)',
      'High total cost of ownership',
      'Complex licensing across products',
      'No built-in CRM features',
      'Separate purchases for full coverage',
    ],
  },
  pentera: {
    name: 'Pentera',
    logo: 'P',
    tagline: 'Automated Security Validation',
    description: 'Pentera provides automated penetration testing and continuous security validation for enterprise environments.',
    founded: '2015',
    headquarters: 'Boston, MA',
    pricing: '$75K-$200K+/year',
    pricingNote: 'Enterprise-only pricing',
    targetMarket: 'Large enterprises with mature security teams',
    strengths: [
      'Continuous automated pentesting',
      'Attack path visualization',
      'Safe exploitation',
      'Good reporting',
    ],
    weaknesses: [
      'Extremely expensive',
      'No vulnerability management',
      'No SIEM capabilities',
      'No compliance automation',
      'No CRM/consultancy features',
      'Limited to pentesting only',
    ],
  },
  crowdstrike: {
    name: 'CrowdStrike Falcon',
    logo: 'CS',
    tagline: 'Endpoint Security Leader',
    description: 'CrowdStrike is a cybersecurity company providing endpoint security, threat intelligence, and cyberattack response services.',
    founded: '2011',
    headquarters: 'Austin, TX',
    pricing: '$8.99-$18.99/endpoint/mo',
    pricingNote: 'Plus platform fees, enterprise pricing varies',
    targetMarket: 'Enterprises seeking EDR/XDR solutions',
    strengths: [
      'Industry-leading EDR',
      'Strong threat intelligence',
      'Cloud-native architecture',
      'Fast deployment',
    ],
    weaknesses: [
      'Endpoint-focused, not VM platform',
      'No penetration testing',
      'No compliance automation',
      'Expensive per-endpoint model',
      'Not designed for consultancies',
    ],
  },
};

const getFeatureComparison = (competitor: string): FeatureComparison[] => [
  {
    category: 'Vulnerability Management',
    features: [
      { name: 'Network Vulnerability Scanning', heroforge: true, competitor: true },
      { name: 'Web Application Scanning', heroforge: true, competitor: competitor !== 'crowdstrike' },
      { name: 'Container Security', heroforge: true, competitor: ['qualys', 'rapid7', 'crowdstrike'].includes(competitor) },
      { name: 'Cloud Security (AWS/Azure/GCP)', heroforge: true, competitor: competitor !== 'pentera' },
      { name: 'API Security Testing', heroforge: true, competitor: 'partial' },
      { name: 'Continuous Monitoring', heroforge: true, competitor: true },
    ],
  },
  {
    category: 'Offensive Security',
    features: [
      { name: 'Penetration Testing Tools', heroforge: true, competitor: competitor === 'pentera' || competitor === 'rapid7' ? 'partial' : false },
      { name: 'Exploitation Framework', heroforge: true, competitor: competitor === 'rapid7' ? 'partial' : false, notes: competitor === 'rapid7' ? 'Separate Metasploit purchase' : undefined },
      { name: 'Active Directory Assessment', heroforge: true, competitor: competitor === 'pentera' },
      { name: 'Phishing Simulation', heroforge: true, competitor: false },
      { name: 'C2 Framework Integration', heroforge: true, competitor: false },
      { name: 'Privilege Escalation Testing', heroforge: true, competitor: competitor === 'pentera' },
    ],
  },
  {
    category: 'Detection & Response',
    features: [
      { name: 'Built-in SIEM', heroforge: true, competitor: competitor === 'rapid7' ? 'partial' : competitor === 'crowdstrike' },
      { name: 'Log Ingestion & Correlation', heroforge: true, competitor: competitor === 'rapid7' ? 'partial' : competitor === 'crowdstrike' },
      { name: 'Detection Engineering', heroforge: true, competitor: competitor === 'crowdstrike' },
      { name: 'Incident Response', heroforge: true, competitor: competitor === 'crowdstrike' },
      { name: 'Threat Hunting', heroforge: true, competitor: competitor === 'crowdstrike' },
    ],
  },
  {
    category: 'Compliance & GRC',
    features: [
      { name: '45+ Compliance Frameworks', heroforge: true, competitor: false, notes: 'HeroForge: 45 frameworks, competitors: 10-20 typically' },
      { name: 'Automated Evidence Collection', heroforge: true, competitor: 'partial' },
      { name: 'Audit Management', heroforge: true, competitor: 'partial' },
      { name: 'Risk Assessment', heroforge: true, competitor: 'partial' },
      { name: 'Policy Management', heroforge: true, competitor: 'partial' },
    ],
  },
  {
    category: 'Consultancy & Business',
    features: [
      { name: 'Built-in CRM', heroforge: true, competitor: false },
      { name: 'Customer Portal', heroforge: true, competitor: false },
      { name: 'White-Label Support', heroforge: true, competitor: false },
      { name: 'Time Tracking', heroforge: true, competitor: false },
      { name: 'Engagement Management', heroforge: true, competitor: false },
      { name: 'Custom Report Templates', heroforge: true, competitor: 'partial' },
    ],
  },
];

const ComparePage: React.FC = () => {
  const { competitor: competitorSlug } = useParams<{ competitor: string }>();
  const competitor = competitors[competitorSlug || ''];

  if (!competitor) {
    return (
      <div className="min-h-screen bg-gray-900 py-12 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-3xl font-bold text-white mb-4">Comparison Not Found</h1>
          <p className="text-gray-400 mb-8">Select a competitor to compare:</p>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            {Object.entries(competitors).map(([slug, data]) => (
              <Link
                key={slug}
                to={`/compare/${slug}`}
                className="bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-cyan-500 transition-colors"
              >
                <div className="text-xl font-bold text-white mb-1">{data.name}</div>
                <div className="text-sm text-gray-400">{data.tagline}</div>
              </Link>
            ))}
          </div>
        </div>
      </div>
    );
  }

  const features = getFeatureComparison(competitorSlug || '');

  const renderFeatureIcon = (value: boolean | 'partial') => {
    if (value === true) return <Check className="w-5 h-5 text-green-400" />;
    if (value === 'partial') return <Minus className="w-5 h-5 text-yellow-400" />;
    return <X className="w-5 h-5 text-red-400" />;
  };

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Hero Section */}
      <div className="bg-gradient-to-b from-gray-800 to-gray-900 py-12 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-8">
            <h1 className="text-3xl md:text-4xl font-bold text-white mb-4">
              HeroForge vs {competitor.name}
            </h1>
            <p className="text-xl text-gray-400">
              See why security teams are switching to HeroForge
            </p>
          </div>

          {/* Quick Comparison Cards */}
          <div className="grid md:grid-cols-2 gap-6">
            {/* HeroForge Card */}
            <div className="bg-gradient-to-br from-cyan-900/50 to-blue-900/50 border border-cyan-700 rounded-xl p-6">
              <div className="flex items-center space-x-3 mb-4">
                <div className="w-12 h-12 bg-cyan-600 rounded-lg flex items-center justify-center">
                  <Shield className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">HeroForge</h2>
                  <p className="text-cyan-300 text-sm">Unified Security Platform</p>
                </div>
              </div>
              <div className="space-y-3 mb-4">
                <div className="flex items-center text-gray-300">
                  <DollarSign className="w-4 h-4 mr-2 text-cyan-400" />
                  <span className="font-medium">$299-$1,749/month</span>
                  <span className="text-gray-500 text-sm ml-2">(Unlimited assets)</span>
                </div>
                <div className="flex items-center text-gray-300">
                  <Target className="w-4 h-4 mr-2 text-cyan-400" />
                  <span>SMBs, Consultancies, MSSPs</span>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                {['VM', 'Pentest', 'SIEM', 'Compliance', 'CRM'].map((tag) => (
                  <span key={tag} className="px-2 py-1 bg-cyan-900/50 text-cyan-300 rounded text-xs">
                    {tag}
                  </span>
                ))}
              </div>
            </div>

            {/* Competitor Card */}
            <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
              <div className="flex items-center space-x-3 mb-4">
                <div className="w-12 h-12 bg-gray-700 rounded-lg flex items-center justify-center">
                  <span className="text-xl font-bold text-gray-400">{competitor.logo}</span>
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">{competitor.name}</h2>
                  <p className="text-gray-400 text-sm">{competitor.tagline}</p>
                </div>
              </div>
              <div className="space-y-3 mb-4">
                <div className="flex items-center text-gray-300">
                  <DollarSign className="w-4 h-4 mr-2 text-gray-500" />
                  <span className="font-medium">{competitor.pricing}</span>
                </div>
                <div className="flex items-center text-gray-400 text-sm">
                  <span>{competitor.pricingNote}</span>
                </div>
                <div className="flex items-center text-gray-300">
                  <Target className="w-4 h-4 mr-2 text-gray-500" />
                  <span>{competitor.targetMarket}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Feature Comparison Table */}
      <div className="max-w-6xl mx-auto px-6 py-12">
        <h2 className="text-2xl font-bold text-white mb-8 text-center">Feature Comparison</h2>

        <div className="space-y-8">
          {features.map((category) => (
            <div key={category.category} className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
              <div className="bg-gray-750 px-6 py-4 border-b border-gray-700">
                <h3 className="text-lg font-semibold text-white">{category.category}</h3>
              </div>
              <div className="divide-y divide-gray-700">
                {/* Header Row */}
                <div className="grid grid-cols-3 px-6 py-3 bg-gray-900/50">
                  <div className="text-sm font-medium text-gray-400">Feature</div>
                  <div className="text-sm font-medium text-cyan-400 text-center">HeroForge</div>
                  <div className="text-sm font-medium text-gray-400 text-center">{competitor.name}</div>
                </div>
                {/* Feature Rows */}
                {category.features.map((feature) => (
                  <div key={feature.name} className="grid grid-cols-3 px-6 py-3 items-center">
                    <div>
                      <span className="text-gray-300">{feature.name}</span>
                      {feature.notes && (
                        <p className="text-xs text-gray-500 mt-1">{feature.notes}</p>
                      )}
                    </div>
                    <div className="flex justify-center">{renderFeatureIcon(feature.heroforge)}</div>
                    <div className="flex justify-center">{renderFeatureIcon(feature.competitor)}</div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* TCO Comparison */}
        <div className="mt-12 bg-gradient-to-r from-green-900/30 to-cyan-900/30 border border-green-800 rounded-xl p-8">
          <h2 className="text-2xl font-bold text-white mb-6 text-center">Total Cost of Ownership</h2>
          <div className="grid md:grid-cols-2 gap-8">
            <div className="text-center">
              <div className="text-5xl font-bold text-cyan-400 mb-2">70%</div>
              <div className="text-gray-300">Average cost savings vs {competitor.name}</div>
            </div>
            <div className="text-center">
              <div className="text-5xl font-bold text-green-400 mb-2">1</div>
              <div className="text-gray-300">Platform instead of 5+ separate tools</div>
            </div>
          </div>
          <div className="mt-8 bg-gray-900/50 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Annual Cost Comparison (100 assets)</h3>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-gray-300">HeroForge Professional</span>
                <span className="text-cyan-400 font-bold">$11,988/year</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-300">{competitor.name}</span>
                <span className="text-gray-400 font-bold">{competitor.pricing}</span>
              </div>
              <div className="border-t border-gray-700 pt-4 flex justify-between items-center">
                <span className="text-green-400 font-medium">Your Savings</span>
                <span className="text-green-400 font-bold">$15,000+ / year</span>
              </div>
            </div>
          </div>
        </div>

        {/* Strengths & Weaknesses */}
        <div className="mt-12 grid md:grid-cols-2 gap-8">
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
              <Star className="w-5 h-5 text-yellow-400 mr-2" />
              {competitor.name} Strengths
            </h3>
            <ul className="space-y-2">
              {competitor.strengths.map((strength) => (
                <li key={strength} className="flex items-start text-gray-300">
                  <Check className="w-4 h-4 text-green-400 mr-2 mt-0.5 flex-shrink-0" />
                  {strength}
                </li>
              ))}
            </ul>
          </div>
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
              <X className="w-5 h-5 text-red-400 mr-2" />
              {competitor.name} Gaps (HeroForge Fills)
            </h3>
            <ul className="space-y-2">
              {competitor.weaknesses.map((weakness) => (
                <li key={weakness} className="flex items-start text-gray-300">
                  <Check className="w-4 h-4 text-cyan-400 mr-2 mt-0.5 flex-shrink-0" />
                  {weakness}
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* CTA */}
        <div className="mt-12 bg-gradient-to-r from-cyan-900/50 to-blue-900/50 border border-cyan-700 rounded-xl p-8 text-center">
          <h2 className="text-2xl font-bold text-white mb-4">Ready to make the switch?</h2>
          <p className="text-gray-300 mb-6">
            Start your free trial today and see why teams are choosing HeroForge over {competitor.name}.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              to="/register"
              className="inline-flex items-center justify-center px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium transition-colors"
            >
              Start Free Trial
              <ArrowRight className="w-4 h-4 ml-2" />
            </Link>
            <Link
              to="/sales"
              className="inline-flex items-center justify-center px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg font-medium transition-colors"
            >
              Talk to Sales
            </Link>
          </div>
          <p className="text-sm text-gray-400 mt-4">
            Free 14-day trial. No credit card required. Migration assistance included.
          </p>
        </div>

        {/* Other Comparisons */}
        <div className="mt-12">
          <h3 className="text-lg font-semibold text-white mb-4">Compare with other platforms</h3>
          <div className="flex flex-wrap gap-3">
            {Object.entries(competitors)
              .filter(([slug]) => slug !== competitorSlug)
              .map(([slug, data]) => (
                <Link
                  key={slug}
                  to={`/compare/${slug}`}
                  className="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-300 hover:border-cyan-500 hover:text-white transition-colors"
                >
                  vs {data.name}
                </Link>
              ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ComparePage;
