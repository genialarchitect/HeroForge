import { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  Check,
  X,
  Shield,
  Users,
  Building2,
  User,
  Zap,
  Clock,
  BarChart3,
  Lock,
  Globe,
  HelpCircle,
  ArrowRight,
  Sparkles,
} from 'lucide-react';
import { registrationAPI } from '../services/api';

type BillingCycle = 'monthly' | 'yearly';

interface TierFeatures {
  scanning?: boolean;
  reporting?: boolean;
  scheduling?: boolean;
  team_management?: boolean;
  crm?: boolean;
  api_access?: boolean;
  custom_branding?: boolean;
  sso?: boolean;
  dedicated_support?: boolean;
  on_premise?: boolean;
}

interface SubscriptionTier {
  id: string;
  name: string;
  display_name: string;
  description?: string;
  monthly_price?: number | null;
  yearly_price?: number | null;
  max_users: number;
  max_scans_per_day: number;
  max_assets: number;
  features: TierFeatures;
}

// Feature comparison data
const featureComparison = [
  { name: 'Vulnerability Scanning', free: true, solo: true, professional: true, team: true, enterprise: true },
  { name: 'Network Reconnaissance', free: true, solo: true, professional: true, team: true, enterprise: true },
  { name: 'Service Detection', free: true, solo: true, professional: true, team: true, enterprise: true },
  { name: 'Report Generation', free: 'Basic', solo: true, professional: true, team: true, enterprise: true },
  { name: 'Compliance Frameworks', free: '3', solo: '10', professional: '25', team: '45', enterprise: 'All' },
  { name: 'Scheduled Scans', free: false, solo: false, professional: true, team: true, enterprise: true },
  { name: 'Team Management', free: false, solo: false, professional: true, team: true, enterprise: true },
  { name: 'CRM & Customer Portals', free: false, solo: false, professional: false, team: true, enterprise: true },
  { name: 'API Access', free: false, solo: false, professional: true, team: true, enterprise: true },
  { name: 'Custom Branding', free: false, solo: false, professional: false, team: true, enterprise: true },
  { name: 'SSO Integration', free: false, solo: false, professional: false, team: false, enterprise: true },
  { name: 'Dedicated Support', free: false, solo: false, professional: false, team: false, enterprise: true },
  { name: 'On-Premise Deployment', free: false, solo: false, professional: false, team: false, enterprise: true },
  { name: 'Custom Integrations', free: false, solo: false, professional: false, team: false, enterprise: true },
];

// FAQ data
const faqs = [
  {
    question: 'Can I try HeroForge before purchasing?',
    answer: 'Yes! Our Free tier lets you explore HeroForge with up to 3 scans per day and 10 assets. No credit card required.',
  },
  {
    question: 'What payment methods do you accept?',
    answer: 'We accept all major credit cards (Visa, Mastercard, American Express) through our secure payment processor, Stripe.',
  },
  {
    question: 'Can I upgrade or downgrade my plan?',
    answer: 'Yes, you can change your plan at any time. When upgrading, you\'ll be prorated for the remainder of your billing cycle. When downgrading, the change takes effect at the next billing cycle.',
  },
  {
    question: 'Do you offer refunds?',
    answer: 'We offer a 14-day money-back guarantee for all paid plans. If you\'re not satisfied, contact support for a full refund.',
  },
  {
    question: 'What\'s included in Enterprise?',
    answer: 'Enterprise includes everything in Team plus SSO integration, dedicated support, on-premise deployment options, custom integrations, SLA guarantees, and a dedicated account manager.',
  },
  {
    question: 'Is my data secure?',
    answer: 'Absolutely. We use AES-256 encryption for data at rest, TLS 1.3 for data in transit, and maintain SOC 2 compliance. Your scan data is never shared with third parties.',
  },
];

// Tier card component
function TierCard({
  tier,
  billingCycle,
  isPopular,
}: {
  tier: SubscriptionTier;
  billingCycle: BillingCycle;
  isPopular?: boolean;
}) {
  const navigate = useNavigate();
  const price = billingCycle === 'yearly' ? tier.yearly_price : tier.monthly_price;
  const isEnterprise = tier.name === 'enterprise';
  const isFree = tier.name === 'free';
  const monthlyEquivalent = billingCycle === 'yearly' && tier.yearly_price ? tier.yearly_price / 12 : null;

  const getIcon = () => {
    switch (tier.name) {
      case 'free':
        return <Zap className="h-8 w-8 text-gray-400" />;
      case 'solo':
        return <User className="h-8 w-8 text-cyan-400" />;
      case 'professional':
        return <Shield className="h-8 w-8 text-cyan-400" />;
      case 'team':
        return <Users className="h-8 w-8 text-cyan-400" />;
      case 'enterprise':
        return <Building2 className="h-8 w-8 text-purple-400" />;
      default:
        return <Shield className="h-8 w-8 text-cyan-400" />;
    }
  };

  const handleClick = () => {
    if (isEnterprise) {
      navigate('/contact-sales');
    } else {
      navigate(`/register?tier=${tier.name}`);
    }
  };

  return (
    <div
      className={`relative flex flex-col p-6 rounded-2xl border-2 transition-all duration-200 ${
        isPopular
          ? 'border-cyan-500 bg-cyan-500/5 scale-105 shadow-xl shadow-cyan-500/20'
          : isEnterprise
          ? 'border-purple-500/50 bg-purple-500/5'
          : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'
      }`}
    >
      {isPopular && (
        <div className="absolute -top-4 left-1/2 -translate-x-1/2">
          <span className="inline-flex items-center gap-1 px-4 py-1 text-sm font-semibold bg-cyan-500 text-white rounded-full shadow-lg">
            <Sparkles className="h-4 w-4" />
            Most Popular
          </span>
        </div>
      )}

      <div className="flex items-center gap-3 mb-4">
        {getIcon()}
        <h3 className="text-2xl font-bold text-white">{tier.display_name}</h3>
      </div>

      <div className="mb-4 min-h-[80px]">
        {isEnterprise ? (
          <div>
            <p className="text-3xl font-bold text-white">Custom</p>
            <p className="text-sm text-gray-400 mt-1">Tailored to your needs</p>
          </div>
        ) : isFree ? (
          <div>
            <p className="text-3xl font-bold text-white">$0</p>
            <p className="text-sm text-gray-400 mt-1">Forever free</p>
          </div>
        ) : (
          <div>
            <div className="flex items-baseline gap-1">
              <span className="text-4xl font-bold text-white">${price?.toFixed(0)}</span>
              <span className="text-gray-400">/{billingCycle === 'yearly' ? 'year' : 'month'}</span>
            </div>
            {billingCycle === 'yearly' && monthlyEquivalent && (
              <p className="text-sm text-cyan-400 mt-1">
                ${monthlyEquivalent.toFixed(0)}/month billed annually
              </p>
            )}
          </div>
        )}
      </div>

      <p className="text-gray-400 text-sm mb-6 min-h-[48px]">{tier.description}</p>

      <ul className="space-y-3 mb-8 flex-grow">
        <li className="flex items-center gap-3 text-gray-300">
          <Users className="h-5 w-5 text-cyan-500 flex-shrink-0" />
          <span>{tier.max_users === -1 ? 'Unlimited' : tier.max_users} user{tier.max_users !== 1 ? 's' : ''}</span>
        </li>
        <li className="flex items-center gap-3 text-gray-300">
          <BarChart3 className="h-5 w-5 text-cyan-500 flex-shrink-0" />
          <span>{tier.max_scans_per_day === -1 ? 'Unlimited' : tier.max_scans_per_day} scans/day</span>
        </li>
        <li className="flex items-center gap-3 text-gray-300">
          <Globe className="h-5 w-5 text-cyan-500 flex-shrink-0" />
          <span>{tier.max_assets === -1 ? 'Unlimited' : tier.max_assets} assets</span>
        </li>
        {tier.features.scheduling && (
          <li className="flex items-center gap-3 text-gray-300">
            <Clock className="h-5 w-5 text-cyan-500 flex-shrink-0" />
            <span>Scheduled scans</span>
          </li>
        )}
        {tier.features.team_management && (
          <li className="flex items-center gap-3 text-gray-300">
            <Users className="h-5 w-5 text-cyan-500 flex-shrink-0" />
            <span>Team management</span>
          </li>
        )}
        {tier.features.crm && (
          <li className="flex items-center gap-3 text-gray-300">
            <Building2 className="h-5 w-5 text-cyan-500 flex-shrink-0" />
            <span>CRM & portals</span>
          </li>
        )}
        {tier.features.sso && (
          <li className="flex items-center gap-3 text-gray-300">
            <Lock className="h-5 w-5 text-purple-400 flex-shrink-0" />
            <span>SSO integration</span>
          </li>
        )}
      </ul>

      <button
        onClick={handleClick}
        className={`w-full py-3 px-6 rounded-lg font-semibold transition-all duration-200 flex items-center justify-center gap-2 ${
          isPopular
            ? 'bg-cyan-500 text-white hover:bg-cyan-600 shadow-lg shadow-cyan-500/25'
            : isEnterprise
            ? 'bg-purple-500 text-white hover:bg-purple-600'
            : isFree
            ? 'bg-gray-700 text-white hover:bg-gray-600'
            : 'bg-gray-700 text-white hover:bg-gray-600'
        }`}
      >
        {isEnterprise ? 'Contact Sales' : isFree ? 'Get Started Free' : 'Start Free Trial'}
        <ArrowRight className="h-5 w-5" />
      </button>
    </div>
  );
}

// Feature comparison table
function FeatureComparisonTable() {
  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-gray-700">
            <th className="text-left py-4 px-4 text-gray-300 font-medium">Feature</th>
            <th className="text-center py-4 px-4 text-gray-300 font-medium">Free</th>
            <th className="text-center py-4 px-4 text-gray-300 font-medium">Solo</th>
            <th className="text-center py-4 px-4 text-cyan-400 font-medium">Professional</th>
            <th className="text-center py-4 px-4 text-gray-300 font-medium">Team</th>
            <th className="text-center py-4 px-4 text-purple-400 font-medium">Enterprise</th>
          </tr>
        </thead>
        <tbody>
          {featureComparison.map((feature, index) => (
            <tr key={feature.name} className={index % 2 === 0 ? 'bg-gray-800/30' : ''}>
              <td className="py-3 px-4 text-gray-300">{feature.name}</td>
              {['free', 'solo', 'professional', 'team', 'enterprise'].map((tier) => {
                const value = feature[tier as keyof typeof feature];
                return (
                  <td key={tier} className="text-center py-3 px-4">
                    {value === true ? (
                      <Check className="h-5 w-5 text-green-500 mx-auto" />
                    ) : value === false ? (
                      <X className="h-5 w-5 text-gray-600 mx-auto" />
                    ) : (
                      <span className="text-gray-300">{value}</span>
                    )}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// FAQ Section
function FAQSection() {
  const [openIndex, setOpenIndex] = useState<number | null>(null);

  return (
    <div className="space-y-4">
      {faqs.map((faq, index) => (
        <div
          key={index}
          className="border border-gray-700 rounded-lg overflow-hidden"
        >
          <button
            onClick={() => setOpenIndex(openIndex === index ? null : index)}
            className="w-full flex items-center justify-between p-4 text-left hover:bg-gray-800/50 transition-colors"
          >
            <span className="font-medium text-white">{faq.question}</span>
            <HelpCircle
              className={`h-5 w-5 text-gray-400 transition-transform ${
                openIndex === index ? 'rotate-180' : ''
              }`}
            />
          </button>
          {openIndex === index && (
            <div className="px-4 pb-4 text-gray-400">
              {faq.answer}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

export default function PricingPage() {
  const navigate = useNavigate();
  const [billingCycle, setBillingCycle] = useState<BillingCycle>('monthly');
  const [tiers, setTiers] = useState<SubscriptionTier[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadTiers = async () => {
      try {
        const response = await registrationAPI.getTiers();
        setTiers(response.data);
      } catch {
        // Fallback tiers
        setTiers([
          {
            id: 'tier_free',
            name: 'free',
            display_name: 'Free',
            description: 'Get started with basic security scanning - no credit card required',
            monthly_price: null,
            yearly_price: null,
            max_users: 1,
            max_scans_per_day: 3,
            max_assets: 10,
            features: { scanning: true, reporting: true },
          },
          {
            id: 'tier_solo',
            name: 'solo',
            display_name: 'Solo',
            description: 'Perfect for individual security professionals and freelancers',
            monthly_price: 99,
            yearly_price: 990,
            max_users: 1,
            max_scans_per_day: 10,
            max_assets: 100,
            features: { scanning: true, reporting: true },
          },
          {
            id: 'tier_professional',
            name: 'professional',
            display_name: 'Professional',
            description: 'For growing security teams and consultancies',
            monthly_price: 299,
            yearly_price: 2990,
            max_users: 5,
            max_scans_per_day: 50,
            max_assets: 500,
            features: { scanning: true, reporting: true, scheduling: true, team_management: true, api_access: true },
          },
          {
            id: 'tier_team',
            name: 'team',
            display_name: 'Team',
            description: 'For established security teams with client management needs',
            monthly_price: 599,
            yearly_price: 5990,
            max_users: 15,
            max_scans_per_day: 200,
            max_assets: 2000,
            features: { scanning: true, reporting: true, scheduling: true, team_management: true, crm: true, api_access: true, custom_branding: true },
          },
          {
            id: 'tier_enterprise',
            name: 'enterprise',
            display_name: 'Enterprise',
            description: 'Custom solutions for large organizations with advanced needs',
            monthly_price: null,
            yearly_price: null,
            max_users: -1,
            max_scans_per_day: -1,
            max_assets: -1,
            features: { scanning: true, reporting: true, scheduling: true, team_management: true, crm: true, api_access: true, custom_branding: true, sso: true, dedicated_support: true, on_premise: true },
          },
        ]);
      } finally {
        setLoading(false);
      }
    };

    loadTiers();
  }, []);

  const yearlySavings = billingCycle === 'yearly' ? 17 : 0;

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-gray-900/80 backdrop-blur-md border-b border-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <Link to="/" className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-cyan-500" />
              <span className="text-xl font-bold text-white">HeroForge</span>
            </Link>
            <div className="hidden md:flex items-center gap-4">
              <Link to="/" className="text-gray-300 hover:text-white transition-colors">Home</Link>
              <Link to="/features" className="text-gray-300 hover:text-white transition-colors">Features</Link>
              <Link to="/pricing" className="text-cyan-400 font-medium">Pricing</Link>
              <Link to="/tools" className="text-gray-300 hover:text-white transition-colors">Free Tools</Link>
              <Link to="/blog" className="text-gray-300 hover:text-white transition-colors">Blog</Link>
              <Link to="/academy" className="text-gray-300 hover:text-white transition-colors">Academy</Link>
              <Link to="/docs" className="text-gray-300 hover:text-white transition-colors">Docs</Link>
              <Link
                to="/register"
                className="bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg font-medium transition-colors"
              >
                Start Free Trial
              </Link>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-4">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-4xl md:text-5xl font-bold text-white mb-6">
            Simple, Transparent Pricing
          </h1>
          <p className="text-xl text-gray-400 mb-8">
            Choose the plan that fits your security testing needs. All plans include our core scanning engine.
          </p>

          {/* Billing Toggle */}
          <div className="inline-flex items-center gap-4 p-1 bg-gray-800 rounded-lg">
            <button
              onClick={() => setBillingCycle('monthly')}
              className={`px-6 py-2 rounded-md text-sm font-medium transition-all ${
                billingCycle === 'monthly'
                  ? 'bg-cyan-500 text-white shadow-lg'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              Monthly
            </button>
            <button
              onClick={() => setBillingCycle('yearly')}
              className={`px-6 py-2 rounded-md text-sm font-medium transition-all flex items-center gap-2 ${
                billingCycle === 'yearly'
                  ? 'bg-cyan-500 text-white shadow-lg'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              Yearly
              <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded-full">
                Save {yearlySavings}%
              </span>
            </button>
          </div>
        </div>
      </section>

      {/* Pricing Cards */}
      <section className="pb-20 px-4">
        <div className="max-w-7xl mx-auto">
          {loading ? (
            <div className="flex justify-center py-20">
              <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-cyan-500"></div>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 items-stretch">
              {tiers.map((tier) => (
                <TierCard
                  key={tier.id}
                  tier={tier}
                  billingCycle={billingCycle}
                  isPopular={tier.name === 'professional'}
                />
              ))}
            </div>
          )}
        </div>
      </section>

      {/* Feature Comparison */}
      <section className="py-20 px-4 bg-gray-800/30">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-3xl font-bold text-white text-center mb-12">
            Compare Plans
          </h2>
          <div className="bg-gray-800/50 rounded-xl border border-gray-700 p-6">
            <FeatureComparisonTable />
          </div>
        </div>
      </section>

      {/* FAQ Section */}
      <section className="py-20 px-4">
        <div className="max-w-3xl mx-auto">
          <h2 className="text-3xl font-bold text-white text-center mb-12">
            Frequently Asked Questions
          </h2>
          <FAQSection />
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4 bg-gradient-to-r from-cyan-500/10 to-purple-500/10">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-3xl font-bold text-white mb-4">
            Ready to secure your infrastructure?
          </h2>
          <p className="text-xl text-gray-400 mb-8">
            Start with our Free tier and upgrade when you're ready.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <button
              onClick={() => navigate('/register?tier=free')}
              className="px-8 py-3 bg-cyan-500 text-white font-semibold rounded-lg hover:bg-cyan-600 transition-colors shadow-lg shadow-cyan-500/25"
            >
              Start Free
            </button>
            <button
              onClick={() => navigate('/contact-sales')}
              className="px-8 py-3 bg-gray-700 text-white font-semibold rounded-lg hover:bg-gray-600 transition-colors"
            >
              Talk to Sales
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-800 py-12 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
            <div>
              <div className="flex items-center gap-3 mb-4">
                <Shield className="w-8 h-8 text-cyan-500" />
                <span className="text-xl font-bold text-white">HeroForge</span>
              </div>
              <p className="text-gray-400 text-sm">
                Professional penetration testing and vulnerability management platform.
              </p>
            </div>
            <div>
              <h4 className="text-white font-semibold mb-4">Product</h4>
              <ul className="space-y-2">
                <li><Link to="/features" className="text-gray-400 hover:text-white text-sm">Features</Link></li>
                <li><Link to="/use-cases" className="text-gray-400 hover:text-white text-sm">Use Cases</Link></li>
                <li><Link to="/pricing" className="text-gray-400 hover:text-white text-sm">Pricing</Link></li>
                <li><Link to="/roadmap" className="text-gray-400 hover:text-white text-sm">Roadmap</Link></li>
                <li><Link to="/status" className="text-gray-400 hover:text-white text-sm">Status</Link></li>
                <li><Link to="/about" className="text-gray-400 hover:text-white text-sm">About</Link></li>
                <li><Link to="/login" className="text-gray-400 hover:text-white text-sm">Login</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="text-white font-semibold mb-4">Resources</h4>
              <ul className="space-y-2">
                <li><Link to="/tools" className="text-gray-400 hover:text-white text-sm">Free Tools</Link></li>
                <li><Link to="/blog" className="text-gray-400 hover:text-white text-sm">Blog</Link></li>
                <li><Link to="/academy" className="text-gray-400 hover:text-white text-sm">Academy</Link></li>
                <li><Link to="/certifications" className="text-gray-400 hover:text-white text-sm">Certifications</Link></li>
                <li><Link to="/docs" className="text-gray-400 hover:text-white text-sm">Documentation</Link></li>
                <li><Link to="/whitepapers" className="text-gray-400 hover:text-white text-sm">Whitepapers</Link></li>
                <li><Link to="/developers" className="text-gray-400 hover:text-white text-sm">Developer Portal</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="text-white font-semibold mb-4">Contact</h4>
              <ul className="space-y-2">
                <li><a href="mailto:sales@genialarchitect.io" className="text-gray-400 hover:text-white text-sm">sales@genialarchitect.io</a></li>
                <li><a href="mailto:support@genialarchitect.io" className="text-gray-400 hover:text-white text-sm">support@genialarchitect.io</a></li>
              </ul>
            </div>
          </div>
          <div className="border-t border-gray-800 pt-8 flex flex-col md:flex-row items-center justify-between">
            <p className="text-gray-500 text-sm">
              &copy; 2026 Genial Architect Cybersecurity Research Associates. All rights reserved.
            </p>
            <div className="flex items-center gap-6 mt-4 md:mt-0">
              <Link to="/legal/terms" className="text-gray-400 hover:text-white text-sm">Terms of Service</Link>
              <Link to="/legal/privacy" className="text-gray-400 hover:text-white text-sm">Privacy Policy</Link>
              <Link to="/legal/acceptable-use" className="text-gray-400 hover:text-white text-sm">Acceptable Use</Link>
              <Link to="/legal/cookies" className="text-gray-400 hover:text-white text-sm">Cookies</Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
