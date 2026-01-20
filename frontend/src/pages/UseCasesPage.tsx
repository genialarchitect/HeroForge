import React from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Building2,
  Users,
  Briefcase,
  Heart,
  CreditCard,
  Factory,
  GraduationCap,
  Globe,
  Server,
  ArrowRight,
  Check,
  Clock,
  DollarSign,
  Target,
  Zap,
  Award,
  BarChart3
} from 'lucide-react';

interface UseCase {
  id: string;
  icon: React.ReactNode;
  title: string;
  subtitle: string;
  color: string;
  description: string;
  challenges: string[];
  solutions: string[];
  features: string[];
  metrics: { label: string; value: string }[];
}

const UseCasesPage: React.FC = () => {
  const useCases: UseCase[] = [
    {
      id: 'consultancy',
      icon: <Briefcase className="w-8 h-8" />,
      title: 'Security Consultancies',
      subtitle: 'Boutique firms and solo practitioners',
      color: 'cyan',
      description: 'Purpose-built for security consultants who need to deliver comprehensive assessments efficiently while managing multiple client engagements.',
      challenges: [
        'Juggling 5+ tools for scanning, reporting, and client management',
        'Spending 40% of billable time on administrative work',
        'No unified view across client engagements',
        'Expensive enterprise tools with per-asset pricing',
      ],
      solutions: [
        'All-in-one platform: scanning, CRM, time tracking, reporting',
        'AI-powered report generation saves 8+ hours per engagement',
        'Customer portal gives clients 24/7 visibility',
        'Flat pricing with unlimited scans',
      ],
      features: [
        'Customer Portal',
        'CRM & Engagement Management',
        'Time Tracking',
        'Methodology Checklists',
        'White-Label Reports',
        'Finding Templates',
      ],
      metrics: [
        { label: 'Time Saved', value: '40%' },
        { label: 'Report Time', value: '45 min' },
        { label: 'Client Retention', value: '+40%' },
      ],
    },
    {
      id: 'msp',
      icon: <Server className="w-8 h-8" />,
      title: 'Managed Security Providers',
      subtitle: 'MSPs and MSSPs serving multiple clients',
      color: 'purple',
      description: 'Manage security for dozens of clients with multi-tenant isolation, automated scanning, and unified dashboards.',
      challenges: [
        'Managing security across 20+ diverse client environments',
        'Different compliance requirements per client',
        'Limited visibility into client security posture',
        'Manual processes don\'t scale',
      ],
      solutions: [
        'Multi-tenant architecture with complete isolation',
        'Automated scheduled scans with alerting',
        'Client-specific compliance templates',
        'Unified dashboard across all clients',
      ],
      features: [
        'Multi-Tenant Management',
        'Scheduled Scans',
        'Compliance Frameworks',
        'SIEM Integration',
        'Client Portals',
        'SLA Tracking',
      ],
      metrics: [
        { label: 'Clients Managed', value: 'Unlimited' },
        { label: 'Cost vs Tenable', value: '-70%' },
        { label: 'Automation', value: '90%' },
      ],
    },
    {
      id: 'healthcare',
      icon: <Heart className="w-8 h-8" />,
      title: 'Healthcare Organizations',
      subtitle: 'Hospitals, clinics, and healthcare IT',
      color: 'red',
      description: 'Meet HIPAA requirements with continuous vulnerability management and automated compliance evidence collection.',
      challenges: [
        'HIPAA compliance requires continuous monitoring',
        'Medical devices create blind spots',
        'PHI protection is critical',
        'Limited security budget and staff',
      ],
      solutions: [
        'HIPAA compliance framework with evidence collection',
        'IoT/Medical device discovery and monitoring',
        'Automated compliance reporting for audits',
        'Affordable pricing for healthcare budgets',
      ],
      features: [
        'HIPAA Framework',
        'IoT Security',
        'Evidence Collection',
        'Risk Assessment',
        'Asset Discovery',
        'Audit Reports',
      ],
      metrics: [
        { label: 'HIPAA Coverage', value: '100%' },
        { label: 'Audit Prep Time', value: '-80%' },
        { label: 'Device Visibility', value: '100%' },
      ],
    },
    {
      id: 'financial',
      icon: <CreditCard className="w-8 h-8" />,
      title: 'Financial Services',
      subtitle: 'Banks, fintech, and payment processors',
      color: 'green',
      description: 'Achieve and maintain PCI-DSS compliance with continuous scanning and automated evidence for QSA audits.',
      challenges: [
        'PCI-DSS 4.0 requires continuous testing',
        'Annual pentests don\'t catch emerging vulnerabilities',
        'QSA audits require extensive evidence',
        'Regulatory scrutiny is increasing',
      ],
      solutions: [
        'PCI-DSS 4.0 framework with all requirements mapped',
        'Continuous vulnerability scanning',
        'Automated evidence collection for QSAs',
        'Executive dashboards for board reporting',
      ],
      features: [
        'PCI-DSS 4.0 Framework',
        'ASV-Quality Scanning',
        'Evidence Collection',
        'Executive Dashboards',
        'Trend Analysis',
        'Remediation Tracking',
      ],
      metrics: [
        { label: 'PCI Controls', value: '100%' },
        { label: 'Audit Prep', value: '-75%' },
        { label: 'Finding Resolution', value: '3x faster' },
      ],
    },
    {
      id: 'manufacturing',
      icon: <Factory className="w-8 h-8" />,
      title: 'Manufacturing & OT/ICS',
      subtitle: 'Industrial facilities and critical infrastructure',
      color: 'orange',
      description: 'Secure operational technology and industrial control systems with specialized OT/ICS scanning and monitoring.',
      challenges: [
        'IT/OT convergence creates new attack surfaces',
        'Legacy systems can\'t be patched',
        'Downtime costs millions per hour',
        'Traditional security tools don\'t understand OT protocols',
      ],
      solutions: [
        'OT/ICS-aware scanning that won\'t disrupt operations',
        'Modbus, DNP3, and industrial protocol support',
        'Asset discovery for shadow OT devices',
        'Air-gapped network support',
      ],
      features: [
        'OT/ICS Scanning',
        'Industrial Protocols',
        'Asset Discovery',
        'Network Segmentation Analysis',
        'NIST CSF Compliance',
        'Air-Gap Support',
      ],
      metrics: [
        { label: 'OT Visibility', value: '100%' },
        { label: 'Downtime Risk', value: '-90%' },
        { label: 'Protocols Supported', value: '15+' },
      ],
    },
    {
      id: 'education',
      icon: <GraduationCap className="w-8 h-8" />,
      title: 'Education Institutions',
      subtitle: 'Universities, colleges, and K-12',
      color: 'blue',
      description: 'Protect student data and meet FERPA requirements with budget-friendly security that covers distributed campuses.',
      challenges: [
        'FERPA compliance for student data',
        'Distributed campuses with different networks',
        'BYOD creates thousands of endpoints',
        'Limited IT security budget',
      ],
      solutions: [
        'FERPA compliance framework',
        'Distributed scanning across campuses',
        'Asset discovery for BYOD devices',
        'Educational institution pricing',
      ],
      features: [
        'FERPA Framework',
        'Distributed Agents',
        'Asset Discovery',
        'Student Portal',
        'Phishing Simulation',
        'Security Awareness Training',
      ],
      metrics: [
        { label: 'FERPA Coverage', value: '100%' },
        { label: 'Cost Savings', value: '60%' },
        { label: 'Campus Coverage', value: 'Unlimited' },
      ],
    },
    {
      id: 'enterprise',
      icon: <Building2 className="w-8 h-8" />,
      title: 'Enterprise Security Teams',
      subtitle: 'Large organizations with internal security',
      color: 'indigo',
      description: 'Augment your security team with AI-powered vulnerability management that integrates with your existing tools.',
      challenges: [
        'Tool sprawl across 10+ security products',
        'Alert fatigue from thousands of findings',
        'Difficulty prioritizing remediation',
        'Proving ROI to leadership',
      ],
      solutions: [
        'Unified platform reduces tool sprawl',
        'AI prioritization cuts false positives by 70%',
        'Attack path analysis focuses remediation',
        'Executive dashboards show ROI',
      ],
      features: [
        'AI Prioritization',
        'Attack Path Analysis',
        'SIEM/SOAR Integration',
        'SSO/SAML',
        'Custom Compliance Frameworks',
        'Executive Dashboards',
      ],
      metrics: [
        { label: 'False Positives', value: '-70%' },
        { label: 'Tool Reduction', value: '5-10 tools' },
        { label: 'MTTR', value: '-50%' },
      ],
    },
    {
      id: 'startup',
      icon: <Zap className="w-8 h-8" />,
      title: 'Startups & Scale-ups',
      subtitle: 'Fast-growing companies building security',
      color: 'yellow',
      description: 'Build security from day one with DevSecOps integration and compliance frameworks that grow with you.',
      challenges: [
        'Need SOC 2 for enterprise customers',
        'Security can\'t slow down development',
        'Limited security expertise on team',
        'Need to scale security with growth',
      ],
      solutions: [
        'SOC 2 compliance framework',
        'CI/CD integration for DevSecOps',
        'AI-guided remediation recommendations',
        'Pricing that scales with your growth',
      ],
      features: [
        'SOC 2 Framework',
        'CI/CD Integration',
        'SAST/SCA',
        'Secret Detection',
        'Compliance Evidence',
        'Growth-Friendly Pricing',
      ],
      metrics: [
        { label: 'SOC 2 Ready', value: '90 days' },
        { label: 'Dev Impact', value: 'Minimal' },
        { label: 'Starting Price', value: '$99/mo' },
      ],
    },
  ];

  const getColorClasses = (color: string) => {
    const colors: Record<string, { bg: string; border: string; text: string; gradient: string }> = {
      cyan: { bg: 'bg-cyan-500/20', border: 'border-cyan-500/30', text: 'text-cyan-400', gradient: 'from-cyan-600/20 to-cyan-800/20' },
      purple: { bg: 'bg-purple-500/20', border: 'border-purple-500/30', text: 'text-purple-400', gradient: 'from-purple-600/20 to-purple-800/20' },
      red: { bg: 'bg-red-500/20', border: 'border-red-500/30', text: 'text-red-400', gradient: 'from-red-600/20 to-red-800/20' },
      green: { bg: 'bg-green-500/20', border: 'border-green-500/30', text: 'text-green-400', gradient: 'from-green-600/20 to-green-800/20' },
      orange: { bg: 'bg-orange-500/20', border: 'border-orange-500/30', text: 'text-orange-400', gradient: 'from-orange-600/20 to-orange-800/20' },
      blue: { bg: 'bg-blue-500/20', border: 'border-blue-500/30', text: 'text-blue-400', gradient: 'from-blue-600/20 to-blue-800/20' },
      indigo: { bg: 'bg-indigo-500/20', border: 'border-indigo-500/30', text: 'text-indigo-400', gradient: 'from-indigo-600/20 to-indigo-800/20' },
      yellow: { bg: 'bg-yellow-500/20', border: 'border-yellow-500/30', text: 'text-yellow-400', gradient: 'from-yellow-600/20 to-yellow-800/20' },
    };
    return colors[color] || colors.cyan;
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-900 to-gray-800">
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
              <Link to="/pricing" className="text-gray-300 hover:text-white transition-colors">Pricing</Link>
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
      <section className="pt-32 pb-16 px-4">
        <div className="max-w-7xl mx-auto text-center">
          <h1 className="text-5xl md:text-6xl font-bold text-white mb-6">
            Security Solutions for
            <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">
              Every Industry
            </span>
          </h1>
          <p className="text-xl text-gray-400 max-w-3xl mx-auto mb-10">
            Whether you're a solo consultant, healthcare provider, or Fortune 500 enterprise,
            HeroForge adapts to your unique security needs.
          </p>
        </div>
      </section>

      {/* Quick Navigation */}
      <section className="py-8 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-wrap justify-center gap-3">
            {useCases.map((useCase) => {
              const colors = getColorClasses(useCase.color);
              return (
                <a
                  key={useCase.id}
                  href={`#${useCase.id}`}
                  className={`flex items-center gap-2 px-4 py-2 rounded-full ${colors.bg} ${colors.border} border hover:scale-105 transition-all`}
                >
                  <span className={colors.text}>{useCase.icon}</span>
                  <span className="text-white text-sm font-medium">{useCase.title}</span>
                </a>
              );
            })}
          </div>
        </div>
      </section>

      {/* Use Case Sections */}
      <section className="py-16 px-4">
        <div className="max-w-7xl mx-auto space-y-24">
          {useCases.map((useCase, index) => {
            const colors = getColorClasses(useCase.color);
            const isEven = index % 2 === 0;

            return (
              <div
                key={useCase.id}
                id={useCase.id}
                className="scroll-mt-24"
              >
                <div className={`flex flex-col ${isEven ? 'lg:flex-row' : 'lg:flex-row-reverse'} gap-12 items-start`}>
                  {/* Content Side */}
                  <div className="flex-1">
                    <div className="flex items-center gap-4 mb-6">
                      <div className={`p-4 rounded-xl ${colors.bg} ${colors.border} border`}>
                        <div className={colors.text}>{useCase.icon}</div>
                      </div>
                      <div>
                        <h2 className="text-3xl font-bold text-white">{useCase.title}</h2>
                        <p className="text-gray-400">{useCase.subtitle}</p>
                      </div>
                    </div>

                    <p className="text-lg text-gray-300 mb-8">{useCase.description}</p>

                    {/* Challenges & Solutions */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                      <div>
                        <h3 className="text-red-400 font-semibold mb-3 flex items-center gap-2">
                          <Target className="w-5 h-5" />
                          Challenges
                        </h3>
                        <ul className="space-y-2">
                          {useCase.challenges.map((challenge, idx) => (
                            <li key={idx} className="text-gray-400 text-sm flex items-start gap-2">
                              <span className="text-red-400 mt-1">•</span>
                              {challenge}
                            </li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <h3 className="text-green-400 font-semibold mb-3 flex items-center gap-2">
                          <Check className="w-5 h-5" />
                          How HeroForge Helps
                        </h3>
                        <ul className="space-y-2">
                          {useCase.solutions.map((solution, idx) => (
                            <li key={idx} className="text-gray-400 text-sm flex items-start gap-2">
                              <Check className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                              {solution}
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>

                    {/* Key Features */}
                    <div className="flex flex-wrap gap-2 mb-6">
                      {useCase.features.map((feature, idx) => (
                        <span
                          key={idx}
                          className={`px-3 py-1 rounded-full text-sm ${colors.bg} ${colors.text} ${colors.border} border`}
                        >
                          {feature}
                        </span>
                      ))}
                    </div>

                    <Link
                      to={useCase.id === 'enterprise' ? '/contact-sales' : '/register'}
                      className={`inline-flex items-center gap-2 px-6 py-3 rounded-lg font-semibold transition-all hover:scale-105 ${
                        useCase.id === 'enterprise'
                          ? 'bg-gray-700 hover:bg-gray-600 text-white'
                          : 'bg-cyan-600 hover:bg-cyan-700 text-white'
                      }`}
                    >
                      {useCase.id === 'enterprise' ? 'Contact Sales' : 'Start Free Trial'}
                      <ArrowRight className="w-4 h-4" />
                    </Link>
                  </div>

                  {/* Metrics Side */}
                  <div className={`w-full lg:w-80 bg-gradient-to-br ${colors.gradient} ${colors.border} border rounded-2xl p-6`}>
                    <h3 className="text-white font-bold mb-6 flex items-center gap-2">
                      <BarChart3 className="w-5 h-5" />
                      Key Metrics
                    </h3>
                    <div className="space-y-6">
                      {useCase.metrics.map((metric, idx) => (
                        <div key={idx}>
                          <div className={`text-3xl font-bold ${colors.text} mb-1`}>{metric.value}</div>
                          <div className="text-gray-400 text-sm">{metric.label}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4 bg-gray-800/50">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
            Don't See Your Industry?
          </h2>
          <p className="text-xl text-gray-400 mb-8">
            HeroForge is flexible enough to support any security use case.
            Contact us to discuss your specific needs.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link
              to="/register"
              className="bg-cyan-600 hover:bg-cyan-700 text-white px-8 py-4 rounded-lg font-semibold text-lg transition-all hover:scale-105 flex items-center gap-2"
            >
              Start Your Free Trial
              <ArrowRight className="w-5 h-5" />
            </Link>
            <Link
              to="/contact-sales"
              className="border border-gray-600 hover:border-gray-500 text-gray-300 hover:text-white px-8 py-4 rounded-lg font-semibold text-lg transition-colors"
            >
              Contact Sales
            </Link>
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
};

export default UseCasesPage;
