import React from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Heart,
  Target,
  Zap,
  Users,
  Award,
  Flag,
  Code,
  ArrowRight,
  Mail,
  MapPin,
  Globe,
  CheckCircle2,
  Sparkles,
  Brain,
  Lock
} from 'lucide-react';

const AboutPage: React.FC = () => {
  const values = [
    {
      icon: <Heart className="w-8 h-8" />,
      title: 'Security is a Right',
      description: 'We believe every organization deserves access to enterprise-grade security tools, regardless of budget. Security shouldn\'t be a luxury reserved for Fortune 500 companies.',
      color: 'red',
    },
    {
      icon: <Shield className="w-8 h-8" />,
      title: 'Transparency First',
      description: 'No hidden fees, no confusing pricing models. Simple, honest pricing with unlimited scans. We build in public and share our journey openly.',
      color: 'cyan',
    },
    {
      icon: <Zap className="w-8 h-8" />,
      title: 'Speed Without Compromise',
      description: 'AI assistance allows us to move at startup speed while maintaining enterprise quality. What takes VC-backed teams 18 months, we built in 3 weeks.',
      color: 'yellow',
    },
    {
      icon: <Users className="w-8 h-8" />,
      title: 'Community Driven',
      description: 'Built for the InfoSec community, by the InfoSec community. We listen to practitioners and build what security professionals actually need.',
      color: 'purple',
    },
  ];

  const timeline = [
    {
      year: '2004-2024',
      title: 'Signals Intelligence Career',
      description: 'Two decades of nation-state level SIGINT operations worldwide, developing deep expertise in cybersecurity.',
    },
    {
      year: 'November 2024',
      title: 'HeroForge Concept',
      description: 'After retiring as a 100% disabled Army veteran, the founder identified the gap in affordable security tools for consultancies.',
    },
    {
      year: 'December 2024',
      title: '3-Week Build Sprint',
      description: 'Using AI-assisted development (Claude Code), built 90% of HeroForge in just 3 weeks—proving the power of domain expertise + AI.',
    },
    {
      year: 'January 2025',
      title: 'Beta Launch',
      description: 'Opening private beta to security consultancies and MSPs. Building in public and gathering feedback from real users.',
    },
    {
      year: '2025',
      title: 'General Availability',
      description: 'Public launch with full feature set, compliance certifications, and enterprise-grade reliability.',
    },
  ];

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
      <section className="pt-32 pb-20 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h1 className="text-5xl md:text-6xl font-bold text-white mb-6">
              Built by a Veteran.
              <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">
                Driven by Mission.
              </span>
            </h1>
            <p className="text-xl text-gray-400 max-w-3xl mx-auto">
              After 20 years protecting national security, I'm on a new mission:
              making enterprise-grade security accessible to everyone.
            </p>
          </div>

          {/* Founder Highlights */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="bg-gradient-to-br from-cyan-600/20 to-cyan-800/20 border border-cyan-500/30 rounded-2xl p-6 text-center">
              <Shield className="w-10 h-10 text-cyan-400 mx-auto mb-4" />
              <div className="text-2xl font-bold text-white mb-2">20 Years</div>
              <div className="text-gray-400 text-sm">Signals Intelligence</div>
            </div>
            <div className="bg-gradient-to-br from-red-600/20 to-red-800/20 border border-red-500/30 rounded-2xl p-6 text-center">
              <Flag className="w-10 h-10 text-red-400 mx-auto mb-4" />
              <div className="text-2xl font-bold text-white mb-2">100%</div>
              <div className="text-gray-400 text-sm">Disabled Army Veteran</div>
            </div>
            <div className="bg-gradient-to-br from-purple-600/20 to-purple-800/20 border border-purple-500/30 rounded-2xl p-6 text-center">
              <Code className="w-10 h-10 text-purple-400 mx-auto mb-4" />
              <div className="text-2xl font-bold text-white mb-2">3 Weeks</div>
              <div className="text-gray-400 text-sm">To Build HeroForge</div>
            </div>
            <div className="bg-gradient-to-br from-green-600/20 to-green-800/20 border border-green-500/30 rounded-2xl p-6 text-center">
              <Heart className="w-10 h-10 text-green-400 mx-auto mb-4" />
              <div className="text-2xl font-bold text-white mb-2">Father</div>
              <div className="text-gray-400 text-sm">Mission-Driven</div>
            </div>
          </div>
        </div>
      </section>

      {/* The Story */}
      <section className="py-20 px-4 bg-gray-800/50">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-8 text-center">
            The HeroForge Story
          </h2>
          <div className="space-y-6 text-lg text-gray-300 leading-relaxed">
            <p>
              For two decades, I operated at the <strong className="text-white">nation-state level</strong> in
              Signals Intelligence—targeting threats worldwide. I've seen what elite security teams can do with
              the right tools. I've also watched those tools become increasingly expensive and exclusive.
            </p>
            <p>
              Tenable costs $2,275/year for just 65 assets. Qualys requires enterprise contracts with sales
              calls. The best security tools are reserved for those who can afford them—leaving small businesses,
              consultancies, and startups vulnerable.
            </p>
            <p>
              As a <strong className="text-white">100% disabled Army veteran and father</strong>, I believe
              security is a right, not a luxury. Every organization deserves protection, regardless of their
              budget. That belief drove me to create HeroForge.
            </p>
            <p>
              Using <strong className="text-white">AI-assisted development</strong>, I built what typically
              takes VC-backed teams 18 months in just 3 weeks. Not by cutting corners, but by leveraging
              20 years of domain expertise combined with modern AI tools like Claude Code.
            </p>
            <p>
              HeroForge combines everything security professionals need: network scanning, web app testing,
              compliance frameworks, customer portals, CRM, and time tracking—all at a price point that
              freelancers and small consultancies can afford.
            </p>
          </div>
        </div>
      </section>

      {/* Our Values */}
      <section className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-4 text-center">
            What We Stand For
          </h2>
          <p className="text-xl text-gray-400 max-w-2xl mx-auto mb-12 text-center">
            Every decision we make is guided by these core principles.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {values.map((value, idx) => {
              const colorClasses: Record<string, string> = {
                red: 'from-red-600/20 to-red-800/20 border-red-500/30 text-red-400',
                cyan: 'from-cyan-600/20 to-cyan-800/20 border-cyan-500/30 text-cyan-400',
                yellow: 'from-yellow-600/20 to-yellow-800/20 border-yellow-500/30 text-yellow-400',
                purple: 'from-purple-600/20 to-purple-800/20 border-purple-500/30 text-purple-400',
              };
              const classes = colorClasses[value.color] || colorClasses.cyan;

              return (
                <div
                  key={idx}
                  className={`bg-gradient-to-br ${classes} border rounded-2xl p-8`}
                >
                  <div className={classes.split(' ').pop()}>
                    {value.icon}
                  </div>
                  <h3 className="text-2xl font-bold text-white mt-4 mb-3">{value.title}</h3>
                  <p className="text-gray-300">{value.description}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Timeline */}
      <section className="py-20 px-4 bg-gray-800/50">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-12 text-center">
            Our Journey
          </h2>
          <div className="relative">
            {/* Timeline line */}
            <div className="absolute left-8 top-0 bottom-0 w-0.5 bg-gray-700" />

            <div className="space-y-12">
              {timeline.map((item, idx) => (
                <div key={idx} className="relative flex gap-8">
                  <div className="w-16 flex-shrink-0 flex items-start justify-center">
                    <div className="w-4 h-4 bg-cyan-500 rounded-full z-10 mt-1.5" />
                  </div>
                  <div className="flex-1 pb-4">
                    <div className="text-cyan-400 font-semibold text-sm mb-1">{item.year}</div>
                    <h3 className="text-xl font-bold text-white mb-2">{item.title}</h3>
                    <p className="text-gray-400">{item.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Technology */}
      <section className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-4 text-center">
            Built with Modern Technology
          </h2>
          <p className="text-xl text-gray-400 max-w-2xl mx-auto mb-12 text-center">
            HeroForge is built on a foundation of modern, secure, and scalable technologies.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-orange-500/10 rounded-lg">
                  <Lock className="w-6 h-6 text-orange-400" />
                </div>
                <h3 className="text-xl font-bold text-white">Rust Backend</h3>
              </div>
              <p className="text-gray-400">
                Memory-safe, high-performance backend built with Rust and Tokio async runtime.
                No buffer overflows, no null pointer exceptions.
              </p>
            </div>
            <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-blue-500/10 rounded-lg">
                  <Code className="w-6 h-6 text-blue-400" />
                </div>
                <h3 className="text-xl font-bold text-white">React Frontend</h3>
              </div>
              <p className="text-gray-400">
                Modern React 18 with TypeScript, Vite for fast builds, and TailwindCSS for
                beautiful, responsive design.
              </p>
            </div>
            <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-purple-500/10 rounded-lg">
                  <Brain className="w-6 h-6 text-purple-400" />
                </div>
                <h3 className="text-xl font-bold text-white">AI-Powered</h3>
              </div>
              <p className="text-gray-400">
                Machine learning for vulnerability prioritization, LLM integration for security
                testing, and AI-generated reports.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Company Info */}
      <section className="py-20 px-4 bg-gray-800/50">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-12">
            <div>
              <h2 className="text-3xl font-bold text-white mb-6">Company Information</h2>
              <div className="space-y-4">
                <div className="flex items-start gap-3">
                  <Globe className="w-5 h-5 text-cyan-400 mt-1" />
                  <div>
                    <div className="text-white font-semibold">Legal Name</div>
                    <div className="text-gray-400">Genial Architect Cybersecurity Research Associates</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <MapPin className="w-5 h-5 text-cyan-400 mt-1" />
                  <div>
                    <div className="text-white font-semibold">Headquarters</div>
                    <div className="text-gray-400">United States</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Mail className="w-5 h-5 text-cyan-400 mt-1" />
                  <div>
                    <div className="text-white font-semibold">Contact</div>
                    <div className="text-gray-400">
                      <a href="mailto:info@genialarchitect.io" className="hover:text-cyan-400">info@genialarchitect.io</a>
                    </div>
                    <div className="text-gray-400">
                      <a href="mailto:sales@genialarchitect.io" className="hover:text-cyan-400">sales@genialarchitect.io</a>
                    </div>
                    <div className="text-gray-400">
                      <a href="mailto:support@genialarchitect.io" className="hover:text-cyan-400">support@genialarchitect.io</a>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div>
              <h2 className="text-3xl font-bold text-white mb-6">For Investors</h2>
              <p className="text-gray-400 mb-6">
                HeroForge is currently raising a pre-seed round to accelerate growth and
                bring enterprise-grade security to underserved markets.
              </p>
              <div className="space-y-4">
                <Link
                  to="/investors"
                  className="flex items-center gap-3 bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-cyan-500/50 transition-colors"
                >
                  <Award className="w-6 h-6 text-cyan-400" />
                  <div>
                    <div className="text-white font-semibold">Investor Page</div>
                    <div className="text-gray-400 text-sm">Full pitch and company overview</div>
                  </div>
                  <ArrowRight className="w-5 h-5 text-gray-400 ml-auto" />
                </Link>
                <Link
                  to="/pitch"
                  className="flex items-center gap-3 bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-cyan-500/50 transition-colors"
                >
                  <Sparkles className="w-6 h-6 text-purple-400" />
                  <div>
                    <div className="text-white font-semibold">Pitch Deck</div>
                    <div className="text-gray-400 text-sm">View our presentation</div>
                  </div>
                  <ArrowRight className="w-5 h-5 text-gray-400 ml-auto" />
                </Link>
                <Link
                  to="/one-pager"
                  className="flex items-center gap-3 bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-cyan-500/50 transition-colors"
                >
                  <Target className="w-6 h-6 text-green-400" />
                  <div>
                    <div className="text-white font-semibold">One-Pager</div>
                    <div className="text-gray-400 text-sm">Quick overview document</div>
                  </div>
                  <ArrowRight className="w-5 h-5 text-gray-400 ml-auto" />
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
            Ready to Join Our Mission?
          </h2>
          <p className="text-xl text-gray-400 mb-8">
            Start your free trial and experience what enterprise security should be.
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

export default AboutPage;
