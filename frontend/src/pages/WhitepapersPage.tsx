import React, { useState, useEffect } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Shield, FileText, ArrowLeft, Download, Clock, BookOpen, ChevronRight, ExternalLink } from 'lucide-react';

interface Whitepaper {
  id: string;
  title: string;
  subtitle: string;
  description: string;
  readTime: string;
  date: string;
  topics: string[];
}

const whitepapers: Whitepaper[] = [
  {
    id: 'unified-security',
    title: 'Transforming the Cybersecurity Landscape',
    subtitle: 'Through Unified Security Operations',
    description: 'Examines how HeroForge\'s unified security architecture with 86+ modules, 45 compliance frameworks, and AI-powered operations addresses critical gaps in the current cybersecurity landscape.',
    readTime: '18 min read',
    date: 'January 2026 • v2.0',
    topics: ['Unified Security', 'AI-Powered Operations', '45 Compliance Frameworks', 'Finding Lifecycle', 'DevSecOps'],
  },
  {
    id: 'novel-approach',
    title: 'Breaking the Mold',
    subtitle: 'HeroForge\'s Novel Approach to Enterprise Cybersecurity',
    description: 'Explores 8 novel approaches including AI-powered security operations, finding lifecycle management, automated passive reconnaissance, and capabilities unavailable in fragmented security stacks.',
    readTime: '25 min read',
    date: 'January 2026 • v2.0',
    topics: ['AI Security Operations', 'Finding Lifecycle', 'Passive Recon', 'Remediation Roadmaps', '8 Novel Approaches'],
  },
  {
    id: 'competitive-analysis',
    title: 'HeroForge vs. The Market',
    subtitle: 'A Comprehensive Competitive Analysis',
    description: 'Detailed comparison of HeroForge against Tenable, Qualys, Rapid7, and traditional penetration testing firms, demonstrating 70-82% cost savings with superior capabilities.',
    readTime: '22 min read',
    date: 'January 2026 • v1.0',
    topics: ['Competitive Analysis', 'TCO Comparison', 'Feature Matrix', 'Pricing', 'Market Position'],
  },
];

const WhitepapersPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [content, setContent] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedPaper = id ? whitepapers.find(wp => wp.id === id) : null;

  useEffect(() => {
    if (id) {
      setLoading(true);
      setError(null);
      fetch(`/api/whitepapers/${id}`)
        .then(res => {
          if (!res.ok) throw new Error('Failed to load whitepaper');
          return res.text();
        })
        .then(text => {
          setContent(text);
          setLoading(false);
        })
        .catch(err => {
          setError(err.message);
          setLoading(false);
        });
    }
  }, [id]);

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
              <Link to="/use-cases" className="text-gray-300 hover:text-white transition-colors">Use Cases</Link>
              <Link to="/about" className="text-gray-300 hover:text-white transition-colors">About</Link>
              <Link to="/whitepapers" className="text-cyan-400 font-medium">Whitepapers</Link>
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

      <div className="pt-24 pb-16">
        {!id ? (
          // Whitepaper listing view
          <>
            {/* Hero Section */}
            <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mb-16">
              <div className="text-center">
                <div className="flex items-center justify-center gap-3 mb-6">
                  <BookOpen className="w-12 h-12 text-cyan-500" />
                </div>
                <h1 className="text-4xl md:text-5xl font-bold text-white mb-4">
                  Research & <span className="text-cyan-400">Whitepapers</span>
                </h1>
                <p className="text-xl text-gray-400 max-w-3xl mx-auto">
                  Deep dives into HeroForge's architecture, innovative approaches, and
                  how unified security operations transforms enterprise cybersecurity.
                </p>
              </div>
            </section>

            {/* Whitepapers Grid */}
            <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="grid md:grid-cols-2 gap-8">
                {whitepapers.map((paper) => (
                  <div
                    key={paper.id}
                    className="bg-gray-800/50 rounded-2xl border border-gray-700 hover:border-cyan-500/50 transition-all duration-300 overflow-hidden group"
                  >
                    <div className="p-8">
                      <div className="flex items-start gap-4 mb-6">
                        <div className="p-3 bg-cyan-500/10 rounded-xl">
                          <FileText className="w-8 h-8 text-cyan-500" />
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-3 text-sm text-gray-400 mb-2">
                            <span className="flex items-center gap-1">
                              <Clock className="w-4 h-4" />
                              {paper.readTime}
                            </span>
                            <span>{paper.date}</span>
                          </div>
                          <h3 className="text-2xl font-bold text-white group-hover:text-cyan-400 transition-colors">
                            {paper.title}
                          </h3>
                          <p className="text-cyan-400 font-medium">{paper.subtitle}</p>
                        </div>
                      </div>

                      <p className="text-gray-400 mb-6 leading-relaxed">
                        {paper.description}
                      </p>

                      <div className="flex flex-wrap gap-2 mb-6">
                        {paper.topics.map((topic, idx) => (
                          <span
                            key={idx}
                            className="px-3 py-1 bg-gray-700/50 text-gray-300 rounded-full text-sm"
                          >
                            {topic}
                          </span>
                        ))}
                      </div>

                      <button
                        onClick={() => navigate(`/whitepapers/${paper.id}`)}
                        className="flex items-center gap-2 text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
                      >
                        Read Whitepaper
                        <ChevronRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            {/* CTA Section */}
            <section className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 mt-20">
              <div className="bg-gradient-to-r from-cyan-900/30 to-purple-900/30 rounded-2xl p-8 md:p-12 border border-cyan-500/20 text-center">
                <h2 className="text-3xl font-bold text-white mb-4">
                  Ready to Experience Unified Security?
                </h2>
                <p className="text-gray-400 mb-8 max-w-2xl mx-auto">
                  See how HeroForge's innovative approach can transform your security operations.
                  Start your free trial today.
                </p>
                <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                  <Link
                    to="/register"
                    className="bg-cyan-600 hover:bg-cyan-700 text-white px-8 py-3 rounded-lg font-semibold transition-colors flex items-center gap-2"
                  >
                    Start Free Trial
                    <ExternalLink className="w-5 h-5" />
                  </Link>
                  <Link
                    to="/features"
                    className="text-gray-300 hover:text-white px-8 py-3 rounded-lg font-medium transition-colors border border-gray-600 hover:border-gray-500"
                  >
                    Explore Features
                  </Link>
                </div>
              </div>
            </section>
          </>
        ) : (
          // Whitepaper detail view
          <section className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
            {/* Back button */}
            <button
              onClick={() => navigate('/whitepapers')}
              className="flex items-center gap-2 text-gray-400 hover:text-white mb-8 transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
              Back to Whitepapers
            </button>

            {selectedPaper && (
              <div className="mb-8 pb-8 border-b border-gray-700">
                <div className="flex items-center gap-3 text-sm text-gray-400 mb-4">
                  <span className="flex items-center gap-1">
                    <Clock className="w-4 h-4" />
                    {selectedPaper.readTime}
                  </span>
                  <span>{selectedPaper.date}</span>
                </div>
                <h1 className="text-3xl md:text-4xl font-bold text-white mb-2">
                  {selectedPaper.title}
                </h1>
                <p className="text-xl text-cyan-400">{selectedPaper.subtitle}</p>
              </div>
            )}

            {loading && (
              <div className="flex items-center justify-center py-20">
                <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin" />
              </div>
            )}

            {error && (
              <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6 text-center">
                <p className="text-red-400">{error}</p>
                <button
                  onClick={() => navigate('/whitepapers')}
                  className="mt-4 text-cyan-400 hover:text-cyan-300"
                >
                  Return to whitepaper list
                </button>
              </div>
            )}

            {content && (
              <article className="prose prose-invert prose-lg max-w-none prose-headings:text-white prose-p:text-gray-300 prose-a:text-cyan-400 prose-strong:text-white prose-code:text-cyan-300 prose-pre:bg-gray-800 prose-pre:border prose-pre:border-gray-700 prose-table:border-collapse prose-th:bg-gray-800 prose-th:border prose-th:border-gray-700 prose-th:p-3 prose-td:border prose-td:border-gray-700 prose-td:p-3">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                  {content}
                </ReactMarkdown>
              </article>
            )}
          </section>
        )}
      </div>

      {/* Footer */}
      <footer className="border-t border-gray-800 py-12 bg-gray-900/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <Shield className="w-6 h-6 text-cyan-500" />
              <span className="text-white font-semibold">HeroForge</span>
            </div>
            <div className="flex items-center gap-6 text-sm text-gray-400">
              <Link to="/terms" className="hover:text-white transition-colors">Terms</Link>
              <Link to="/privacy" className="hover:text-white transition-colors">Privacy</Link>
              <Link to="/acceptable-use" className="hover:text-white transition-colors">Acceptable Use</Link>
            </div>
            <p className="text-sm text-gray-500">
              &copy; {new Date().getFullYear()} Genial Architect LLC. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default WhitepapersPage;
