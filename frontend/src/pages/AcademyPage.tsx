import React, { useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  BookOpen, Award, Clock, Play,
  Star, Users, Trophy, Shield, Target, Zap
} from 'lucide-react';
import { useAcademyStore } from '../store/academyStore';
import { useAuthStore } from '../store/authStore';
import { LearningPath } from '../types/academy';

// Icon mapping
const iconMap: Record<string, React.ReactNode> = {
  'Shield': <Shield className="w-8 h-8" />,
  'Target': <Target className="w-8 h-8" />,
  'Zap': <Zap className="w-8 h-8" />,
};

// Labs data (static for now)
const labs = [
  {
    id: 'vuln-network',
    title: 'Scan a Vulnerable Network',
    description: 'Practice network scanning against a deliberately vulnerable environment.',
    difficulty: 'Easy',
    duration: '30 min',
    points: 100,
  },
  {
    id: 'web-enum',
    title: 'Web Service Enumeration',
    description: 'Discover and enumerate web services to find hidden endpoints.',
    difficulty: 'Medium',
    duration: '45 min',
    points: 200,
  },
  {
    id: 'owasp-top10',
    title: 'OWASP Top 10 Challenge',
    description: 'Find and exploit all 10 OWASP vulnerabilities in a test application.',
    difficulty: 'Hard',
    duration: '2 hours',
    points: 500,
  },
  {
    id: 'report-writing',
    title: 'Professional Report Writing',
    description: 'Document your findings and create a client-ready security report.',
    difficulty: 'Medium',
    duration: '1 hour',
    points: 150,
  },
];

// Path Card Component
const PathCard: React.FC<{ path: LearningPath; enrolled?: boolean }> = ({ path, enrolled }) => {
  const navigate = useNavigate();
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  const handleClick = () => {
    navigate(`/academy/path/${path.slug}`);
  };

  const handleEnroll = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!isAuthenticated) {
      navigate('/login?redirect=/academy/path/' + path.slug);
    } else {
      navigate(`/academy/path/${path.slug}`);
    }
  };

  const colorClasses: Record<string, { border: string; bg: string; text: string; button: string }> = {
    cyan: {
      border: 'hover:border-cyan-500',
      bg: 'bg-cyan-900/50',
      text: 'text-cyan-400',
      button: 'bg-cyan-600 hover:bg-cyan-700',
    },
    purple: {
      border: 'hover:border-purple-500',
      bg: 'bg-purple-900/50',
      text: 'text-purple-400',
      button: 'bg-purple-600 hover:bg-purple-700',
    },
    orange: {
      border: 'hover:border-orange-500',
      bg: 'bg-orange-900/50',
      text: 'text-orange-400',
      button: 'bg-orange-600 hover:bg-orange-700',
    },
  };

  const color = colorClasses[path.color || 'cyan'] || colorClasses.cyan;
  const icon = iconMap[path.icon || 'Shield'] || <Shield className="w-8 h-8" />;
  const isFree = path.price_cents === 0;
  const priceDisplay = isFree ? 'Free' : `$${(path.price_cents / 100).toFixed(0)}`;

  return (
    <div
      className={`bg-gray-800 border border-gray-700 rounded-xl p-6 ${color.border} transition-colors cursor-pointer`}
      onClick={handleClick}
    >
      <div className={`w-16 h-16 ${color.bg} rounded-xl flex items-center justify-center ${color.text} mb-4`}>
        {icon}
      </div>
      <div className="flex items-center gap-2 mb-2">
        <span className={`text-xs font-medium px-2 py-1 rounded ${color.bg} ${color.text}`}>
          {path.level}
        </span>
        <span className="text-xs text-gray-500">{path.duration_hours} hours</span>
      </div>
      <h3 className="text-xl font-bold text-white mb-2">{path.title}</h3>
      <p className="text-gray-400 text-sm mb-4 line-clamp-2">{path.description}</p>

      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center text-sm text-gray-500">
          <BookOpen className="w-4 h-4 mr-1" />
          {path.module_count} modules
        </div>
        <div className="flex items-center">
          {[1, 2, 3, 4, 5].map(i => (
            <Star key={i} className="w-4 h-4 text-yellow-500 fill-yellow-500" />
          ))}
        </div>
      </div>

      <div className="flex items-center justify-between pt-4 border-t border-gray-700">
        <span className={`font-bold ${isFree ? 'text-green-400' : 'text-white'}`}>
          {priceDisplay}
        </span>
        <button
          onClick={handleEnroll}
          className={`${color.button} text-white font-medium px-4 py-2 rounded-lg transition-colors text-sm`}
        >
          {enrolled ? 'Continue' : isFree ? 'Start Free' : 'Learn More'}
        </button>
      </div>
    </div>
  );
};

// Academy Landing Page
const AcademyLanding: React.FC = () => {
  const { publicPaths, userPaths, isLoadingPaths, fetchPublicPaths, fetchUserPaths } = useAcademyStore();
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  useEffect(() => {
    if (isAuthenticated) {
      fetchUserPaths();
    } else {
      fetchPublicPaths();
    }
  }, [isAuthenticated, fetchPublicPaths, fetchUserPaths]);

  const paths = isAuthenticated ? userPaths : publicPaths;

  return (
    <div className="max-w-6xl mx-auto">
      {/* Hero */}
      <div className="text-center mb-16">
        <div className="inline-flex items-center bg-cyan-900/30 text-cyan-400 px-4 py-2 rounded-full text-sm font-medium mb-6">
          <BookOpen className="w-4 h-4 mr-2" />
          Learn. Practice. Get Certified.
        </div>
        <h1 className="text-5xl font-bold text-white mb-6">HeroForge Academy</h1>
        <p className="text-xl text-gray-400 max-w-3xl mx-auto mb-8">
          Master cybersecurity skills with hands-on courses, practical labs, and industry-recognized certifications.
          From beginner fundamentals to advanced red team operations.
        </p>
        <div className="flex justify-center gap-4">
          <Link
            to="/academy/path/beginner"
            className="bg-cyan-600 hover:bg-cyan-700 text-white font-medium px-8 py-3 rounded-lg transition-colors"
          >
            Start Learning Free
          </Link>
          <a
            href="#paths"
            className="bg-gray-700 hover:bg-gray-600 text-white font-medium px-8 py-3 rounded-lg transition-colors"
          >
            View All Paths
          </a>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mb-16">
        <div className="bg-gray-800 rounded-xl p-6 text-center">
          <div className="text-3xl font-bold text-cyan-400 mb-1">4,500+</div>
          <div className="text-gray-400">Students Enrolled</div>
        </div>
        <div className="bg-gray-800 rounded-xl p-6 text-center">
          <div className="text-3xl font-bold text-cyan-400 mb-1">72+</div>
          <div className="text-gray-400">Hours of Content</div>
        </div>
        <div className="bg-gray-800 rounded-xl p-6 text-center">
          <div className="text-3xl font-bold text-cyan-400 mb-1">15</div>
          <div className="text-gray-400">Hands-on Labs</div>
        </div>
        <div className="bg-gray-800 rounded-xl p-6 text-center">
          <div className="text-3xl font-bold text-cyan-400 mb-1">3</div>
          <div className="text-gray-400">Certifications</div>
        </div>
      </div>

      {/* Learning Paths */}
      <div id="paths" className="mb-16">
        <h2 className="text-3xl font-bold text-white mb-8 text-center">Learning Paths</h2>
        {isLoadingPaths ? (
          <div className="text-center py-12">
            <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
            <p className="text-gray-400">Loading courses...</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {paths.map(path => (
              <PathCard
                key={path.id}
                path={path}
                enrolled={'enrolled' in path ? (path as any).enrolled : false}
              />
            ))}
          </div>
        )}
      </div>

      {/* Hands-on Labs */}
      <div className="mb-16">
        <h2 className="text-3xl font-bold text-white mb-8 text-center">Hands-on Labs</h2>
        <p className="text-gray-400 text-center mb-8 max-w-2xl mx-auto">
          Practice your skills in safe, legal environments. Our labs simulate real-world scenarios
          without the risk of affecting production systems.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {labs.map(lab => (
            <div key={lab.id} className="bg-gray-800 rounded-xl p-6 flex items-center justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <span className={`text-xs font-medium px-2 py-1 rounded ${
                    lab.difficulty === 'Easy' ? 'bg-green-900/50 text-green-400' :
                    lab.difficulty === 'Medium' ? 'bg-yellow-900/50 text-yellow-400' :
                    'bg-red-900/50 text-red-400'
                  }`}>
                    {lab.difficulty}
                  </span>
                  <span className="text-xs text-gray-500">{lab.duration}</span>
                </div>
                <h3 className="text-lg font-semibold text-white mb-1">{lab.title}</h3>
                <p className="text-gray-400 text-sm">{lab.description}</p>
              </div>
              <div className="text-right ml-4">
                <div className="text-cyan-400 font-bold mb-1">+{lab.points} pts</div>
                <button className="bg-gray-700 hover:bg-gray-600 text-white text-sm px-4 py-2 rounded-lg transition-colors">
                  <Play className="w-4 h-4 inline mr-1" />
                  Start
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Certifications */}
      <div className="mb-16">
        <h2 className="text-3xl font-bold text-white mb-8 text-center">Industry-Recognized Certifications</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-gradient-to-br from-cyan-900/30 to-blue-900/30 border border-cyan-700 rounded-xl p-6 text-center">
            <Award className="w-16 h-16 text-cyan-400 mx-auto mb-4" />
            <h3 className="text-xl font-bold text-white mb-2">Certificate of Completion</h3>
            <p className="text-gray-400 text-sm mb-4">Complete the beginner path to earn your first certificate.</p>
            <span className="text-green-400 font-bold">Free</span>
          </div>
          <div className="bg-gradient-to-br from-purple-900/30 to-pink-900/30 border border-purple-700 rounded-xl p-6 text-center">
            <Award className="w-16 h-16 text-purple-400 mx-auto mb-4" />
            <h3 className="text-xl font-bold text-white mb-2">HeroForge Certified Analyst</h3>
            <p className="text-gray-400 text-sm mb-4">Validate your security assessment skills with the HCA credential.</p>
            <span className="text-white font-bold">$199</span>
          </div>
          <div className="bg-gradient-to-br from-orange-900/30 to-red-900/30 border border-orange-700 rounded-xl p-6 text-center">
            <Trophy className="w-16 h-16 text-orange-400 mx-auto mb-4" />
            <h3 className="text-xl font-bold text-white mb-2">HeroForge Certified Professional</h3>
            <p className="text-gray-400 text-sm mb-4">The ultimate credential for security professionals.</p>
            <span className="text-white font-bold">$499</span>
          </div>
        </div>
      </div>

      {/* CTA */}
      <div className="bg-gradient-to-r from-cyan-900/50 to-purple-900/50 border border-cyan-700 rounded-xl p-12 text-center">
        <h2 className="text-3xl font-bold text-white mb-4">Ready to Start Your Security Journey?</h2>
        <p className="text-gray-300 mb-8 max-w-2xl mx-auto">
          Join thousands of security professionals who have advanced their careers with HeroForge Academy.
          Start with our free beginner path today.
        </p>
        <Link
          to="/academy/path/beginner"
          className="inline-block bg-cyan-600 hover:bg-cyan-700 text-white font-bold px-8 py-4 rounded-lg transition-colors text-lg"
        >
          Get Started Free
        </Link>
      </div>
    </div>
  );
};

// Main AcademyPage component
const AcademyPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link to="/" className="flex items-center space-x-2">
            <span className="text-2xl font-bold text-cyan-400">HeroForge</span>
          </Link>
          <nav className="hidden md:flex items-center space-x-6">
            <Link to="/features" className="text-gray-300 hover:text-white">Features</Link>
            <Link to="/pricing" className="text-gray-300 hover:text-white">Pricing</Link>
            <Link to="/tools" className="text-gray-300 hover:text-white">Free Tools</Link>
            <Link to="/blog" className="text-gray-300 hover:text-white">Blog</Link>
            <Link to="/academy" className="text-cyan-400">Academy</Link>
            <Link to="/docs" className="text-gray-300 hover:text-white">Docs</Link>
            <Link to="/login" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg">Sign In</Link>
          </nav>
        </div>
      </header>

      {/* Main content */}
      <main className="max-w-6xl mx-auto px-4 py-12">
        <AcademyLanding />
      </main>

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 mt-16">
        <div className="max-w-6xl mx-auto px-4 py-8">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <p className="text-gray-400 text-sm">
              &copy; 2026 Genial Architect Cybersecurity Research Associates. All rights reserved.
            </p>
            <div className="flex space-x-6 mt-4 md:mt-0">
              <Link to="/legal/terms" className="text-gray-400 hover:text-white text-sm">Terms</Link>
              <Link to="/legal/privacy" className="text-gray-400 hover:text-white text-sm">Privacy</Link>
              <Link to="/docs" className="text-gray-400 hover:text-white text-sm">Documentation</Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default AcademyPage;
