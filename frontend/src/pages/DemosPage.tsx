import React, { useState } from 'react';
import { Link } from 'react-router-dom';

interface DemoVideo {
  id: string;
  title: string;
  description: string;
  duration: string;
  category: string;
  youtubeId: string;
  thumbnail?: string;
  featured?: boolean;
}

// Static video data - can be moved to an API later
const demoVideos: DemoVideo[] = [
  // Getting Started
  {
    id: '1',
    title: 'Getting Started with HeroForge',
    description: 'A complete walkthrough of setting up your first security scan, understanding the dashboard, and navigating the platform.',
    duration: '8:24',
    category: 'Getting Started',
    youtubeId: 'dQw4w9WgXcQ', // Placeholder - replace with actual video IDs
    featured: true,
  },
  {
    id: '2',
    title: 'Quick Start: Your First Scan in 5 Minutes',
    description: 'Learn how to run your first vulnerability scan and interpret the results.',
    duration: '5:12',
    category: 'Getting Started',
    youtubeId: 'dQw4w9WgXcQ',
  },
  {
    id: '3',
    title: 'Account Setup & Team Management',
    description: 'Configure your account settings, invite team members, and set up permissions.',
    duration: '6:45',
    category: 'Getting Started',
    youtubeId: 'dQw4w9WgXcQ',
  },
  // Scanning
  {
    id: '4',
    title: 'Deep Dive: Network Scanning',
    description: 'Master network reconnaissance with port scanning, service detection, and OS fingerprinting.',
    duration: '12:30',
    category: 'Scanning',
    youtubeId: 'dQw4w9WgXcQ',
  },
  {
    id: '5',
    title: 'Web Application Security Testing',
    description: 'Discover vulnerabilities in web applications including XSS, SQLi, and OWASP Top 10.',
    duration: '15:18',
    category: 'Scanning',
    youtubeId: 'dQw4w9WgXcQ',
  },
  {
    id: '6',
    title: 'Cloud Security Scanning',
    description: 'Scan AWS, Azure, and GCP environments for misconfigurations and security issues.',
    duration: '11:42',
    category: 'Scanning',
    youtubeId: 'dQw4w9WgXcQ',
  },
  {
    id: '7',
    title: 'Container & Kubernetes Security',
    description: 'Secure your containerized workloads with Docker and Kubernetes scanning.',
    duration: '9:56',
    category: 'Scanning',
    youtubeId: 'dQw4w9WgXcQ',
  },
  // Compliance
  {
    id: '8',
    title: 'Compliance Made Easy',
    description: 'Map your security findings to compliance frameworks like SOC 2, PCI-DSS, and HIPAA.',
    duration: '10:22',
    category: 'Compliance',
    youtubeId: 'dQw4w9WgXcQ',
  },
  {
    id: '9',
    title: 'FedRAMP & CMMC Compliance',
    description: 'Navigate federal compliance requirements with automated control mapping.',
    duration: '14:08',
    category: 'Compliance',
    youtubeId: 'dQw4w9WgXcQ',
  },
  {
    id: '10',
    title: 'Generating Compliance Reports',
    description: 'Create audit-ready compliance reports for your security assessments.',
    duration: '7:33',
    category: 'Compliance',
    youtubeId: 'dQw4w9WgXcQ',
  },
  // Reports
  {
    id: '11',
    title: 'Creating Professional Pentest Reports',
    description: 'Generate executive and technical reports that impress your clients.',
    duration: '11:15',
    category: 'Reports',
    youtubeId: 'dQw4w9WgXcQ',
  },
  {
    id: '12',
    title: 'Customizing Report Templates',
    description: 'Build branded report templates with your company logo and formatting.',
    duration: '8:47',
    category: 'Reports',
    youtubeId: 'dQw4w9WgXcQ',
  },
  {
    id: '13',
    title: 'Export Options: PDF, HTML, CSV',
    description: 'Learn about different export formats and when to use each.',
    duration: '4:28',
    category: 'Reports',
    youtubeId: 'dQw4w9WgXcQ',
  },
  // Integrations
  {
    id: '14',
    title: 'JIRA Integration Setup',
    description: 'Automatically create JIRA tickets from vulnerabilities for seamless tracking.',
    duration: '6:52',
    category: 'Integrations',
    youtubeId: 'dQw4w9WgXcQ',
  },
  {
    id: '15',
    title: 'Slack & Teams Notifications',
    description: 'Set up real-time alerts for critical findings in your team chat.',
    duration: '5:19',
    category: 'Integrations',
    youtubeId: 'dQw4w9WgXcQ',
  },
  {
    id: '16',
    title: 'CI/CD Pipeline Integration',
    description: 'Add security scanning to your GitHub Actions, GitLab CI, or Jenkins pipelines.',
    duration: '9:41',
    category: 'Integrations',
    youtubeId: 'dQw4w9WgXcQ',
  },
  // AI Features
  {
    id: '17',
    title: 'AI-Powered Vulnerability Prioritization',
    description: 'Let AI help you focus on the vulnerabilities that matter most.',
    duration: '7:28',
    category: 'AI Features',
    youtubeId: 'dQw4w9WgXcQ',
  },
  {
    id: '18',
    title: 'AI Security Assistant (HeroBot)',
    description: 'Chat with AI to get security guidance, explain findings, and plan remediation.',
    duration: '8:55',
    category: 'AI Features',
    youtubeId: 'dQw4w9WgXcQ',
  },
  // Advanced
  {
    id: '19',
    title: 'Active Directory Assessment',
    description: 'Discover AD vulnerabilities, misconfigurations, and privilege escalation paths.',
    duration: '16:22',
    category: 'Advanced',
    youtubeId: 'dQw4w9WgXcQ',
  },
  {
    id: '20',
    title: 'Social Engineering Campaigns',
    description: 'Set up and manage phishing simulations to test your organization.',
    duration: '12:45',
    category: 'Advanced',
    youtubeId: 'dQw4w9WgXcQ',
  },
];

const categories = [
  'All',
  'Getting Started',
  'Scanning',
  'Compliance',
  'Reports',
  'Integrations',
  'AI Features',
  'Advanced',
];

const DemosPage: React.FC = () => {
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [selectedVideo, setSelectedVideo] = useState<DemoVideo | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  const featuredVideo = demoVideos.find(v => v.featured);

  const filteredVideos = demoVideos.filter(video => {
    const matchesCategory = selectedCategory === 'All' || video.category === selectedCategory;
    const matchesSearch = video.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          video.description.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch && !video.featured;
  });

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'Getting Started': return '🚀';
      case 'Scanning': return '🔍';
      case 'Compliance': return '📋';
      case 'Reports': return '📊';
      case 'Integrations': return '🔗';
      case 'AI Features': return '🤖';
      case 'Advanced': return '⚡';
      default: return '📹';
    }
  };

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link to="/" className="flex items-center space-x-2">
            <span className="text-2xl font-bold text-cyan-400">HeroForge</span>
            <span className="text-gray-400">Demos</span>
          </Link>
          <nav className="hidden md:flex items-center space-x-6">
            <Link to="/features" className="text-gray-300 hover:text-white">Features</Link>
            <Link to="/pricing" className="text-gray-300 hover:text-white">Pricing</Link>
            <Link to="/docs" className="text-gray-300 hover:text-white">Docs</Link>
            <Link to="/login" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg">Sign In</Link>
          </nav>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-12">
        {/* Hero Section */}
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold text-white mb-4">Video Demos</h1>
          <p className="text-xl text-gray-400 max-w-2xl mx-auto">
            Watch step-by-step tutorials and learn how to get the most out of HeroForge.
          </p>
        </div>

        {/* Featured Video */}
        {featuredVideo && (
          <div className="mb-12">
            <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <span className="text-yellow-400">⭐</span> Featured Demo
            </h2>
            <div
              onClick={() => setSelectedVideo(featuredVideo)}
              className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden cursor-pointer hover:border-cyan-500 transition-colors group"
            >
              <div className="grid md:grid-cols-2 gap-6">
                <div className="relative aspect-video bg-gray-900">
                  <img
                    src={`https://img.youtube.com/vi/${featuredVideo.youtubeId}/maxresdefault.jpg`}
                    alt={featuredVideo.title}
                    className="w-full h-full object-cover"
                    onError={(e) => {
                      (e.target as HTMLImageElement).src = `https://img.youtube.com/vi/${featuredVideo.youtubeId}/hqdefault.jpg`;
                    }}
                  />
                  <div className="absolute inset-0 flex items-center justify-center bg-black/30 group-hover:bg-black/40 transition-colors">
                    <div className="w-16 h-16 bg-cyan-600 rounded-full flex items-center justify-center group-hover:scale-110 transition-transform">
                      <svg className="w-8 h-8 text-white ml-1" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M8 5v14l11-7z" />
                      </svg>
                    </div>
                  </div>
                  <span className="absolute bottom-3 right-3 bg-black/80 text-white text-sm px-2 py-1 rounded">
                    {featuredVideo.duration}
                  </span>
                </div>
                <div className="p-6 flex flex-col justify-center">
                  <span className="text-cyan-400 text-sm font-medium mb-2">{featuredVideo.category}</span>
                  <h3 className="text-2xl font-bold text-white mb-3">{featuredVideo.title}</h3>
                  <p className="text-gray-400">{featuredVideo.description}</p>
                  <button className="mt-4 px-6 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium w-fit">
                    Watch Now
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Search and Filter */}
        <div className="flex flex-col md:flex-row gap-4 mb-8">
          {/* Search */}
          <div className="relative flex-1">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search demos..."
              className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-10 pr-4 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
          {/* Category Filter */}
          <div className="flex flex-wrap gap-2">
            {categories.map((category) => (
              <button
                key={category}
                onClick={() => setSelectedCategory(category)}
                className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                  selectedCategory === category
                    ? 'bg-cyan-600 text-white'
                    : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                }`}
              >
                {category}
              </button>
            ))}
          </div>
        </div>

        {/* Video Grid */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredVideos.map((video) => (
            <div
              key={video.id}
              onClick={() => setSelectedVideo(video)}
              className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden cursor-pointer hover:border-cyan-500 transition-colors group"
            >
              <div className="relative aspect-video bg-gray-900">
                <img
                  src={`https://img.youtube.com/vi/${video.youtubeId}/hqdefault.jpg`}
                  alt={video.title}
                  className="w-full h-full object-cover"
                />
                <div className="absolute inset-0 flex items-center justify-center bg-black/30 group-hover:bg-black/40 transition-colors">
                  <div className="w-12 h-12 bg-cyan-600 rounded-full flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">
                    <svg className="w-6 h-6 text-white ml-0.5" fill="currentColor" viewBox="0 0 24 24">
                      <path d="M8 5v14l11-7z" />
                    </svg>
                  </div>
                </div>
                <span className="absolute bottom-2 right-2 bg-black/80 text-white text-xs px-2 py-1 rounded">
                  {video.duration}
                </span>
              </div>
              <div className="p-4">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-sm">{getCategoryIcon(video.category)}</span>
                  <span className="text-cyan-400 text-xs font-medium">{video.category}</span>
                </div>
                <h3 className="text-white font-medium mb-2 line-clamp-2">{video.title}</h3>
                <p className="text-gray-400 text-sm line-clamp-2">{video.description}</p>
              </div>
            </div>
          ))}
        </div>

        {filteredVideos.length === 0 && (
          <div className="text-center py-12">
            <p className="text-gray-400">No demos found matching your search.</p>
          </div>
        )}

        {/* CTA Section */}
        <div className="mt-16 bg-gradient-to-r from-cyan-900/30 to-blue-900/30 rounded-xl border border-cyan-700/50 p-8 text-center">
          <h2 className="text-2xl font-bold text-white mb-2">Ready to try HeroForge?</h2>
          <p className="text-gray-400 mb-6 max-w-xl mx-auto">
            Start your free trial and experience enterprise-grade security testing for yourself.
          </p>
          <div className="flex justify-center gap-4">
            <Link
              to="/register"
              className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium transition-colors"
            >
              Start Free Trial
            </Link>
            <Link
              to="/pricing"
              className="px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg font-medium transition-colors"
            >
              View Pricing
            </Link>
          </div>
        </div>
      </main>

      {/* Video Modal */}
      {selectedVideo && (
        <div
          className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4"
          onClick={() => setSelectedVideo(null)}
        >
          <div
            className="bg-gray-900 rounded-xl overflow-hidden max-w-4xl w-full"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between p-4 border-b border-gray-700">
              <div>
                <span className="text-cyan-400 text-sm font-medium">{selectedVideo.category}</span>
                <h3 className="text-white font-semibold">{selectedVideo.title}</h3>
              </div>
              <button
                onClick={() => setSelectedVideo(null)}
                className="text-gray-400 hover:text-white p-2"
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="relative aspect-video">
              <iframe
                src={`https://www.youtube.com/embed/${selectedVideo.youtubeId}?autoplay=1`}
                title={selectedVideo.title}
                className="w-full h-full"
                frameBorder="0"
                allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                allowFullScreen
              />
            </div>
            <div className="p-4 border-t border-gray-700">
              <p className="text-gray-400 text-sm">{selectedVideo.description}</p>
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 mt-16">
        <div className="max-w-6xl mx-auto px-4 py-8">
          <div className="flex flex-col md:flex-row justify-between items-center gap-4">
            <p className="text-gray-500 text-sm">
              &copy; {new Date().getFullYear()} HeroForge Security. All rights reserved.
            </p>
            <div className="flex items-center gap-6">
              <Link to="/status" className="text-gray-400 hover:text-white text-sm">System Status</Link>
              <Link to="/roadmap" className="text-gray-400 hover:text-white text-sm">Roadmap</Link>
              <Link to="/legal/terms" className="text-gray-400 hover:text-white text-sm">Terms</Link>
              <Link to="/legal/privacy" className="text-gray-400 hover:text-white text-sm">Privacy</Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default DemosPage;
