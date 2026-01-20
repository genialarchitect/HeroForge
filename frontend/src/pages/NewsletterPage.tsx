import React, { useState } from 'react';
import { Link } from 'react-router-dom';

interface NewsletterIssue {
  id: string;
  number: number;
  title: string;
  description: string;
  date: string;
  status: 'published' | 'scheduled';
  topics: string[];
  readTime: string;
  highlights?: string[];
}

// Year's worth of newsletter content (52 weeks)
const newsletterIssues: NewsletterIssue[] = [
  // January 2026
  {
    id: 'issue-1',
    number: 1,
    title: 'Welcome to HeroForge Weekly',
    description: 'Introducing our weekly security newsletter. What to expect, how to get the most out of HeroForge, and the top 5 vulnerabilities of 2025.',
    date: '2026-01-06',
    status: 'published',
    topics: ['Introduction', 'Getting Started', 'Top Vulnerabilities'],
    readTime: '5 min',
    highlights: ['Platform introduction', '2025 vulnerability recap', 'Quick start guide'],
  },
  {
    id: 'issue-2',
    number: 2,
    title: 'Mastering Network Reconnaissance',
    description: 'Deep dive into effective network scanning techniques. Passive vs active reconnaissance, avoiding detection, and documenting findings.',
    date: '2026-01-13',
    status: 'published',
    topics: ['Reconnaissance', 'Scanning', 'Best Practices'],
    readTime: '7 min',
    highlights: ['Passive recon techniques', 'Nmap alternatives', 'Documentation tips'],
  },
  {
    id: 'issue-3',
    number: 3,
    title: 'Understanding CVSS 4.0',
    description: 'Breaking down the new CVSS 4.0 scoring system. What changed from 3.1, how to interpret scores, and when scores don\'t tell the full story.',
    date: '2026-01-20',
    status: 'published',
    topics: ['CVSS', 'Vulnerability Scoring', 'Risk Assessment'],
    readTime: '8 min',
    highlights: ['CVSS 4.0 changes', 'Scoring examples', 'Beyond the score'],
  },
  {
    id: 'issue-4',
    number: 4,
    title: 'PCI-DSS 4.0: What You Need to Know',
    description: 'The new PCI-DSS 4.0 requirements are here. Key changes, compliance deadlines, and how HeroForge helps you stay compliant.',
    date: '2026-01-27',
    status: 'scheduled',
    topics: ['PCI-DSS', 'Compliance', 'Payment Security'],
    readTime: '10 min',
  },
  // February 2026
  {
    id: 'issue-5',
    number: 5,
    title: 'Web Application Security Fundamentals',
    description: 'OWASP Top 10 deep dive. Understanding injection attacks, broken authentication, and how to test for common web vulnerabilities.',
    date: '2026-02-03',
    status: 'scheduled',
    topics: ['Web Security', 'OWASP', 'Application Testing'],
    readTime: '9 min',
  },
  {
    id: 'issue-6',
    number: 6,
    title: 'Cloud Security: AWS Edition',
    description: 'Securing your AWS infrastructure. Common misconfigurations, IAM best practices, and automated security scanning with HeroForge.',
    date: '2026-02-10',
    status: 'scheduled',
    topics: ['AWS', 'Cloud Security', 'IAM'],
    readTime: '8 min',
  },
  {
    id: 'issue-7',
    number: 7,
    title: 'Valentine\'s Day Security Special',
    description: 'Love is in the air, and so are romance scams. Protecting yourself and your organization from social engineering attacks.',
    date: '2026-02-17',
    status: 'scheduled',
    topics: ['Social Engineering', 'Phishing', 'Awareness'],
    readTime: '6 min',
  },
  {
    id: 'issue-8',
    number: 8,
    title: 'Reporting That Gets Results',
    description: 'How to write security reports that executives actually read. Formatting, prioritization, and actionable recommendations.',
    date: '2026-02-24',
    status: 'scheduled',
    topics: ['Reporting', 'Communication', 'Executive Summary'],
    readTime: '7 min',
  },
  // March 2026
  {
    id: 'issue-9',
    number: 9,
    title: 'Active Directory Security',
    description: 'Attacking and defending Active Directory. Common attack paths, Kerberoasting, and how to audit your AD environment.',
    date: '2026-03-03',
    status: 'scheduled',
    topics: ['Active Directory', 'Windows Security', 'Kerberos'],
    readTime: '10 min',
  },
  {
    id: 'issue-10',
    number: 10,
    title: 'Container Security Best Practices',
    description: 'Securing Docker and Kubernetes deployments. Image scanning, runtime protection, and network policies.',
    date: '2026-03-10',
    status: 'scheduled',
    topics: ['Docker', 'Kubernetes', 'Container Security'],
    readTime: '9 min',
  },
  {
    id: 'issue-11',
    number: 11,
    title: 'API Security Testing',
    description: 'Testing REST and GraphQL APIs for vulnerabilities. Authentication bypasses, injection attacks, and rate limiting.',
    date: '2026-03-17',
    status: 'scheduled',
    topics: ['API Security', 'REST', 'GraphQL'],
    readTime: '8 min',
  },
  {
    id: 'issue-12',
    number: 12,
    title: 'Threat Intelligence for Practitioners',
    description: 'Using threat intelligence effectively. Free and paid sources, IOC management, and integrating intel into your workflow.',
    date: '2026-03-24',
    status: 'scheduled',
    topics: ['Threat Intelligence', 'IOC', 'CTI'],
    readTime: '7 min',
  },
  {
    id: 'issue-13',
    number: 13,
    title: 'Q1 2026 Vulnerability Roundup',
    description: 'The biggest vulnerabilities of Q1 2026. What was exploited, lessons learned, and preparing for what\'s next.',
    date: '2026-03-31',
    status: 'scheduled',
    topics: ['Quarterly Review', 'CVE Analysis', 'Trends'],
    readTime: '12 min',
  },
  // April 2026
  {
    id: 'issue-14',
    number: 14,
    title: 'Wireless Network Security',
    description: 'Auditing WiFi networks. WPA3 security, evil twin attacks, and rogue access point detection.',
    date: '2026-04-07',
    status: 'scheduled',
    topics: ['Wireless', 'WiFi', 'Network Security'],
    readTime: '8 min',
  },
  {
    id: 'issue-15',
    number: 15,
    title: 'Secure Code Review Essentials',
    description: 'Finding vulnerabilities in source code. Manual review techniques, SAST tools, and common vulnerability patterns.',
    date: '2026-04-14',
    status: 'scheduled',
    topics: ['Code Review', 'SAST', 'Secure Coding'],
    readTime: '9 min',
  },
  {
    id: 'issue-16',
    number: 16,
    title: 'Building a Security Program from Scratch',
    description: 'Starting a security program at a small company. Prioritizing efforts, building buy-in, and measuring success.',
    date: '2026-04-21',
    status: 'scheduled',
    topics: ['Security Program', 'Strategy', 'SMB Security'],
    readTime: '10 min',
  },
  {
    id: 'issue-17',
    number: 17,
    title: 'Password Cracking Techniques',
    description: 'Understanding password attacks to build better defenses. Hashcat, John the Ripper, and password policy recommendations.',
    date: '2026-04-28',
    status: 'scheduled',
    topics: ['Password Security', 'Cracking', 'Authentication'],
    readTime: '8 min',
  },
  // May 2026
  {
    id: 'issue-18',
    number: 18,
    title: 'Cloud Security: Azure Edition',
    description: 'Securing Microsoft Azure environments. Conditional access, Azure AD security, and resource configuration.',
    date: '2026-05-05',
    status: 'scheduled',
    topics: ['Azure', 'Cloud Security', 'Microsoft'],
    readTime: '9 min',
  },
  {
    id: 'issue-19',
    number: 19,
    title: 'Supply Chain Security',
    description: 'Protecting against supply chain attacks. SBOMs, dependency scanning, and vendor risk management.',
    date: '2026-05-12',
    status: 'scheduled',
    topics: ['Supply Chain', 'SBOM', 'Third-Party Risk'],
    readTime: '8 min',
  },
  {
    id: 'issue-20',
    number: 20,
    title: 'Red Team Operations',
    description: 'Advanced adversary simulation techniques. C2 frameworks, evasion techniques, and realistic attack scenarios.',
    date: '2026-05-19',
    status: 'scheduled',
    topics: ['Red Team', 'Adversary Simulation', 'C2'],
    readTime: '11 min',
  },
  {
    id: 'issue-21',
    number: 21,
    title: 'Memorial Day Security Reminder',
    description: 'Security while traveling. Protecting devices abroad, public WiFi risks, and border crossing considerations.',
    date: '2026-05-26',
    status: 'scheduled',
    topics: ['Travel Security', 'Physical Security', 'Privacy'],
    readTime: '6 min',
  },
  // June 2026
  {
    id: 'issue-22',
    number: 22,
    title: 'HIPAA Compliance Deep Dive',
    description: 'Healthcare security requirements explained. Technical safeguards, risk assessments, and breach notification.',
    date: '2026-06-02',
    status: 'scheduled',
    topics: ['HIPAA', 'Healthcare', 'Compliance'],
    readTime: '10 min',
  },
  {
    id: 'issue-23',
    number: 23,
    title: 'Incident Response Planning',
    description: 'Building an effective IR plan. Detection, containment, eradication, and lessons learned.',
    date: '2026-06-09',
    status: 'scheduled',
    topics: ['Incident Response', 'IR Plan', 'DFIR'],
    readTime: '9 min',
  },
  {
    id: 'issue-24',
    number: 24,
    title: 'Privilege Escalation Techniques',
    description: 'Windows and Linux privilege escalation. Misconfigurations to look for and how to prevent them.',
    date: '2026-06-16',
    status: 'scheduled',
    topics: ['Privilege Escalation', 'Linux', 'Windows'],
    readTime: '10 min',
  },
  {
    id: 'issue-25',
    number: 25,
    title: 'DevSecOps Pipeline Security',
    description: 'Integrating security into CI/CD. GitHub Actions, GitLab CI, and Jenkins security scanning.',
    date: '2026-06-23',
    status: 'scheduled',
    topics: ['DevSecOps', 'CI/CD', 'Pipeline Security'],
    readTime: '8 min',
  },
  {
    id: 'issue-26',
    number: 26,
    title: 'Mid-Year Security Review',
    description: 'H1 2026 in review. Major breaches, emerging threats, and predictions for the second half.',
    date: '2026-06-30',
    status: 'scheduled',
    topics: ['Half-Year Review', 'Trends', 'Predictions'],
    readTime: '12 min',
  },
  // July 2026
  {
    id: 'issue-27',
    number: 27,
    title: 'Cloud Security: GCP Edition',
    description: 'Google Cloud Platform security fundamentals. IAM, VPC security, and GCP-specific best practices.',
    date: '2026-07-07',
    status: 'scheduled',
    topics: ['GCP', 'Cloud Security', 'Google Cloud'],
    readTime: '9 min',
  },
  {
    id: 'issue-28',
    number: 28,
    title: 'Mobile Application Security',
    description: 'Testing iOS and Android applications. Static analysis, dynamic testing, and API security.',
    date: '2026-07-14',
    status: 'scheduled',
    topics: ['Mobile Security', 'iOS', 'Android'],
    readTime: '10 min',
  },
  {
    id: 'issue-29',
    number: 29,
    title: 'Ransomware Defense Strategies',
    description: 'Protecting against ransomware. Backup strategies, network segmentation, and recovery planning.',
    date: '2026-07-21',
    status: 'scheduled',
    topics: ['Ransomware', 'Defense', 'Recovery'],
    readTime: '9 min',
  },
  {
    id: 'issue-30',
    number: 30,
    title: 'Security Automation with Python',
    description: 'Automating security tasks with Python. Scripts for reconnaissance, monitoring, and alerting.',
    date: '2026-07-28',
    status: 'scheduled',
    topics: ['Python', 'Automation', 'Scripting'],
    readTime: '8 min',
  },
  // August 2026
  {
    id: 'issue-31',
    number: 31,
    title: 'Zero Trust Architecture',
    description: 'Implementing zero trust. Identity-centric security, microsegmentation, and continuous verification.',
    date: '2026-08-04',
    status: 'scheduled',
    topics: ['Zero Trust', 'Architecture', 'Identity'],
    readTime: '10 min',
  },
  {
    id: 'issue-32',
    number: 32,
    title: 'SIEM Best Practices',
    description: 'Getting value from your SIEM. Use cases, alert tuning, and correlation rules that work.',
    date: '2026-08-11',
    status: 'scheduled',
    topics: ['SIEM', 'Logging', 'Monitoring'],
    readTime: '9 min',
  },
  {
    id: 'issue-33',
    number: 33,
    title: 'Black Hat & DEF CON Recap',
    description: 'Key takeaways from Black Hat and DEF CON 2026. New research, tools, and vulnerabilities.',
    date: '2026-08-18',
    status: 'scheduled',
    topics: ['Conference', 'Research', 'New Tools'],
    readTime: '11 min',
  },
  {
    id: 'issue-34',
    number: 34,
    title: 'DNS Security Deep Dive',
    description: 'DNS as an attack vector. DNS tunneling, cache poisoning, and DNS security solutions.',
    date: '2026-08-25',
    status: 'scheduled',
    topics: ['DNS', 'Network Security', 'Monitoring'],
    readTime: '8 min',
  },
  // September 2026
  {
    id: 'issue-35',
    number: 35,
    title: 'SOC 2 Certification Guide',
    description: 'Preparing for SOC 2 Type II. Controls, evidence collection, and audit preparation.',
    date: '2026-09-01',
    status: 'scheduled',
    topics: ['SOC 2', 'Compliance', 'Audit'],
    readTime: '10 min',
  },
  {
    id: 'issue-36',
    number: 36,
    title: 'Threat Hunting Fundamentals',
    description: 'Proactive threat hunting techniques. Hypothesis-driven hunting, TTPs, and hunting playbooks.',
    date: '2026-09-08',
    status: 'scheduled',
    topics: ['Threat Hunting', 'Detection', 'MITRE'],
    readTime: '9 min',
  },
  {
    id: 'issue-37',
    number: 37,
    title: 'Email Security',
    description: 'Protecting against email-based attacks. DMARC, DKIM, SPF, and advanced email threats.',
    date: '2026-09-15',
    status: 'scheduled',
    topics: ['Email Security', 'Phishing', 'BEC'],
    readTime: '8 min',
  },
  {
    id: 'issue-38',
    number: 38,
    title: 'ICS/OT Security',
    description: 'Securing industrial control systems. SCADA security, network segmentation, and OT monitoring.',
    date: '2026-09-22',
    status: 'scheduled',
    topics: ['ICS', 'OT', 'Industrial Security'],
    readTime: '10 min',
  },
  {
    id: 'issue-39',
    number: 39,
    title: 'Q3 2026 Vulnerability Roundup',
    description: 'The biggest vulnerabilities of Q3 2026. Exploitation trends and defensive strategies.',
    date: '2026-09-29',
    status: 'scheduled',
    topics: ['Quarterly Review', 'CVE Analysis', 'Trends'],
    readTime: '12 min',
  },
  // October 2026
  {
    id: 'issue-40',
    number: 40,
    title: 'Cybersecurity Awareness Month',
    description: 'Security awareness program ideas. Training effectiveness, phishing simulations, and culture building.',
    date: '2026-10-06',
    status: 'scheduled',
    topics: ['Security Awareness', 'Training', 'Culture'],
    readTime: '7 min',
  },
  {
    id: 'issue-41',
    number: 41,
    title: 'Penetration Testing Methodology',
    description: 'Structured approach to pentesting. PTES, OWASP, and custom methodologies.',
    date: '2026-10-13',
    status: 'scheduled',
    topics: ['Pentest', 'Methodology', 'Standards'],
    readTime: '9 min',
  },
  {
    id: 'issue-42',
    number: 42,
    title: 'Identity and Access Management',
    description: 'IAM best practices. SSO, MFA, privileged access management, and access reviews.',
    date: '2026-10-20',
    status: 'scheduled',
    topics: ['IAM', 'Identity', 'Access Control'],
    readTime: '8 min',
  },
  {
    id: 'issue-43',
    number: 43,
    title: 'Halloween Hacker Stories',
    description: 'Scary true stories from the security trenches. Real incidents and lessons learned.',
    date: '2026-10-27',
    status: 'scheduled',
    topics: ['Stories', 'Incidents', 'Lessons Learned'],
    readTime: '10 min',
  },
  // November 2026
  {
    id: 'issue-44',
    number: 44,
    title: 'Endpoint Security Evolution',
    description: 'Beyond antivirus. EDR, XDR, and next-gen endpoint protection strategies.',
    date: '2026-11-03',
    status: 'scheduled',
    topics: ['Endpoint', 'EDR', 'XDR'],
    readTime: '8 min',
  },
  {
    id: 'issue-45',
    number: 45,
    title: 'Network Segmentation',
    description: 'Implementing effective network segmentation. VLANs, microsegmentation, and zero trust networks.',
    date: '2026-11-10',
    status: 'scheduled',
    topics: ['Segmentation', 'Network', 'Architecture'],
    readTime: '9 min',
  },
  {
    id: 'issue-46',
    number: 46,
    title: 'Security Budget Planning for 2027',
    description: 'Building your security budget. ROI calculations, prioritization, and justifying spend.',
    date: '2026-11-17',
    status: 'scheduled',
    topics: ['Budget', 'Planning', 'ROI'],
    readTime: '8 min',
  },
  {
    id: 'issue-47',
    number: 47,
    title: 'Black Friday Security',
    description: 'E-commerce security during peak season. Fraud prevention, DDoS protection, and PCI compliance.',
    date: '2026-11-24',
    status: 'scheduled',
    topics: ['E-commerce', 'Fraud', 'DDoS'],
    readTime: '7 min',
  },
  // December 2026
  {
    id: 'issue-48',
    number: 48,
    title: 'AI in Security: State of the Art',
    description: 'How AI is transforming security. Detection, response, and the future of AI-powered security.',
    date: '2026-12-01',
    status: 'scheduled',
    topics: ['AI', 'Machine Learning', 'Future'],
    readTime: '10 min',
  },
  {
    id: 'issue-49',
    number: 49,
    title: 'Log4Shell Anniversary',
    description: 'One year later: lessons from Log4Shell. Dependency management and vulnerability response.',
    date: '2026-12-08',
    status: 'scheduled',
    topics: ['Log4Shell', 'Retrospective', 'Dependencies'],
    readTime: '9 min',
  },
  {
    id: 'issue-50',
    number: 50,
    title: 'Holiday Security Checklist',
    description: 'Security tasks before the holidays. Coverage planning, monitoring, and incident readiness.',
    date: '2026-12-15',
    status: 'scheduled',
    topics: ['Checklist', 'Planning', 'Coverage'],
    readTime: '6 min',
  },
  {
    id: 'issue-51',
    number: 51,
    title: '2026 Year in Review',
    description: 'The biggest security stories of 2026. Breaches, vulnerabilities, and industry milestones.',
    date: '2026-12-22',
    status: 'scheduled',
    topics: ['Year Review', 'Retrospective', 'Top Stories'],
    readTime: '15 min',
  },
  {
    id: 'issue-52',
    number: 52,
    title: '2027 Security Predictions',
    description: 'What to expect in 2027. Emerging threats, technology trends, and security priorities.',
    date: '2026-12-29',
    status: 'scheduled',
    topics: ['Predictions', 'Trends', '2027'],
    readTime: '12 min',
  },
];

const NewsletterPage: React.FC = () => {
  const [email, setEmail] = useState('');
  const [subscribed, setSubscribed] = useState(false);
  const [selectedTopic, setSelectedTopic] = useState<string>('all');
  const [showArchive, setShowArchive] = useState(false);

  const topics = Array.from(new Set(newsletterIssues.flatMap(i => i.topics))).sort();

  const publishedIssues = newsletterIssues.filter(i => i.status === 'published');
  const upcomingIssues = newsletterIssues.filter(i => i.status === 'scheduled').slice(0, 8);

  const filteredIssues = selectedTopic === 'all'
    ? newsletterIssues
    : newsletterIssues.filter(i => i.topics.includes(selectedTopic));

  const handleSubscribe = (e: React.FormEvent) => {
    e.preventDefault();
    if (email) {
      setSubscribed(true);
      setEmail('');
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'long',
      day: 'numeric',
      year: 'numeric',
    });
  };

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link to="/" className="flex items-center space-x-2">
            <span className="text-2xl font-bold text-cyan-400">HeroForge</span>
            <span className="text-gray-400">Newsletter</span>
          </Link>
          <nav className="hidden md:flex items-center space-x-6">
            <Link to="/blog" className="text-gray-300 hover:text-white">Blog</Link>
            <Link to="/academy" className="text-gray-300 hover:text-white">Academy</Link>
            <Link to="/docs" className="text-gray-300 hover:text-white">Docs</Link>
            <Link to="/login" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg">Sign In</Link>
          </nav>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-12">
        {/* Hero / Subscribe Section */}
        <div className="bg-gradient-to-r from-cyan-900/50 to-blue-900/50 rounded-2xl border border-cyan-700/50 p-8 md:p-12 mb-12">
          <div className="max-w-2xl">
            <div className="flex items-center gap-2 mb-4">
              <span className="text-3xl">📧</span>
              <span className="text-cyan-400 font-medium">Weekly Security Newsletter</span>
            </div>
            <h1 className="text-4xl md:text-5xl font-bold text-white mb-4">
              HeroForge Weekly
            </h1>
            <p className="text-xl text-gray-300 mb-8">
              Stay ahead of threats with weekly security insights, vulnerability analysis,
              best practices, and industry news delivered to your inbox every Monday.
            </p>

            {subscribed ? (
              <div className="flex items-center gap-3 bg-green-500/20 border border-green-500/50 rounded-lg p-4">
                <svg className="w-6 h-6 text-green-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
                <div>
                  <p className="text-green-400 font-medium">You're subscribed!</p>
                  <p className="text-green-300/70 text-sm">Check your inbox for a confirmation email.</p>
                </div>
              </div>
            ) : (
              <form onSubmit={handleSubscribe} className="flex flex-col sm:flex-row gap-3">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Enter your email"
                  className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  required
                />
                <button
                  type="submit"
                  className="px-8 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium transition-colors whitespace-nowrap"
                >
                  Subscribe Free
                </button>
              </form>
            )}
            <p className="text-gray-500 text-sm mt-4">
              Join 5,000+ security professionals. Unsubscribe anytime.
            </p>
          </div>
        </div>

        {/* What You'll Get */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
          {[
            {
              icon: '🎯',
              title: 'Vulnerability Analysis',
              description: 'Deep dives into critical CVEs, exploitation techniques, and remediation guidance.',
            },
            {
              icon: '📚',
              title: 'Best Practices',
              description: 'Security frameworks, compliance guidance, and industry standards explained.',
            },
            {
              icon: '🔧',
              title: 'Tools & Techniques',
              description: 'Tutorials, tool reviews, and hands-on guides for security practitioners.',
            },
          ].map((item) => (
            <div key={item.title} className="bg-gray-800 rounded-xl border border-gray-700 p-6">
              <span className="text-3xl mb-4 block">{item.icon}</span>
              <h3 className="text-lg font-semibold text-white mb-2">{item.title}</h3>
              <p className="text-gray-400">{item.description}</p>
            </div>
          ))}
        </div>

        {/* Latest Issues */}
        {publishedIssues.length > 0 && (
          <div className="mb-12">
            <h2 className="text-2xl font-bold text-white mb-6">Latest Issues</h2>
            <div className="space-y-4">
              {publishedIssues.map((issue) => (
                <div
                  key={issue.id}
                  className="bg-gray-800 rounded-xl border border-gray-700 p-6 hover:border-cyan-500/50 transition-colors cursor-pointer"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <span className="text-cyan-400 text-sm font-medium">#{issue.number}</span>
                        <span className="text-gray-500 text-sm">{formatDate(issue.date)}</span>
                        <span className="text-gray-500 text-sm">· {issue.readTime}</span>
                      </div>
                      <h3 className="text-lg font-semibold text-white mb-2">{issue.title}</h3>
                      <p className="text-gray-400 mb-3">{issue.description}</p>
                      {issue.highlights && (
                        <div className="flex flex-wrap gap-2">
                          {issue.highlights.map((h) => (
                            <span key={h} className="text-xs bg-cyan-500/20 text-cyan-400 px-2 py-1 rounded">
                              {h}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                    <button className="text-cyan-400 hover:text-cyan-300 transition-colors">
                      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                      </svg>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Upcoming Schedule */}
        <div className="mb-12">
          <h2 className="text-2xl font-bold text-white mb-6">Coming Up</h2>
          <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
            <div className="divide-y divide-gray-700">
              {upcomingIssues.map((issue) => (
                <div key={issue.id} className="p-4 hover:bg-gray-750 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 bg-gray-700 rounded-lg flex items-center justify-center">
                        <span className="text-gray-400 font-medium">#{issue.number}</span>
                      </div>
                      <div>
                        <h3 className="text-white font-medium">{issue.title}</h3>
                        <p className="text-gray-500 text-sm">{formatDate(issue.date)}</p>
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {issue.topics.slice(0, 2).map((topic) => (
                        <span key={topic} className="text-xs bg-gray-700 text-gray-400 px-2 py-1 rounded">
                          {topic}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Full Archive Toggle */}
        <div className="mb-8">
          <button
            onClick={() => setShowArchive(!showArchive)}
            className="flex items-center gap-2 text-cyan-400 hover:text-cyan-300 transition-colors"
          >
            <span>{showArchive ? 'Hide' : 'View'} Full 2026 Schedule ({newsletterIssues.length} issues)</span>
            <svg
              className={`w-5 h-5 transition-transform ${showArchive ? 'rotate-180' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
        </div>

        {/* Full Archive */}
        {showArchive && (
          <div className="mb-12">
            {/* Topic Filter */}
            <div className="flex flex-wrap gap-2 mb-6">
              <button
                onClick={() => setSelectedTopic('all')}
                className={`px-3 py-1 rounded-lg text-sm transition-colors ${
                  selectedTopic === 'all'
                    ? 'bg-cyan-600 text-white'
                    : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                }`}
              >
                All Topics
              </button>
              {topics.slice(0, 15).map((topic) => (
                <button
                  key={topic}
                  onClick={() => setSelectedTopic(topic)}
                  className={`px-3 py-1 rounded-lg text-sm transition-colors ${
                    selectedTopic === topic
                      ? 'bg-cyan-600 text-white'
                      : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                  }`}
                >
                  {topic}
                </button>
              ))}
            </div>

            {/* Archive Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filteredIssues.map((issue) => (
                <div
                  key={issue.id}
                  className={`bg-gray-800 rounded-lg border p-4 ${
                    issue.status === 'published'
                      ? 'border-green-500/30 hover:border-green-500/50'
                      : 'border-gray-700 hover:border-gray-600'
                  } transition-colors`}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-sm font-medium text-gray-400">#{issue.number}</span>
                    <span className="text-gray-600">·</span>
                    <span className="text-sm text-gray-500">{formatDate(issue.date)}</span>
                    {issue.status === 'published' && (
                      <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded">Published</span>
                    )}
                  </div>
                  <h3 className="text-white font-medium mb-1">{issue.title}</h3>
                  <p className="text-gray-500 text-sm line-clamp-2">{issue.description}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* CTA */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-8 text-center">
          <h2 className="text-2xl font-bold text-white mb-4">Never Miss an Issue</h2>
          <p className="text-gray-400 mb-6">
            Subscribe to HeroForge Weekly and stay on top of the latest security trends,
            vulnerabilities, and best practices.
          </p>
          {!subscribed && (
            <form onSubmit={handleSubscribe} className="flex flex-col sm:flex-row gap-3 max-w-md mx-auto">
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter your email"
                className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                required
              />
              <button
                type="submit"
                className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium transition-colors"
              >
                Subscribe
              </button>
            </form>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 mt-16">
        <div className="max-w-5xl mx-auto px-4 py-8">
          <div className="flex flex-col md:flex-row justify-between items-center gap-4">
            <p className="text-gray-500 text-sm">
              &copy; {new Date().getFullYear()} HeroForge Security. All rights reserved.
            </p>
            <div className="flex items-center gap-6">
              <Link to="/blog" className="text-gray-400 hover:text-white text-sm">Blog</Link>
              <Link to="/legal/privacy" className="text-gray-400 hover:text-white text-sm">Privacy</Link>
              <a href="mailto:newsletter@heroforge.io" className="text-gray-400 hover:text-white text-sm">Contact</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default NewsletterPage;
