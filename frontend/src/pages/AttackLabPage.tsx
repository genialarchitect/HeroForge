import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Play,
  Pause,
  Square,
  Clock,
  Target,
  Trophy,
  Star,
  Lock,
  Unlock,
  Server,
  Globe,
  Database,
  Network,
  Terminal,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ArrowRight,
  RefreshCw,
  Zap,
  BookOpen,
  Users,
  Award,
  ChevronRight,
  Flag,
  Flame,
  Skull,
  Bug,
  Eye,
  Code,
  Wifi,
  Cloud,
  Box,
  Cpu,
  HardDrive,
  Settings,
  Timer,
  Lightbulb,
  MessageSquare,
} from 'lucide-react';

interface Lab {
  id: string;
  title: string;
  description: string;
  category: 'web' | 'network' | 'cloud' | 'ad' | 'container' | 'iot';
  difficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert';
  duration: string;
  points: number;
  objectives: string[];
  tools: string[];
  prerequisites: string[];
  completionRate: number;
  featured?: boolean;
  isNew?: boolean;
  machines: {
    name: string;
    type: string;
    ip?: string;
  }[];
}

interface UserProgress {
  labId: string;
  status: 'not_started' | 'in_progress' | 'completed';
  completedObjectives: number[];
  startedAt?: string;
  completedAt?: string;
  timeSpent: number; // minutes
  flagsFound: string[];
  score: number;
}

const labs: Lab[] = [
  {
    id: 'web-basics',
    title: 'Web Application Fundamentals',
    description: 'Learn to identify and exploit common web vulnerabilities including SQL injection, XSS, and authentication bypasses.',
    category: 'web',
    difficulty: 'beginner',
    duration: '2-3 hours',
    points: 100,
    objectives: [
      'Perform reconnaissance on the web application',
      'Identify SQL injection vulnerability in login form',
      'Extract user credentials from database',
      'Discover stored XSS vulnerability',
      'Bypass authentication to access admin panel',
      'Capture the flag from admin dashboard',
    ],
    tools: ['HeroForge Scanner', 'Browser DevTools', 'Burp Suite (optional)'],
    prerequisites: ['Basic HTTP/HTML knowledge', 'Understanding of web forms'],
    completionRate: 78,
    machines: [
      { name: 'web-target', type: 'Linux', ip: '10.10.10.10' },
    ],
  },
  {
    id: 'network-pentest',
    title: 'Network Penetration Testing',
    description: 'Conduct a full network penetration test against a simulated corporate environment with multiple hosts.',
    category: 'network',
    difficulty: 'intermediate',
    duration: '4-6 hours',
    points: 250,
    featured: true,
    objectives: [
      'Perform network discovery and enumeration',
      'Identify vulnerable services on each host',
      'Exploit SMB vulnerability on file server',
      'Perform privilege escalation on Linux host',
      'Pivot to internal network segment',
      'Capture domain administrator credentials',
      'Access the secret file on the domain controller',
    ],
    tools: ['HeroForge Scanner', 'Nmap', 'Metasploit', 'CrackMapExec'],
    prerequisites: ['HCA Certification or equivalent', 'Network fundamentals'],
    completionRate: 45,
    machines: [
      { name: 'gateway', type: 'Linux', ip: '10.10.10.1' },
      { name: 'web-server', type: 'Linux', ip: '10.10.10.10' },
      { name: 'file-server', type: 'Windows', ip: '10.10.10.20' },
      { name: 'dc01', type: 'Windows', ip: '10.10.10.100' },
    ],
  },
  {
    id: 'cloud-aws',
    title: 'AWS Security Assessment',
    description: 'Identify and exploit misconfigurations in a realistic AWS environment including S3, IAM, and EC2.',
    category: 'cloud',
    difficulty: 'intermediate',
    duration: '3-4 hours',
    points: 200,
    isNew: true,
    objectives: [
      'Enumerate publicly accessible S3 buckets',
      'Find leaked AWS credentials',
      'Escalate IAM privileges',
      'Access sensitive data in private bucket',
      'Compromise EC2 instance via SSRF',
      'Exfiltrate data from RDS database',
    ],
    tools: ['HeroForge Cloud Scanner', 'AWS CLI', 'Pacu'],
    prerequisites: ['AWS fundamentals', 'Basic cloud security knowledge'],
    completionRate: 32,
    machines: [
      { name: 'web-app', type: 'EC2', ip: 'public' },
      { name: 'internal-api', type: 'EC2', ip: 'private' },
      { name: 'database', type: 'RDS', ip: 'private' },
    ],
  },
  {
    id: 'ad-attack',
    title: 'Active Directory Attack Path',
    description: 'Compromise a Windows domain from initial foothold to domain admin using common AD attack techniques.',
    category: 'ad',
    difficulty: 'advanced',
    duration: '6-8 hours',
    points: 400,
    objectives: [
      'Gain initial foothold via phishing simulation',
      'Enumerate Active Directory with BloodHound',
      'Perform Kerberoasting attack',
      'Crack service account password',
      'Move laterally using Pass-the-Hash',
      'Exploit delegation vulnerability',
      'Achieve Domain Admin access',
      'Extract NTDS.dit and capture final flag',
    ],
    tools: ['HeroForge AD Scanner', 'BloodHound', 'Mimikatz', 'Rubeus', 'CrackMapExec'],
    prerequisites: ['HCP Certification', 'Windows/AD fundamentals', 'Network Pentest lab completion'],
    completionRate: 18,
    machines: [
      { name: 'workstation01', type: 'Windows 10', ip: '10.10.20.10' },
      { name: 'workstation02', type: 'Windows 10', ip: '10.10.20.11' },
      { name: 'file-server', type: 'Windows Server', ip: '10.10.20.20' },
      { name: 'sql-server', type: 'Windows Server', ip: '10.10.20.30' },
      { name: 'dc01', type: 'Windows Server', ip: '10.10.20.100' },
    ],
  },
  {
    id: 'container-escape',
    title: 'Container Escape Challenge',
    description: 'Break out of a Docker container and compromise the host system using real-world techniques.',
    category: 'container',
    difficulty: 'advanced',
    duration: '3-4 hours',
    points: 300,
    objectives: [
      'Enumerate the container environment',
      'Identify container misconfiguration',
      'Exploit privileged container',
      'Escape to host filesystem',
      'Escalate privileges on host',
      'Access other containers via Docker socket',
      'Capture the flag from Kubernetes secret',
    ],
    tools: ['HeroForge Container Scanner', 'Docker CLI', 'kubectl'],
    prerequisites: ['Docker fundamentals', 'Linux privilege escalation knowledge'],
    completionRate: 22,
    machines: [
      { name: 'vulnerable-app', type: 'Container', ip: 'container' },
      { name: 'docker-host', type: 'Linux', ip: '10.10.30.1' },
    ],
  },
  {
    id: 'iot-hacking',
    title: 'IoT Device Exploitation',
    description: 'Hack into smart home devices and industrial IoT sensors in this hands-on IoT security lab.',
    category: 'iot',
    difficulty: 'intermediate',
    duration: '3-4 hours',
    points: 200,
    isNew: true,
    objectives: [
      'Scan for IoT devices on the network',
      'Identify default credentials on smart camera',
      'Extract firmware from IoT device',
      'Analyze firmware for hardcoded secrets',
      'Exploit MQTT broker misconfiguration',
      'Take control of industrial sensor',
    ],
    tools: ['HeroForge IoT Scanner', 'Binwalk', 'Wireshark'],
    prerequisites: ['Network fundamentals', 'Basic embedded systems knowledge'],
    completionRate: 28,
    machines: [
      { name: 'smart-camera', type: 'IoT', ip: '10.10.40.10' },
      { name: 'hvac-controller', type: 'IoT', ip: '10.10.40.20' },
      { name: 'mqtt-broker', type: 'Linux', ip: '10.10.40.1' },
    ],
  },
];

const userProgress: UserProgress[] = [
  {
    labId: 'web-basics',
    status: 'completed',
    completedObjectives: [0, 1, 2, 3, 4, 5],
    startedAt: '2026-01-10T10:00:00Z',
    completedAt: '2026-01-10T13:30:00Z',
    timeSpent: 210,
    flagsFound: ['FLAG{sql_injection_master}', 'FLAG{xss_hunter}', 'FLAG{admin_access}'],
    score: 100,
  },
  {
    labId: 'network-pentest',
    status: 'in_progress',
    completedObjectives: [0, 1, 2],
    startedAt: '2026-01-15T14:00:00Z',
    timeSpent: 180,
    flagsFound: ['FLAG{network_recon}', 'FLAG{smb_pwned}'],
    score: 100,
  },
];

const categoryIcons: Record<string, React.ReactNode> = {
  web: <Globe className="w-5 h-5" />,
  network: <Network className="w-5 h-5" />,
  cloud: <Cloud className="w-5 h-5" />,
  ad: <Server className="w-5 h-5" />,
  container: <Box className="w-5 h-5" />,
  iot: <Cpu className="w-5 h-5" />,
};

const difficultyColors: Record<string, string> = {
  beginner: 'text-green-400 bg-green-500/20',
  intermediate: 'text-amber-400 bg-amber-500/20',
  advanced: 'text-orange-400 bg-orange-500/20',
  expert: 'text-red-400 bg-red-500/20',
};

export default function AttackLabPage() {
  const [selectedLab, setSelectedLab] = useState<Lab | null>(null);
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [labRunning, setLabRunning] = useState(false);
  const [timeElapsed, setTimeElapsed] = useState(0);
  const [showHint, setShowHint] = useState(false);
  const [currentObjective, setCurrentObjective] = useState(0);
  const [flagInput, setFlagInput] = useState('');
  const [flagResult, setFlagResult] = useState<'correct' | 'incorrect' | null>(null);

  const totalPoints = userProgress.reduce((sum, p) => sum + p.score, 0);
  const completedLabs = userProgress.filter(p => p.status === 'completed').length;

  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    if (labRunning) {
      interval = setInterval(() => {
        setTimeElapsed(prev => prev + 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [labRunning]);

  const formatTime = (seconds: number) => {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hrs.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  const getProgress = (labId: string) => {
    return userProgress.find(p => p.labId === labId);
  };

  const submitFlag = () => {
    // Simulate flag verification
    if (flagInput.toLowerCase().includes('flag{')) {
      setFlagResult('correct');
      setTimeout(() => {
        setFlagResult(null);
        setFlagInput('');
        setCurrentObjective(prev => prev + 1);
      }, 2000);
    } else {
      setFlagResult('incorrect');
      setTimeout(() => setFlagResult(null), 2000);
    }
  };

  const categories = [
    { id: 'all', label: 'All Labs', count: labs.length },
    { id: 'web', label: 'Web', count: labs.filter(l => l.category === 'web').length },
    { id: 'network', label: 'Network', count: labs.filter(l => l.category === 'network').length },
    { id: 'cloud', label: 'Cloud', count: labs.filter(l => l.category === 'cloud').length },
    { id: 'ad', label: 'Active Directory', count: labs.filter(l => l.category === 'ad').length },
    { id: 'container', label: 'Container', count: labs.filter(l => l.category === 'container').length },
    { id: 'iot', label: 'IoT', count: labs.filter(l => l.category === 'iot').length },
  ];

  const filteredLabs = activeCategory === 'all' ? labs : labs.filter(l => l.category === activeCategory);

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-2">
              <Shield className="w-8 h-8 text-cyan-500" />
              <span className="text-xl font-bold text-white">HeroForge</span>
              <span className="text-gray-500 ml-2">| Attack Labs</span>
            </Link>
            <nav className="hidden md:flex items-center gap-6">
              <Link to="/academy" className="text-gray-300 hover:text-white">Academy</Link>
              <Link to="/certifications" className="text-gray-300 hover:text-white">Certifications</Link>
              <Link to="/login" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg">Sign In</Link>
            </nav>
          </div>
        </div>
      </header>

      {!selectedLab ? (
        <>
          {/* Hero Section */}
          <section className="py-12 bg-gradient-to-b from-gray-800 to-gray-900 border-b border-gray-700">
            <div className="max-w-7xl mx-auto px-4">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-red-500/20 rounded-lg">
                  <Flame className="w-6 h-6 text-red-500" />
                </div>
                <h1 className="text-3xl font-bold text-white">Attack Simulation Labs</h1>
              </div>
              <p className="text-xl text-gray-400 max-w-2xl mb-8">
                Practice real-world attack techniques in safe, isolated environments. Earn points, capture flags, and build your skills.
              </p>

              {/* Stats */}
              <div className="grid md:grid-cols-4 gap-4">
                <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                  <div className="flex items-center gap-3">
                    <Trophy className="w-8 h-8 text-amber-500" />
                    <div>
                      <p className="text-2xl font-bold text-white">{totalPoints}</p>
                      <p className="text-sm text-gray-500">Total Points</p>
                    </div>
                  </div>
                </div>
                <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                  <div className="flex items-center gap-3">
                    <CheckCircle className="w-8 h-8 text-green-500" />
                    <div>
                      <p className="text-2xl font-bold text-white">{completedLabs}</p>
                      <p className="text-sm text-gray-500">Labs Completed</p>
                    </div>
                  </div>
                </div>
                <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                  <div className="flex items-center gap-3">
                    <Flag className="w-8 h-8 text-cyan-500" />
                    <div>
                      <p className="text-2xl font-bold text-white">
                        {userProgress.reduce((sum, p) => sum + p.flagsFound.length, 0)}
                      </p>
                      <p className="text-sm text-gray-500">Flags Captured</p>
                    </div>
                  </div>
                </div>
                <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                  <div className="flex items-center gap-3">
                    <Users className="w-8 h-8 text-purple-500" />
                    <div>
                      <p className="text-2xl font-bold text-white">#42</p>
                      <p className="text-sm text-gray-500">Leaderboard Rank</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Category Filter */}
          <section className="py-6 border-b border-gray-700">
            <div className="max-w-7xl mx-auto px-4">
              <div className="flex flex-wrap gap-2">
                {categories.map((cat) => (
                  <button
                    key={cat.id}
                    onClick={() => setActiveCategory(cat.id)}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                      activeCategory === cat.id
                        ? 'bg-cyan-600 text-white'
                        : 'bg-gray-800 text-gray-400 hover:text-white'
                    }`}
                  >
                    {cat.label} ({cat.count})
                  </button>
                ))}
              </div>
            </div>
          </section>

          {/* Labs Grid */}
          <section className="py-8">
            <div className="max-w-7xl mx-auto px-4">
              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                {filteredLabs.map((lab) => {
                  const progress = getProgress(lab.id);
                  return (
                    <div
                      key={lab.id}
                      className={`bg-gray-800 rounded-xl border ${
                        lab.featured ? 'border-cyan-500/50 ring-1 ring-cyan-500/20' : 'border-gray-700'
                      } overflow-hidden hover:border-gray-600 transition-all cursor-pointer group`}
                      onClick={() => setSelectedLab(lab)}
                    >
                      {/* Header */}
                      <div className="p-4 border-b border-gray-700">
                        <div className="flex items-start justify-between mb-3">
                          <div className={`p-2 rounded-lg ${
                            lab.category === 'web' ? 'bg-blue-500/20 text-blue-400' :
                            lab.category === 'network' ? 'bg-green-500/20 text-green-400' :
                            lab.category === 'cloud' ? 'bg-purple-500/20 text-purple-400' :
                            lab.category === 'ad' ? 'bg-amber-500/20 text-amber-400' :
                            lab.category === 'container' ? 'bg-cyan-500/20 text-cyan-400' :
                            'bg-pink-500/20 text-pink-400'
                          }`}>
                            {categoryIcons[lab.category]}
                          </div>
                          <div className="flex items-center gap-2">
                            {lab.isNew && (
                              <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs font-medium">
                                NEW
                              </span>
                            )}
                            {lab.featured && (
                              <span className="px-2 py-1 bg-cyan-500/20 text-cyan-400 rounded text-xs font-medium">
                                FEATURED
                              </span>
                            )}
                          </div>
                        </div>
                        <h3 className="text-lg font-semibold text-white mb-1 group-hover:text-cyan-400 transition-colors">
                          {lab.title}
                        </h3>
                        <p className="text-sm text-gray-400 line-clamp-2">{lab.description}</p>
                      </div>

                      {/* Meta */}
                      <div className="p-4">
                        <div className="flex flex-wrap items-center gap-3 mb-4">
                          <span className={`px-2 py-1 rounded text-xs font-medium ${difficultyColors[lab.difficulty]}`}>
                            {lab.difficulty}
                          </span>
                          <span className="flex items-center gap-1 text-sm text-gray-400">
                            <Clock className="w-4 h-4" />
                            {lab.duration}
                          </span>
                          <span className="flex items-center gap-1 text-sm text-amber-400">
                            <Star className="w-4 h-4" />
                            {lab.points} pts
                          </span>
                        </div>

                        {/* Progress */}
                        {progress ? (
                          <div>
                            <div className="flex items-center justify-between text-sm mb-2">
                              <span className="text-gray-400">Progress</span>
                              <span className={
                                progress.status === 'completed' ? 'text-green-400' : 'text-cyan-400'
                              }>
                                {progress.status === 'completed' ? 'Completed' : `${progress.completedObjectives.length}/${lab.objectives.length}`}
                              </span>
                            </div>
                            <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full ${
                                  progress.status === 'completed' ? 'bg-green-500' : 'bg-cyan-500'
                                }`}
                                style={{ width: `${(progress.completedObjectives.length / lab.objectives.length) * 100}%` }}
                              />
                            </div>
                          </div>
                        ) : (
                          <div className="flex items-center justify-between">
                            <span className="text-sm text-gray-500">{lab.completionRate}% completion rate</span>
                            <ArrowRight className="w-5 h-5 text-gray-500 group-hover:text-cyan-400 transition-colors" />
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </section>

          {/* Leaderboard Teaser */}
          <section className="py-16 bg-gray-800">
            <div className="max-w-7xl mx-auto px-4">
              <div className="grid md:grid-cols-2 gap-8 items-center">
                <div>
                  <h2 className="text-3xl font-bold text-white mb-4">Compete on the Leaderboard</h2>
                  <p className="text-gray-400 mb-6">
                    Earn points by completing labs and capturing flags. Climb the global leaderboard
                    and showcase your skills to potential employers.
                  </p>
                  <ul className="space-y-3 mb-6">
                    <li className="flex items-center gap-2 text-gray-300">
                      <CheckCircle className="w-5 h-5 text-green-500" />
                      Weekly and monthly challenges
                    </li>
                    <li className="flex items-center gap-2 text-gray-300">
                      <CheckCircle className="w-5 h-5 text-green-500" />
                      Achievement badges for milestones
                    </li>
                    <li className="flex items-center gap-2 text-gray-300">
                      <CheckCircle className="w-5 h-5 text-green-500" />
                      Prizes for top performers
                    </li>
                  </ul>
                  <button className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium">
                    View Full Leaderboard
                  </button>
                </div>
                <div className="bg-gray-900 rounded-xl border border-gray-700 p-6">
                  <h3 className="text-lg font-semibold text-white mb-4">Top Players This Week</h3>
                  <div className="space-y-4">
                    {[
                      { rank: 1, name: 'SecurityNinja', points: 2450, avatar: '🥇' },
                      { rank: 2, name: 'H4ck3rM4n', points: 2280, avatar: '🥈' },
                      { rank: 3, name: 'CyberPunk2077', points: 2150, avatar: '🥉' },
                      { rank: 4, name: 'RedTeamLead', points: 1980, avatar: '4' },
                      { rank: 5, name: 'BugHunter42', points: 1850, avatar: '5' },
                    ].map((player) => (
                      <div key={player.rank} className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <span className="w-8 h-8 flex items-center justify-center bg-gray-800 rounded-full text-sm">
                            {player.avatar}
                          </span>
                          <span className="text-white font-medium">{player.name}</span>
                        </div>
                        <span className="text-amber-400 font-medium">{player.points.toLocaleString()} pts</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </section>
        </>
      ) : (
        /* Lab Detail / Running View */
        <div className="flex h-[calc(100vh-65px)]">
          {/* Sidebar */}
          <div className="w-80 bg-gray-800 border-r border-gray-700 flex flex-col">
            <div className="p-4 border-b border-gray-700">
              <button
                onClick={() => {
                  setSelectedLab(null);
                  setLabRunning(false);
                  setTimeElapsed(0);
                }}
                className="text-gray-400 hover:text-white text-sm mb-4 flex items-center gap-1"
              >
                ← Back to Labs
              </button>
              <h2 className="text-lg font-semibold text-white">{selectedLab.title}</h2>
              <div className="flex items-center gap-2 mt-2">
                <span className={`px-2 py-1 rounded text-xs font-medium ${difficultyColors[selectedLab.difficulty]}`}>
                  {selectedLab.difficulty}
                </span>
                <span className="text-amber-400 text-sm flex items-center gap-1">
                  <Star className="w-4 h-4" />
                  {selectedLab.points} pts
                </span>
              </div>
            </div>

            {/* Objectives */}
            <div className="flex-1 overflow-y-auto p-4">
              <h3 className="text-sm font-medium text-gray-400 mb-3">OBJECTIVES</h3>
              <div className="space-y-3">
                {selectedLab.objectives.map((obj, idx) => (
                  <div
                    key={idx}
                    className={`flex items-start gap-3 p-3 rounded-lg ${
                      idx < currentObjective
                        ? 'bg-green-500/20 border border-green-500/30'
                        : idx === currentObjective
                        ? 'bg-cyan-500/20 border border-cyan-500/30'
                        : 'bg-gray-700/50'
                    }`}
                  >
                    {idx < currentObjective ? (
                      <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0" />
                    ) : idx === currentObjective ? (
                      <Target className="w-5 h-5 text-cyan-400 flex-shrink-0" />
                    ) : (
                      <Lock className="w-5 h-5 text-gray-500 flex-shrink-0" />
                    )}
                    <span className={`text-sm ${
                      idx <= currentObjective ? 'text-white' : 'text-gray-500'
                    }`}>
                      {obj}
                    </span>
                  </div>
                ))}
              </div>

              {/* Machines */}
              <h3 className="text-sm font-medium text-gray-400 mt-6 mb-3">TARGET MACHINES</h3>
              <div className="space-y-2">
                {selectedLab.machines.map((machine, idx) => (
                  <div key={idx} className="flex items-center justify-between p-3 bg-gray-700/50 rounded-lg">
                    <div className="flex items-center gap-2">
                      <HardDrive className="w-4 h-4 text-gray-400" />
                      <span className="text-white text-sm">{machine.name}</span>
                    </div>
                    <span className="text-xs text-gray-500">{machine.ip || machine.type}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Controls */}
            <div className="p-4 border-t border-gray-700">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2 text-white">
                  <Timer className="w-5 h-5 text-cyan-500" />
                  <span className="font-mono text-lg">{formatTime(timeElapsed)}</span>
                </div>
                <div className="flex gap-2">
                  {!labRunning ? (
                    <button
                      onClick={() => setLabRunning(true)}
                      className="p-2 bg-green-600 hover:bg-green-700 text-white rounded-lg"
                    >
                      <Play className="w-5 h-5" />
                    </button>
                  ) : (
                    <>
                      <button
                        onClick={() => setLabRunning(false)}
                        className="p-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg"
                      >
                        <Pause className="w-5 h-5" />
                      </button>
                      <button
                        onClick={() => {
                          setLabRunning(false);
                          setTimeElapsed(0);
                          setCurrentObjective(0);
                        }}
                        className="p-2 bg-red-600 hover:bg-red-700 text-white rounded-lg"
                      >
                        <Square className="w-5 h-5" />
                      </button>
                    </>
                  )}
                </div>
              </div>

              {/* Flag Submission */}
              <div className="space-y-2">
                <label className="text-sm text-gray-400">Submit Flag</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={flagInput}
                    onChange={(e) => setFlagInput(e.target.value)}
                    placeholder="FLAG{...}"
                    className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm font-mono focus:outline-none focus:border-cyan-500"
                  />
                  <button
                    onClick={submitFlag}
                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg text-sm"
                  >
                    Submit
                  </button>
                </div>
                {flagResult && (
                  <div className={`flex items-center gap-2 text-sm ${
                    flagResult === 'correct' ? 'text-green-400' : 'text-red-400'
                  }`}>
                    {flagResult === 'correct' ? (
                      <><CheckCircle className="w-4 h-4" /> Correct! +50 points</>
                    ) : (
                      <><XCircle className="w-4 h-4" /> Incorrect flag, try again</>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Main Content - Terminal/HeroForge Interface */}
          <div className="flex-1 flex flex-col bg-gray-900">
            {/* Toolbar */}
            <div className="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700">
              <div className="flex items-center gap-4">
                <button
                  onClick={() => setShowHint(!showHint)}
                  className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-400 hover:text-white"
                >
                  <Lightbulb className="w-4 h-4" />
                  Hint
                </button>
                <button className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-400 hover:text-white">
                  <BookOpen className="w-4 h-4" />
                  Walkthrough
                </button>
                <button className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-400 hover:text-white">
                  <MessageSquare className="w-4 h-4" />
                  Discussion
                </button>
              </div>
              <button className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-400 hover:text-white">
                <Settings className="w-4 h-4" />
                Settings
              </button>
            </div>

            {/* Hint Panel */}
            {showHint && (
              <div className="mx-4 mt-4 p-4 bg-amber-500/20 border border-amber-500/50 rounded-lg">
                <div className="flex items-start gap-3">
                  <Lightbulb className="w-5 h-5 text-amber-400 flex-shrink-0" />
                  <div>
                    <h4 className="text-amber-400 font-medium mb-1">Hint for Objective {currentObjective + 1}</h4>
                    <p className="text-gray-300 text-sm">
                      Try using HeroForge's web scanner to identify potential injection points.
                      Look for input fields that might not properly sanitize user input.
                    </p>
                  </div>
                  <button onClick={() => setShowHint(false)} className="text-gray-400 hover:text-white">
                    <XCircle className="w-5 h-5" />
                  </button>
                </div>
              </div>
            )}

            {/* Embedded HeroForge Scanner / Terminal */}
            <div className="flex-1 p-4">
              <div className="h-full bg-black rounded-lg border border-gray-700 overflow-hidden">
                <div className="flex items-center gap-2 px-4 py-2 bg-gray-800 border-b border-gray-700">
                  <div className="flex gap-1.5">
                    <div className="w-3 h-3 bg-red-500 rounded-full" />
                    <div className="w-3 h-3 bg-amber-500 rounded-full" />
                    <div className="w-3 h-3 bg-green-500 rounded-full" />
                  </div>
                  <span className="text-sm text-gray-400 ml-2">HeroForge Terminal — {selectedLab.machines[0].name}</span>
                </div>
                <div className="p-4 font-mono text-sm text-green-400 h-[calc(100%-40px)] overflow-y-auto">
                  <p className="text-gray-500"># Lab environment ready</p>
                  <p className="text-gray-500"># Target: {selectedLab.machines[0].ip || selectedLab.machines[0].name}</p>
                  <p className="text-gray-500"># Type 'help' for available commands</p>
                  <p className="text-gray-500"># Use HeroForge scanner: heroforge scan {selectedLab.machines[0].ip}</p>
                  <br />
                  {labRunning ? (
                    <>
                      <p>$ heroforge scan {selectedLab.machines[0].ip} --scan-type quick</p>
                      <p className="text-cyan-400">[*] Starting quick scan on {selectedLab.machines[0].ip}</p>
                      <p className="text-cyan-400">[*] Discovering open ports...</p>
                      <p className="text-white">[+] Port 22/tcp open - SSH</p>
                      <p className="text-white">[+] Port 80/tcp open - HTTP</p>
                      <p className="text-white">[+] Port 443/tcp open - HTTPS</p>
                      <p className="text-white">[+] Port 3306/tcp open - MySQL</p>
                      <p className="text-cyan-400">[*] Detecting services...</p>
                      <p className="text-amber-400">[!] Found potential vulnerability: SQL Injection on /login.php</p>
                      <p className="text-green-400">[✓] Scan complete. 4 ports open, 1 potential vulnerability</p>
                      <br />
                      <p>$ <span className="animate-pulse">_</span></p>
                    </>
                  ) : (
                    <p>$ <span className="animate-pulse">_</span></p>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Footer (only when not in lab) */}
      {!selectedLab && (
        <footer className="bg-gray-800 border-t border-gray-700 py-8">
          <div className="max-w-7xl mx-auto px-4 text-center text-gray-400">
            <p>&copy; 2026 HeroForge. All rights reserved.</p>
          </div>
        </footer>
      )}
    </div>
  );
}
