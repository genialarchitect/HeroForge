import React, { useState, useRef, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { useAuthStore } from '../../store/authStore';
import Button from '../ui/Button';
import ThemeToggle from '../ui/ThemeToggle';
import { OrgSwitcher } from '../organization';
import {
  Shield,
  LogOut,
  User,
  LayoutDashboard,
  Users,
  Settings,
  Server,
  Globe,
  Network,
  ShieldCheck,
  ClipboardCheck,
  Building2,
  BookOpenCheck,
  BarChart3,
  Zap,
  GitCompare,
  GitBranch,
  Box,
  FileCode,
  FileSearch,
  ChevronDown,
  Search,
  FileText,
  Puzzle,
  Radio,
  Activity,
  Crosshair,
  Share2,
  Target,
  Key,
  Terminal,
  Layers,
  Unlock,
  Database,
  UserCheck,
  Lock,
  ArrowRight,
  TrendingUp,
  Wifi,
  Swords,
  ShieldAlert,
  GraduationCap,
  Workflow,
  Scale,
  Eye,
  Bug,
  Radar,
  Play,
  Cpu,
  FileWarning,
  HardDrive,
  AlertCircle,
  ScanSearch,
  Fingerprint,
  Folder,
  Code,
  Binary,
  Biohazard,
  Braces,
  UserCog,
  Factory,
  Lightbulb,
  Sparkles,
  Brain,
  Package,
  GitPullRequest,
} from 'lucide-react';

interface NavItem {
  to: string;
  icon: React.ReactNode;
  label: string;
  matchPaths?: string[];
}

type TeamColor = 'red' | 'blue' | 'purple' | 'yellow' | 'orange' | 'green' | 'white' | 'cyan' | 'default';

interface DropdownMenuProps {
  label: string;
  icon: React.ReactNode;
  items: NavItem[];
  isActive: boolean;
  teamColor?: TeamColor;
}

// Team color configuration for styling
const teamColorStyles: Record<TeamColor, { active: string; hover: string; border: string; dot: string }> = {
  red: {
    active: 'bg-red-500/10 text-red-600 dark:text-red-400',
    hover: 'hover:bg-red-500/5 hover:text-red-600 dark:hover:text-red-400',
    border: 'border-l-red-500',
    dot: 'bg-red-500',
  },
  blue: {
    active: 'bg-blue-500/10 text-blue-600 dark:text-blue-400',
    hover: 'hover:bg-blue-500/5 hover:text-blue-600 dark:hover:text-blue-400',
    border: 'border-l-blue-500',
    dot: 'bg-blue-500',
  },
  purple: {
    active: 'bg-purple-500/10 text-purple-600 dark:text-purple-400',
    hover: 'hover:bg-purple-500/5 hover:text-purple-600 dark:hover:text-purple-400',
    border: 'border-l-purple-500',
    dot: 'bg-purple-500',
  },
  yellow: {
    active: 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400',
    hover: 'hover:bg-yellow-500/5 hover:text-yellow-600 dark:hover:text-yellow-400',
    border: 'border-l-yellow-500',
    dot: 'bg-yellow-500',
  },
  orange: {
    active: 'bg-orange-500/10 text-orange-600 dark:text-orange-400',
    hover: 'hover:bg-orange-500/5 hover:text-orange-600 dark:hover:text-orange-400',
    border: 'border-l-orange-500',
    dot: 'bg-orange-500',
  },
  green: {
    active: 'bg-green-500/10 text-green-600 dark:text-green-400',
    hover: 'hover:bg-green-500/5 hover:text-green-600 dark:hover:text-green-400',
    border: 'border-l-green-500',
    dot: 'bg-green-500',
  },
  white: {
    active: 'bg-slate-500/10 text-slate-700 dark:text-slate-300',
    hover: 'hover:bg-slate-500/5 hover:text-slate-700 dark:hover:text-slate-300',
    border: 'border-l-slate-400',
    dot: 'bg-slate-400',
  },
  cyan: {
    active: 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400',
    hover: 'hover:bg-cyan-500/5 hover:text-cyan-600 dark:hover:text-cyan-400',
    border: 'border-l-cyan-500',
    dot: 'bg-cyan-500',
  },
  default: {
    active: 'bg-primary/10 text-primary',
    hover: 'hover:bg-light-hover dark:hover:bg-dark-hover hover:text-slate-900 dark:hover:text-white',
    border: 'border-l-primary',
    dot: 'bg-primary',
  },
};

const DropdownMenu: React.FC<DropdownMenuProps> = ({ label, icon, items, isActive, teamColor = 'default' }) => {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const location = useLocation();
  const colorStyle = teamColorStyles[teamColor];

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const isItemActive = (item: NavItem) => {
    if (item.matchPaths) {
      return item.matchPaths.some(path => location.pathname.startsWith(path));
    }
    return location.pathname === item.to || location.pathname.startsWith(item.to);
  };

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm transition-colors ${
          isActive
            ? `${colorStyle.active} font-medium`
            : `text-slate-600 dark:text-slate-400 ${colorStyle.hover}`
        }`}
      >
        <span className={`w-2 h-2 rounded-full ${colorStyle.dot}`} />
        {icon}
        {label}
        <ChevronDown className={`h-3 w-3 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div className={`absolute left-0 mt-1 w-52 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg shadow-lg py-1 z-50 border-l-2 ${colorStyle.border}`}>
          {items.map((item) => (
            <Link
              key={item.to}
              to={item.to}
              onClick={() => setIsOpen(false)}
              className={`flex items-center gap-2 px-3 py-2 text-sm transition-colors ${
                isItemActive(item)
                  ? `${colorStyle.active} font-medium`
                  : `text-slate-600 dark:text-slate-400 ${colorStyle.hover}`
              }`}
            >
              {item.icon}
              {item.label}
            </Link>
          ))}
        </div>
      )}
    </div>
  );
};

const Header: React.FC = () => {
  const { user, logout } = useAuth();
  const isAdmin = useAuthStore((state) => state.isAdmin);
  const location = useLocation();

  // ===========================================
  // COLOR TEAM NAVIGATION ORGANIZATION
  // ===========================================

  // RED TEAM - Offensive Security / Penetration Testing
  const redTeamItems: NavItem[] = [
    { to: '/exploit-database', icon: <Bug className="h-4 w-4" />, label: 'Exploit Database' },
    { to: '/poc-repository', icon: <Code className="h-4 w-4" />, label: 'PoC Repository' },
    { to: '/research-workspaces', icon: <Folder className="h-4 w-4" />, label: 'Research Workspaces' },
    { to: '/binary-analysis', icon: <Binary className="h-4 w-4" />, label: 'Binary Analysis' },
    { to: '/malware-analysis', icon: <Biohazard className="h-4 w-4" />, label: 'Malware Analysis' },
    { to: '/fuzzing', icon: <Zap className="h-4 w-4" />, label: 'Fuzzing' },
    { to: '/exploitation', icon: <Target className="h-4 w-4" />, label: 'Exploitation' },
    { to: '/exploitation/password-spray', icon: <Key className="h-4 w-4" />, label: 'Password Spray' },
    { to: '/exploitation/kerberos', icon: <Shield className="h-4 w-4" />, label: 'Kerberoasting' },
    { to: '/exploitation/asrep-roast', icon: <Unlock className="h-4 w-4" />, label: 'AS-REP Roast' },
    { to: '/exploitation/smb-relay', icon: <Network className="h-4 w-4" />, label: 'SMB Relay' },
    { to: '/exploitation/shells', icon: <Terminal className="h-4 w-4" />, label: 'Shell Generator' },
    { to: '/exploitation/credential-dump', icon: <Database className="h-4 w-4" />, label: 'Credential Dump' },
    { to: '/cracking', icon: <Key className="h-4 w-4" />, label: 'Password Cracking' },
    { to: '/privesc', icon: <TrendingUp className="h-4 w-4" />, label: 'Privilege Escalation' },
    { to: '/bloodhound', icon: <GitBranch className="h-4 w-4" />, label: 'BloodHound AD' },
    { to: '/phishing', icon: <Target className="h-4 w-4" />, label: 'Phishing Campaigns' },
    { to: '/c2', icon: <Radio className="h-4 w-4" />, label: 'C2 Management' },
    { to: '/wireless', icon: <Wifi className="h-4 w-4" />, label: 'Wireless Attacks' },
    { to: '/attack-simulation', icon: <Crosshair className="h-4 w-4" />, label: 'Attack Simulation' },
  ];

  // BLUE TEAM - Defensive Security / Detection
  const blueTeamItems: NavItem[] = [
    { to: '/siem', icon: <Activity className="h-4 w-4" />, label: 'SIEM' },
    { to: '/ueba', icon: <UserCog className="h-4 w-4" />, label: 'UEBA' },
    { to: '/traffic-analysis', icon: <Network className="h-4 w-4" />, label: 'Traffic Analysis' },
    { to: '/netflow-analysis', icon: <Activity className="h-4 w-4" />, label: 'NetFlow Analysis' },
    { to: '/dns-analytics', icon: <Globe className="h-4 w-4" />, label: 'DNS Analytics' },
    { to: '/ot-ics-security', icon: <Factory className="h-4 w-4" />, label: 'OT/ICS Security' },
    { to: '/iot-security', icon: <Lightbulb className="h-4 w-4" />, label: 'IoT Security' },
    { to: '/yara', icon: <Braces className="h-4 w-4" />, label: 'YARA Rules' },
    { to: '/sigma-rules', icon: <FileCode className="h-4 w-4" />, label: 'Sigma Rules' },
    { to: '/forensics', icon: <HardDrive className="h-4 w-4" />, label: 'Forensics' },
    { to: '/incident-response', icon: <AlertCircle className="h-4 w-4" />, label: 'Incident Response' },
    { to: '/detection-engineering', icon: <ScanSearch className="h-4 w-4" />, label: 'Detection Engineering' },
    { to: '/threat-hunting', icon: <Fingerprint className="h-4 w-4" />, label: 'Threat Hunting' },
    { to: '/threat-intel', icon: <ShieldAlert className="h-4 w-4" />, label: 'Threat Intel' },
    { to: '/agents', icon: <Radio className="h-4 w-4" />, label: 'Scan Agents' },
    { to: '/agents/mesh', icon: <Share2 className="h-4 w-4" />, label: 'Mesh Network' },
    { to: '/attack-surface', icon: <Radar className="h-4 w-4" />, label: 'Attack Surface' },
  ];

  // PURPLE TEAM - Combined Offense/Defense Validation
  const purpleTeamItems: NavItem[] = [
    { to: '/purple-team', icon: <Eye className="h-4 w-4" />, label: 'Purple Team Dashboard' },
    { to: '/attack-paths', icon: <Network className="h-4 w-4" />, label: 'Attack Paths' },
  ];

  // YELLOW TEAM - DevSecOps / Security Architecture
  const yellowTeamItems: NavItem[] = [
    { to: '/yellow-team', icon: <FileCode className="h-4 w-4" />, label: 'DevSecOps Dashboard' },
    { to: '/sast', icon: <Code className="h-4 w-4" />, label: 'SAST Scanner' },
    { to: '/sca', icon: <Package className="h-4 w-4" />, label: 'SCA (Dependencies)' },
    { to: '/cicd-integration', icon: <GitPullRequest className="h-4 w-4" />, label: 'CI/CD Integration' },
    { to: '/iac-security', icon: <FileCode className="h-4 w-4" />, label: 'IaC Security' },
    { to: '/container-security', icon: <Box className="h-4 w-4" />, label: 'Container Security' },
    { to: '/api-security', icon: <FileSearch className="h-4 w-4" />, label: 'API Security' },
  ];

  // ORANGE TEAM - Security Awareness & Training (has internal tabs)
  const orangeTeamItems: NavItem[] = [
    { to: '/orange-team', icon: <GraduationCap className="h-4 w-4" />, label: 'Security Awareness' },
    { to: '/phishing', icon: <Target className="h-4 w-4" />, label: 'Phishing Campaigns' },
  ];

  // GREEN TEAM - SOAR / Security Automation & AI
  const greenTeamItems: NavItem[] = [
    { to: '/green-team', icon: <Workflow className="h-4 w-4" />, label: 'SOAR Dashboard' },
    { to: '/soar-playbooks', icon: <Play className="h-4 w-4" />, label: 'Playbooks' },
    { to: '/workflows', icon: <Workflow className="h-4 w-4" />, label: 'Workflows' },
    { to: '/remediation', icon: <Layers className="h-4 w-4" />, label: 'Remediation' },
    { to: '/ai-security', icon: <Brain className="h-4 w-4" />, label: 'AI Security' },
    { to: '/llm-testing', icon: <Sparkles className="h-4 w-4" />, label: 'LLM Testing' },
    { to: '/ai-reports', icon: <FileText className="h-4 w-4" />, label: 'AI Reports' },
    { to: '/ml-models', icon: <Cpu className="h-4 w-4" />, label: 'ML Models' },
  ];

  // WHITE TEAM - GRC / Governance, Risk, Compliance
  const whiteTeamItems: NavItem[] = [
    { to: '/white-team', icon: <ShieldCheck className="h-4 w-4" />, label: 'GRC Dashboard' },
    { to: '/compliance', icon: <ShieldCheck className="h-4 w-4" />, label: 'Compliance' },
    { to: '/evidence', icon: <FileText className="h-4 w-4" />, label: 'Evidence' },
    { to: '/manual-assessments', icon: <ClipboardCheck className="h-4 w-4" />, label: 'Assessments' },
    { to: '/methodology', icon: <BookOpenCheck className="h-4 w-4" />, label: 'Methodology' },
    { to: '/finding-templates', icon: <FileWarning className="h-4 w-4" />, label: 'Finding Templates' },
    { to: '/executive-dashboard', icon: <BarChart3 className="h-4 w-4" />, label: 'Executive Dashboard' },
    { to: '/reports', icon: <FileText className="h-4 w-4" />, label: 'Reports' },
  ];

  // ANALYTICS - Cross-Team Insights & Context (TODO: implement context pages)
  const analyticsItems: NavItem[] = [
    { to: '/dns-analytics', icon: <BarChart3 className="h-4 w-4" />, label: 'DNS Analytics' },
    { to: '/netflow-analysis', icon: <Activity className="h-4 w-4" />, label: 'NetFlow Analysis' },
  ];

  // CRM - Customer Relationship Management
  const crmItems: NavItem[] = [
    { to: '/crm', icon: <Building2 className="h-4 w-4" />, label: 'CRM Dashboard' },
    { to: '/crm/customers', icon: <Users className="h-4 w-4" />, label: 'Customers' },
    { to: '/crm/engagements', icon: <Target className="h-4 w-4" />, label: 'Engagements' },
    { to: '/crm/contracts', icon: <FileText className="h-4 w-4" />, label: 'Contracts' },
    { to: '/crm/time-tracking', icon: <Activity className="h-4 w-4" />, label: 'Time Tracking' },
    { to: '/sales', icon: <TrendingUp className="h-4 w-4" />, label: 'Sales' },
  ];

  // RECON - Scanning & Discovery (Cyan)
  const reconItems: NavItem[] = [
    { to: '/dashboard', icon: <LayoutDashboard className="h-4 w-4" />, label: 'Scans' },
    { to: '/discovery', icon: <Globe className="h-4 w-4" />, label: 'Asset Discovery' },
    { to: '/nuclei', icon: <Zap className="h-4 w-4" />, label: 'Nuclei Scanner' },
    { to: '/webapp-scan', icon: <Search className="h-4 w-4" />, label: 'Web App Scan' },
    { to: '/dns-tools', icon: <Network className="h-4 w-4" />, label: 'DNS Tools' },
    { to: '/compare', icon: <GitCompare className="h-4 w-4" />, label: 'Scan Compare' },
    { to: '/assets', icon: <Server className="h-4 w-4" />, label: 'Asset Inventory' },
  ];

  // SYSTEM - Settings & Administration
  const systemItems: NavItem[] = [
    { to: '/settings', icon: <Settings className="h-4 w-4" />, label: 'Settings' },
    { to: '/plugins', icon: <Puzzle className="h-4 w-4" />, label: 'Plugins' },
    ...(isAdmin() ? [{ to: '/admin', icon: <Users className="h-4 w-4" />, label: 'Admin' }] : []),
  ];

  // Check if any item in a category is active
  const isAnalyticsActive = analyticsItems.some(
    item => location.pathname === item.to || location.pathname.startsWith(item.to)
  );
  const isCrmActive = crmItems.some(
    item => location.pathname === item.to || location.pathname.startsWith(item.to)
  );
  const isReconActive = reconItems.some(
    item => location.pathname === item.to || location.pathname.startsWith(item.to)
  );
  const isRedTeamActive = redTeamItems.some(
    item => location.pathname === item.to || location.pathname.startsWith(item.to)
  );
  const isBlueTeamActive = blueTeamItems.some(
    item => location.pathname === item.to || location.pathname.startsWith(item.to)
  );
  const isPurpleTeamActive = purpleTeamItems.some(
    item => location.pathname === item.to || location.pathname.startsWith(item.to)
  );
  const isYellowTeamActive = yellowTeamItems.some(
    item => location.pathname === item.to || location.pathname.startsWith(item.to)
  );
  const isOrangeTeamActive = orangeTeamItems.some(
    item => location.pathname === item.to || location.pathname.startsWith(item.to)
  );
  const isGreenTeamActive = greenTeamItems.some(
    item => location.pathname === item.to || location.pathname.startsWith(item.to)
  );
  const isWhiteTeamActive = whiteTeamItems.some(
    item => location.pathname === item.to || location.pathname.startsWith(item.to)
  );
  const isSystemActive = systemItems.some(
    item => location.pathname === item.to || location.pathname.startsWith(item.to)
  );

  return (
    <header className="bg-light-surface dark:bg-dark-surface border-b border-light-border dark:border-dark-border shadow-lg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo and Title */}
          <div className="flex items-center space-x-6">
            <div className="flex items-center space-x-3">
              <div className="flex items-center justify-center w-10 h-10 bg-primary rounded-lg">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-slate-900 dark:text-white">HeroForge</h1>
                <p className="text-xs text-slate-500 dark:text-slate-400">Network Triage Dashboard</p>
              </div>
            </div>

            {/* Navigation - Organized by Color Teams */}
            {user && (
              <nav className="flex items-center space-x-1">
                {/* Analytics - Cross-Team Insights */}
                <DropdownMenu
                  label="Analytics"
                  icon={<BarChart3 className="h-4 w-4" />}
                  items={analyticsItems}
                  isActive={isAnalyticsActive}
                  teamColor="default"
                />

                {/* CRM - Customer Relationship Management */}
                <DropdownMenu
                  label="CRM"
                  icon={<Building2 className="h-4 w-4" />}
                  items={crmItems}
                  isActive={isCrmActive}
                  teamColor="default"
                />

                {/* Recon - Scanning & Discovery (Cyan) */}
                <DropdownMenu
                  label="Recon"
                  icon={<Search className="h-4 w-4" />}
                  items={reconItems}
                  isActive={isReconActive}
                  teamColor="cyan"
                />

                {/* Red Team - Offensive Security */}
                <DropdownMenu
                  label="Red Team"
                  icon={<Swords className="h-4 w-4" />}
                  items={redTeamItems}
                  isActive={isRedTeamActive}
                  teamColor="red"
                />

                {/* Blue Team - Defensive Security */}
                <DropdownMenu
                  label="Blue Team"
                  icon={<ShieldAlert className="h-4 w-4" />}
                  items={blueTeamItems}
                  isActive={isBlueTeamActive}
                  teamColor="blue"
                />

                {/* Purple Team - Combined Validation */}
                <DropdownMenu
                  label="Purple Team"
                  icon={<Eye className="h-4 w-4" />}
                  items={purpleTeamItems}
                  isActive={isPurpleTeamActive}
                  teamColor="purple"
                />

                {/* Yellow Team - DevSecOps */}
                <DropdownMenu
                  label="Yellow Team"
                  icon={<Cpu className="h-4 w-4" />}
                  items={yellowTeamItems}
                  isActive={isYellowTeamActive}
                  teamColor="yellow"
                />

                {/* Orange Team - Security Awareness & Training */}
                <DropdownMenu
                  label="Orange Team"
                  icon={<BookOpenCheck className="h-4 w-4" />}
                  items={orangeTeamItems}
                  isActive={isOrangeTeamActive}
                  teamColor="orange"
                />

                {/* Green Team - SOAR */}
                <DropdownMenu
                  label="Green Team"
                  icon={<Workflow className="h-4 w-4" />}
                  items={greenTeamItems}
                  isActive={isGreenTeamActive}
                  teamColor="green"
                />

                {/* White Team - GRC */}
                <DropdownMenu
                  label="White Team"
                  icon={<Scale className="h-4 w-4" />}
                  items={whiteTeamItems}
                  isActive={isWhiteTeamActive}
                  teamColor="white"
                />

                {/* System - Settings & Admin */}
                <DropdownMenu
                  label="System"
                  icon={<Settings className="h-4 w-4" />}
                  items={systemItems}
                  isActive={isSystemActive}
                  teamColor="default"
                />
              </nav>
            )}
          </div>

          {/* User Info, Theme Toggle, and Logout */}
          <div className="flex items-center space-x-4">
            {user && (
              <>
                {/* Organization Switcher */}
                <OrgSwitcher />

                <div className="flex items-center space-x-3 text-sm">
                  <div className="flex items-center space-x-2">
                    <User className="h-5 w-5 text-slate-600 dark:text-slate-400" />
                    <span className="text-slate-700 dark:text-slate-300">{user.username}</span>
                  </div>
                  {user.roles && user.roles.length > 0 && (
                    <div className="flex gap-1">
                      {user.roles.map((role) => (
                        <span
                          key={role}
                          className="inline-flex items-center px-2 py-1 text-xs font-medium rounded border bg-slate-500/20 text-slate-700 dark:text-slate-300 border-slate-500/30 capitalize"
                        >
                          {role}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </>
            )}
            <ThemeToggle />
            <Button
              variant="ghost"
              size="sm"
              onClick={logout}
              className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
            >
              <LogOut className="h-4 w-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
