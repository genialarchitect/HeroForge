import React, { useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useUIStore } from '../../store/uiStore';
import { useIsMobile } from '../../hooks/useMediaQuery';
import { useAuth } from '../../hooks/useAuth';
import Tooltip from '../ui/Tooltip';
import {
  Shield,
  PanelLeftClose,
  PanelLeftOpen,
  ChevronDown,
  ChevronRight,
  // Featured section icons
  Network,
  GitBranch,
  Brain,
  Sparkles,
  FileText,
  Cpu,
  Star,
  // Team icons
  Search,
  Swords,
  ShieldAlert,
  Eye,
  GraduationCap,
  Workflow,
  Scale,
  Settings,
  // Navigation icons
  LayoutDashboard,
  Globe,
  Zap,
  Server,
  GitCompare,
  Bug,
  Code,
  Folder,
  Binary,
  Biohazard,
  Target,
  Key,
  Terminal,
  Database,
  TrendingUp,
  Wifi,
  Radio,
  Crosshair,
  Unlock,
  Activity,
  UserCog,
  Factory,
  Lightbulb,
  Braces,
  FileCode,
  HardDrive,
  AlertCircle,
  ScanSearch,
  Fingerprint,
  Layers,
  Play,
  Building2,
  Users,
  Puzzle,
  ShieldCheck,
  ClipboardCheck,
  BookOpenCheck,
  FileWarning,
  BarChart3,
  Package,
  GitPullRequest,
  Box,
  FileSearch,
} from 'lucide-react';

// Types
interface NavItem {
  to: string;
  icon: React.ComponentType<{ className?: string }>;
  label: string;
}

type TeamColor = 'red' | 'blue' | 'purple' | 'yellow' | 'orange' | 'green' | 'white' | 'cyan' | 'default';

interface TeamSectionProps {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  items: NavItem[];
  teamColor: TeamColor;
  collapsed: boolean;
  expanded: boolean;
  onToggle: () => void;
}

// Team color configuration
const teamColorStyles: Record<TeamColor, { active: string; hover: string; border: string; dot: string; bg: string }> = {
  red: {
    active: 'bg-red-500/10 text-red-600 dark:text-red-400',
    hover: 'hover:bg-red-500/5 hover:text-red-600 dark:hover:text-red-400',
    border: 'border-l-red-500',
    dot: 'bg-red-500',
    bg: 'bg-red-500/5',
  },
  blue: {
    active: 'bg-blue-500/10 text-blue-600 dark:text-blue-400',
    hover: 'hover:bg-blue-500/5 hover:text-blue-600 dark:hover:text-blue-400',
    border: 'border-l-blue-500',
    dot: 'bg-blue-500',
    bg: 'bg-blue-500/5',
  },
  purple: {
    active: 'bg-purple-500/10 text-purple-600 dark:text-purple-400',
    hover: 'hover:bg-purple-500/5 hover:text-purple-600 dark:hover:text-purple-400',
    border: 'border-l-purple-500',
    dot: 'bg-purple-500',
    bg: 'bg-purple-500/5',
  },
  yellow: {
    active: 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400',
    hover: 'hover:bg-yellow-500/5 hover:text-yellow-600 dark:hover:text-yellow-400',
    border: 'border-l-yellow-500',
    dot: 'bg-yellow-500',
    bg: 'bg-yellow-500/5',
  },
  orange: {
    active: 'bg-orange-500/10 text-orange-600 dark:text-orange-400',
    hover: 'hover:bg-orange-500/5 hover:text-orange-600 dark:hover:text-orange-400',
    border: 'border-l-orange-500',
    dot: 'bg-orange-500',
    bg: 'bg-orange-500/5',
  },
  green: {
    active: 'bg-green-500/10 text-green-600 dark:text-green-400',
    hover: 'hover:bg-green-500/5 hover:text-green-600 dark:hover:text-green-400',
    border: 'border-l-green-500',
    dot: 'bg-green-500',
    bg: 'bg-green-500/5',
  },
  white: {
    active: 'bg-slate-500/10 text-slate-700 dark:text-slate-300',
    hover: 'hover:bg-slate-500/5 hover:text-slate-700 dark:hover:text-slate-300',
    border: 'border-l-slate-400',
    dot: 'bg-slate-400',
    bg: 'bg-slate-500/5',
  },
  cyan: {
    active: 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400',
    hover: 'hover:bg-cyan-500/5 hover:text-cyan-600 dark:hover:text-cyan-400',
    border: 'border-l-cyan-500',
    dot: 'bg-cyan-500',
    bg: 'bg-cyan-500/5',
  },
  default: {
    active: 'bg-primary/10 text-primary',
    hover: 'hover:bg-light-hover dark:hover:bg-dark-hover hover:text-slate-900 dark:hover:text-white',
    border: 'border-l-primary',
    dot: 'bg-primary',
    bg: 'bg-primary/5',
  },
};

// Navigation item component
const NavItemComponent: React.FC<{
  item: NavItem;
  collapsed: boolean;
  teamColor?: TeamColor;
}> = ({ item, collapsed, teamColor = 'default' }) => {
  const location = useLocation();
  const isActive = location.pathname === item.to ||
    (item.to !== '/dashboard' && location.pathname.startsWith(item.to)) ||
    (item.to.includes('?') && location.pathname + location.search === item.to);
  const colorStyle = teamColorStyles[teamColor];
  const Icon = item.icon;

  const content = (
    <Link
      to={item.to}
      className={`flex items-center gap-3 px-3 py-2 rounded-lg transition-colors text-sm ${
        isActive
          ? `${colorStyle.active} font-medium`
          : `text-slate-600 dark:text-slate-400 ${colorStyle.hover}`
      }`}
    >
      <Icon className="h-4 w-4 flex-shrink-0" />
      {!collapsed && <span className="truncate">{item.label}</span>}
    </Link>
  );

  if (collapsed) {
    return (
      <Tooltip content={item.label} position="right">
        {content}
      </Tooltip>
    );
  }

  return content;
};

// Team section component
const TeamSection: React.FC<TeamSectionProps> = ({
  id,
  label,
  icon: Icon,
  items,
  teamColor,
  collapsed,
  expanded,
  onToggle,
}) => {
  const colorStyle = teamColorStyles[teamColor];
  const location = useLocation();
  const hasActiveItem = items.some(
    (item) => location.pathname === item.to || location.pathname.startsWith(item.to)
  );

  const header = (
    <button
      onClick={onToggle}
      className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg transition-colors text-sm ${
        hasActiveItem
          ? `${colorStyle.active} font-medium`
          : `text-slate-600 dark:text-slate-400 ${colorStyle.hover}`
      }`}
    >
      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${colorStyle.dot}`} />
      {!collapsed && (
        <>
          <Icon className="h-4 w-4 flex-shrink-0" />
          <span className="flex-1 text-left truncate">{label}</span>
          {expanded ? (
            <ChevronDown className="h-3 w-3 flex-shrink-0" />
          ) : (
            <ChevronRight className="h-3 w-3 flex-shrink-0" />
          )}
        </>
      )}
    </button>
  );

  return (
    <div className="mb-1">
      {collapsed ? (
        <Tooltip content={label} position="right">
          {header}
        </Tooltip>
      ) : (
        header
      )}

      {expanded && !collapsed && (
        <div className={`ml-3 pl-3 border-l-2 ${colorStyle.border} mt-1 space-y-0.5`}>
          {items.map((item) => (
            <NavItemComponent
              key={item.to}
              item={item}
              collapsed={false}
              teamColor={teamColor}
            />
          ))}
        </div>
      )}
    </div>
  );
};

// Featured section component
const FeaturedSection: React.FC<{ collapsed: boolean }> = ({ collapsed }) => {
  const featuredItems: NavItem[] = [
    { to: '/dashboard?tab=topology', icon: Network, label: 'Network Topology' },
    { to: '/attack-paths', icon: GitBranch, label: 'Attack Paths' },
    { to: '/ai-security', icon: Brain, label: 'AI Security' },
    { to: '/llm-testing', icon: Sparkles, label: 'LLM Testing' },
    { to: '/ai-reports', icon: FileText, label: 'AI Reports' },
    { to: '/ml-models', icon: Cpu, label: 'ML Models' },
  ];

  return (
    <div
      className={`mb-4 rounded-lg bg-gradient-to-br from-purple-500/10 via-cyan-500/10 to-blue-500/10 border border-purple-500/20 ${
        collapsed ? 'p-2' : 'p-3'
      }`}
    >
      {!collapsed && (
        <div className="flex items-center gap-2 mb-2 px-1">
          <Star className="h-4 w-4 text-yellow-500" />
          <span className="text-xs font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wide">
            AI & Visualization
          </span>
        </div>
      )}
      <div className="space-y-0.5">
        {featuredItems.map((item) => (
          <NavItemComponent
            key={item.to}
            item={item}
            collapsed={collapsed}
            teamColor="purple"
          />
        ))}
      </div>
    </div>
  );
};

// Main Sidebar component
const Sidebar: React.FC = () => {
  const { user } = useAuth();
  const location = useLocation();
  const isMobile = useIsMobile();
  const {
    sidebarCollapsed,
    sidebarOpen,
    expandedSections,
    toggleSidebar,
    setSidebarOpen,
    toggleSection,
  } = useUIStore();

  // Close sidebar on route change (mobile)
  useEffect(() => {
    if (isMobile) {
      setSidebarOpen(false);
    }
  }, [location.pathname, isMobile, setSidebarOpen]);

  // Don't render if no user
  if (!user) return null;

  // Navigation items organized by team
  const reconItems: NavItem[] = [
    { to: '/dashboard', icon: LayoutDashboard, label: 'Scans' },
    { to: '/discovery', icon: Globe, label: 'Asset Discovery' },
    { to: '/nuclei', icon: Zap, label: 'Nuclei Scanner' },
    { to: '/webapp-scan', icon: Search, label: 'Web App Scan' },
    { to: '/dns-tools', icon: Network, label: 'DNS Tools' },
    { to: '/compare', icon: GitCompare, label: 'Scan Compare' },
    { to: '/assets', icon: Server, label: 'Asset Inventory' },
  ];

  const redTeamItems: NavItem[] = [
    { to: '/exploit-database', icon: Bug, label: 'Exploit Database' },
    { to: '/poc-repository', icon: Code, label: 'PoC Repository' },
    { to: '/research-workspaces', icon: Folder, label: 'Research Workspaces' },
    { to: '/binary-analysis', icon: Binary, label: 'Binary Analysis' },
    { to: '/malware-analysis', icon: Biohazard, label: 'Malware Analysis' },
    { to: '/fuzzing', icon: Zap, label: 'Fuzzing' },
    { to: '/exploitation', icon: Target, label: 'Exploitation' },
    { to: '/cracking', icon: Key, label: 'Password Cracking' },
    { to: '/privesc', icon: TrendingUp, label: 'Privilege Escalation' },
    { to: '/bloodhound', icon: GitBranch, label: 'BloodHound AD' },
    { to: '/phishing', icon: Target, label: 'Phishing Campaigns' },
    { to: '/c2', icon: Radio, label: 'C2 Management' },
    { to: '/wireless', icon: Wifi, label: 'Wireless Attacks' },
    { to: '/attack-simulation', icon: Crosshair, label: 'Attack Simulation' },
  ];

  const blueTeamItems: NavItem[] = [
    { to: '/siem', icon: Activity, label: 'SIEM' },
    { to: '/ueba', icon: UserCog, label: 'UEBA' },
    { to: '/traffic-analysis', icon: Network, label: 'Traffic Analysis' },
    { to: '/netflow-analysis', icon: Activity, label: 'NetFlow Analysis' },
    { to: '/dns-analytics', icon: Globe, label: 'DNS Analytics' },
    { to: '/ot-ics-security', icon: Factory, label: 'OT/ICS Security' },
    { to: '/iot-security', icon: Lightbulb, label: 'IoT Security' },
    { to: '/yara', icon: Braces, label: 'YARA Rules' },
    { to: '/sigma-rules', icon: FileCode, label: 'Sigma Rules' },
    { to: '/forensics', icon: HardDrive, label: 'Forensics' },
    { to: '/incident-response', icon: AlertCircle, label: 'Incident Response' },
    { to: '/detection-engineering', icon: ScanSearch, label: 'Detection Engineering' },
    { to: '/threat-hunting', icon: Fingerprint, label: 'Threat Hunting' },
    { to: '/threat-intel', icon: ShieldAlert, label: 'Threat Intel' },
    { to: '/agents', icon: Radio, label: 'Scan Agents' },
    { to: '/attack-surface', icon: Target, label: 'Attack Surface' },
  ];

  const purpleTeamItems: NavItem[] = [
    { to: '/purple-team', icon: Eye, label: 'Purple Team Dashboard' },
  ];

  const yellowTeamItems: NavItem[] = [
    { to: '/yellow-team', icon: FileCode, label: 'DevSecOps Dashboard' },
    { to: '/sast', icon: Code, label: 'SAST Scanner' },
    { to: '/sca', icon: Package, label: 'SCA (Dependencies)' },
    { to: '/cicd-integration', icon: GitPullRequest, label: 'CI/CD Integration' },
    { to: '/iac-security', icon: FileCode, label: 'IaC Security' },
    { to: '/container-security', icon: Box, label: 'Container Security' },
    { to: '/api-security', icon: FileSearch, label: 'API Security' },
  ];

  const orangeTeamItems: NavItem[] = [
    { to: '/orange-team', icon: GraduationCap, label: 'Security Awareness' },
  ];

  const greenTeamItems: NavItem[] = [
    { to: '/green-team', icon: Workflow, label: 'SOAR Dashboard' },
    { to: '/soar-playbooks', icon: Play, label: 'Playbooks' },
    { to: '/workflows', icon: Workflow, label: 'Workflows' },
    { to: '/remediation', icon: Layers, label: 'Remediation' },
  ];

  const whiteTeamItems: NavItem[] = [
    { to: '/white-team', icon: ShieldCheck, label: 'GRC Dashboard' },
    { to: '/compliance', icon: ShieldCheck, label: 'Compliance' },
    { to: '/evidence', icon: FileText, label: 'Evidence' },
    { to: '/manual-assessments', icon: ClipboardCheck, label: 'Assessments' },
    { to: '/methodology', icon: BookOpenCheck, label: 'Methodology' },
    { to: '/finding-templates', icon: FileWarning, label: 'Finding Templates' },
    { to: '/executive-dashboard', icon: BarChart3, label: 'Executive Dashboard' },
    { to: '/reports', icon: FileText, label: 'Reports' },
  ];

  const quickAccessItems: NavItem[] = [
    { to: '/crm', icon: Building2, label: 'CRM Dashboard' },
    { to: '/admin', icon: Users, label: 'Admin' },
    { to: '/settings', icon: Settings, label: 'Settings' },
    { to: '/plugins', icon: Puzzle, label: 'Plugins' },
  ];

  const teams = [
    { id: 'recon', label: 'Recon', icon: Search, items: reconItems, teamColor: 'cyan' as TeamColor },
    { id: 'red', label: 'Red Team', icon: Swords, items: redTeamItems, teamColor: 'red' as TeamColor },
    { id: 'blue', label: 'Blue Team', icon: ShieldAlert, items: blueTeamItems, teamColor: 'blue' as TeamColor },
    { id: 'purple', label: 'Purple Team', icon: Eye, items: purpleTeamItems, teamColor: 'purple' as TeamColor },
    { id: 'yellow', label: 'Yellow Team', icon: Cpu, items: yellowTeamItems, teamColor: 'yellow' as TeamColor },
    { id: 'orange', label: 'Orange Team', icon: GraduationCap, items: orangeTeamItems, teamColor: 'orange' as TeamColor },
    { id: 'green', label: 'Green Team', icon: Workflow, items: greenTeamItems, teamColor: 'green' as TeamColor },
    { id: 'white', label: 'White Team', icon: Scale, items: whiteTeamItems, teamColor: 'white' as TeamColor },
  ];

  // Determine visibility and width
  const isVisible = isMobile ? sidebarOpen : true;
  const sidebarWidth = sidebarCollapsed ? 'w-16' : 'w-64';

  return (
    <>
      {/* Mobile backdrop */}
      {isMobile && sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 transition-opacity"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`
          fixed top-0 left-0 h-full z-50
          bg-light-surface dark:bg-dark-surface
          border-r border-light-border dark:border-dark-border
          transition-all duration-300 ease-in-out
          flex flex-col
          ${isMobile ? `w-64 ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}` : sidebarWidth}
        `}
        role="navigation"
        aria-label="Main navigation"
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-light-border dark:border-dark-border">
          {!sidebarCollapsed && (
            <div className="flex items-center gap-3">
              <div className="flex items-center justify-center w-8 h-8 bg-primary rounded-lg">
                <Shield className="h-5 w-5 text-white" />
              </div>
              <span className="font-bold text-slate-900 dark:text-white">HeroForge</span>
            </div>
          )}
          {sidebarCollapsed && (
            <div className="flex items-center justify-center w-8 h-8 bg-primary rounded-lg mx-auto">
              <Shield className="h-5 w-5 text-white" />
            </div>
          )}
          {!isMobile && (
            <button
              onClick={toggleSidebar}
              className={`p-1.5 rounded-lg hover:bg-light-hover dark:hover:bg-dark-hover transition-colors ${
                sidebarCollapsed ? 'mx-auto mt-2' : ''
              }`}
              aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            >
              {sidebarCollapsed ? (
                <PanelLeftOpen className="h-4 w-4 text-slate-600 dark:text-slate-400" />
              ) : (
                <PanelLeftClose className="h-4 w-4 text-slate-600 dark:text-slate-400" />
              )}
            </button>
          )}
        </div>

        {/* Scrollable content */}
        <div className="flex-1 overflow-y-auto p-3">
          {/* Featured Section */}
          <FeaturedSection collapsed={sidebarCollapsed} />

          {/* Team Sections */}
          <div className="space-y-1">
            {teams.map((team) => (
              <TeamSection
                key={team.id}
                id={team.id}
                label={team.label}
                icon={team.icon}
                items={team.items}
                teamColor={team.teamColor}
                collapsed={sidebarCollapsed}
                expanded={expandedSections.includes(team.id)}
                onToggle={() => toggleSection(team.id)}
              />
            ))}
          </div>

          {/* Divider */}
          <div className="my-4 border-t border-light-border dark:border-dark-border" />

          {/* Quick Access */}
          {!sidebarCollapsed && (
            <div className="mb-2 px-3">
              <span className="text-xs font-semibold text-slate-500 dark:text-slate-500 uppercase tracking-wide">
                Quick Access
              </span>
            </div>
          )}
          <div className="space-y-0.5">
            {quickAccessItems.map((item) => (
              <NavItemComponent
                key={item.to}
                item={item}
                collapsed={sidebarCollapsed}
                teamColor="default"
              />
            ))}
          </div>
        </div>
      </aside>
    </>
  );
};

export default Sidebar;
