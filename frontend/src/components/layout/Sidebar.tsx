import React, { useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useUIStore } from '../../store/uiStore';
import { useAuthStore } from '../../store/authStore';
import { useIsMobile } from '../../hooks/useMediaQuery';
import { useAuth } from '../../hooks/useAuth';
import Tooltip from '../ui/Tooltip';
import { TeamRole } from '../../types';
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
  // Category icons
  Search,
  Crosshair,
  Eye,
  Zap as ZapIcon,
  ShieldCheck,
  Users as UsersIcon,
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
  TrendingUp,
  Wifi,
  Radio,
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
  ClipboardCheck,
  BookOpenCheck,
  FileWarning,
  BarChart3,
  Package,
  GitPullRequest,
  Box,
  FileSearch,
  Map,
  GraduationCap,
  Workflow,
  Scale,
  ShieldAlert,
  Microscope,
  FlaskConical,
  Bomb,
  Radar,
  FileStack,
  Gavel,
  Monitor,
  FileCheck,
  Gift,
} from 'lucide-react';

// Types
interface NavItem {
  to: string;
  icon: React.ComponentType<{ className?: string }>;
  label: string;
}

interface NavSubsection {
  id: string;
  label: string;
  items: NavItem[];
}

interface NavSection {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  items?: NavItem[];
  subsections?: NavSubsection[];
  categoryColor: CategoryColor;
  requiredRoles?: TeamRole[];
}

type CategoryColor = 'blue' | 'cyan' | 'rose' | 'amber' | 'orange' | 'slate' | 'purple' | 'default';

// Section-to-role mapping for menu visibility (NIST/Kill Chain categories)
const SECTION_ROLES: Record<string, TeamRole[]> = {
  identify: [],    // All users
  assess: [],      // All users
  exploit: ['red_team'],
  detect: ['blue_team'],
  respond: ['blue_team', 'green_team'],
  govern: ['white_team'],
  collaborate: ['purple_team', 'red_team', 'blue_team'],
};

interface CategorySectionProps {
  section: NavSection;
  collapsed: boolean;
  expandedSections: string[];
  onToggleSection: (id: string) => void;
}

// Category color configuration (NIST/Kill Chain based)
const categoryColorStyles: Record<CategoryColor, { active: string; hover: string; border: string; dot: string; bg: string }> = {
  blue: {
    active: 'bg-blue-500/10 text-blue-600 dark:text-blue-400',
    hover: 'hover:bg-blue-500/5 hover:text-blue-600 dark:hover:text-blue-400',
    border: 'border-l-blue-500',
    dot: 'bg-blue-500',
    bg: 'bg-blue-500/5',
  },
  cyan: {
    active: 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400',
    hover: 'hover:bg-cyan-500/5 hover:text-cyan-600 dark:hover:text-cyan-400',
    border: 'border-l-cyan-500',
    dot: 'bg-cyan-500',
    bg: 'bg-cyan-500/5',
  },
  rose: {
    active: 'bg-rose-500/10 text-rose-600 dark:text-rose-400',
    hover: 'hover:bg-rose-500/5 hover:text-rose-600 dark:hover:text-rose-400',
    border: 'border-l-rose-500',
    dot: 'bg-rose-500',
    bg: 'bg-rose-500/5',
  },
  amber: {
    active: 'bg-amber-500/10 text-amber-600 dark:text-amber-400',
    hover: 'hover:bg-amber-500/5 hover:text-amber-600 dark:hover:text-amber-400',
    border: 'border-l-amber-500',
    dot: 'bg-amber-500',
    bg: 'bg-amber-500/5',
  },
  orange: {
    active: 'bg-orange-500/10 text-orange-600 dark:text-orange-400',
    hover: 'hover:bg-orange-500/5 hover:text-orange-600 dark:hover:text-orange-400',
    border: 'border-l-orange-500',
    dot: 'bg-orange-500',
    bg: 'bg-orange-500/5',
  },
  slate: {
    active: 'bg-slate-500/10 text-slate-700 dark:text-slate-300',
    hover: 'hover:bg-slate-500/5 hover:text-slate-700 dark:hover:text-slate-300',
    border: 'border-l-slate-400',
    dot: 'bg-slate-400',
    bg: 'bg-slate-500/5',
  },
  purple: {
    active: 'bg-purple-500/10 text-purple-600 dark:text-purple-400',
    hover: 'hover:bg-purple-500/5 hover:text-purple-600 dark:hover:text-purple-400',
    border: 'border-l-purple-500',
    dot: 'bg-purple-500',
    bg: 'bg-purple-500/5',
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
  categoryColor?: CategoryColor;
}> = ({ item, collapsed, categoryColor = 'default' }) => {
  const location = useLocation();
  const isActive = location.pathname === item.to ||
    (item.to !== '/dashboard' && location.pathname.startsWith(item.to)) ||
    (item.to.includes('?') && location.pathname + location.search === item.to);
  const colorStyle = categoryColorStyles[categoryColor];
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

// Subsection component for 3-level nesting
const SubsectionComponent: React.FC<{
  subsection: NavSubsection;
  categoryColor: CategoryColor;
  expanded: boolean;
  onToggle: () => void;
}> = ({ subsection, categoryColor, expanded, onToggle }) => {
  const colorStyle = categoryColorStyles[categoryColor];
  const location = useLocation();
  const hasActiveItem = subsection.items.some(
    (item) => location.pathname === item.to || location.pathname.startsWith(item.to)
  );

  return (
    <div className="mt-1">
      <button
        onClick={onToggle}
        className={`w-full flex items-center gap-2 px-2 py-1.5 rounded-md transition-colors text-xs ${
          hasActiveItem
            ? `${colorStyle.active} font-medium`
            : `text-slate-500 dark:text-slate-400 ${colorStyle.hover}`
        }`}
      >
        <span className="flex-1 text-left truncate">{subsection.label}</span>
        {expanded ? (
          <ChevronDown className="h-3 w-3 flex-shrink-0" />
        ) : (
          <ChevronRight className="h-3 w-3 flex-shrink-0" />
        )}
      </button>
      {expanded && (
        <div className="ml-2 pl-2 border-l border-slate-200 dark:border-slate-700 mt-1 space-y-0.5">
          {subsection.items.map((item) => (
            <NavItemComponent
              key={item.to}
              item={item}
              collapsed={false}
              categoryColor={categoryColor}
            />
          ))}
        </div>
      )}
    </div>
  );
};

// Category section component with 3-level nesting support
const CategorySection: React.FC<CategorySectionProps> = ({
  section,
  collapsed,
  expandedSections,
  onToggleSection,
}) => {
  const colorStyle = categoryColorStyles[section.categoryColor];
  const location = useLocation();
  const Icon = section.icon;

  // Check if any item or subsection item is active
  const hasActiveItem = [
    ...(section.items || []),
    ...(section.subsections?.flatMap((sub) => sub.items) || []),
  ].some((item) => location.pathname === item.to || location.pathname.startsWith(item.to));

  const isExpanded = expandedSections.includes(section.id);

  const header = (
    <button
      onClick={() => onToggleSection(section.id)}
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
          <span className="flex-1 text-left truncate">{section.label}</span>
          {isExpanded ? (
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
        <Tooltip content={section.label} position="right">
          {header}
        </Tooltip>
      ) : (
        header
      )}

      {isExpanded && !collapsed && (
        <div className={`ml-3 pl-3 border-l-2 ${colorStyle.border} mt-1 space-y-0.5`}>
          {/* Direct items (level 2) */}
          {section.items?.map((item) => (
            <NavItemComponent
              key={item.to}
              item={item}
              collapsed={false}
              categoryColor={section.categoryColor}
            />
          ))}

          {/* Subsections (level 3) */}
          {section.subsections?.map((subsection) => (
            <SubsectionComponent
              key={subsection.id}
              subsection={subsection}
              categoryColor={section.categoryColor}
              expanded={expandedSections.includes(`${section.id}-${subsection.id}`)}
              onToggle={() => onToggleSection(`${section.id}-${subsection.id}`)}
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
            categoryColor="purple"
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

  // Get user roles directly from state (don't call store methods in selectors)
  const userRoles = useAuthStore((state) => state.user?.roles ?? []);

  // Compute admin status from userRoles
  const isAdminUser = userRoles.includes('admin');

  // Helper to check if user has any of the specified team roles
  const hasAnyTeamRole = (teams: TeamRole[]): boolean => {
    return teams.some((team) => userRoles.includes(team));
  };

  // Close sidebar on route change (mobile)
  useEffect(() => {
    if (isMobile) {
      setSidebarOpen(false);
    }
  }, [location.pathname, isMobile, setSidebarOpen]);

  // Don't render if no user
  if (!user) return null;

  // Navigation sections organized by NIST/Kill Chain categories
  const allSections: NavSection[] = [
    // IDENTIFY - Asset discovery, inventory, attack surface
    {
      id: 'identify',
      label: 'Identify',
      icon: Search,
      categoryColor: 'blue',
      items: [
        { to: '/dashboard', icon: LayoutDashboard, label: 'Scans Dashboard' },
        { to: '/discovery', icon: Globe, label: 'Asset Discovery' },
        { to: '/assets', icon: Server, label: 'Asset Inventory' },
        { to: '/attack-surface', icon: Target, label: 'Attack Surface' },
        { to: '/dns-tools', icon: Network, label: 'DNS Tools' },
      ],
    },
    // ASSESS - Vulnerability scanning, application security
    {
      id: 'assess',
      label: 'Assess',
      icon: Microscope,
      categoryColor: 'cyan',
      subsections: [
        {
          id: 'scanning',
          label: 'Scanning',
          items: [
            { to: '/nuclei', icon: Zap, label: 'Nuclei Scanner' },
            { to: '/webapp-scan', icon: Search, label: 'Web App Scan' },
            { to: '/compare', icon: GitCompare, label: 'Scan Compare' },
          ],
        },
        {
          id: 'appsec',
          label: 'Application Security',
          items: [
            { to: '/yellow-team', icon: FileCode, label: 'DevSecOps Dashboard' },
            { to: '/sast', icon: Code, label: 'SAST Scanner' },
            { to: '/sca', icon: Package, label: 'SCA (Dependencies)' },
            { to: '/cicd-integration', icon: GitPullRequest, label: 'CI/CD Integration' },
            { to: '/iac-security', icon: FileCode, label: 'IaC Security' },
            { to: '/container-security', icon: Box, label: 'Container Security' },
            { to: '/api-security', icon: FileSearch, label: 'API Security' },
          ],
        },
      ],
    },
    // EXPLOIT - Offensive operations, exploitation (Kill Chain: Initial Access, Execution, Lateral Movement)
    {
      id: 'exploit',
      label: 'Exploit',
      icon: Crosshair,
      categoryColor: 'rose',
      requiredRoles: ['red_team'],
      subsections: [
        {
          id: 'research',
          label: 'Research',
          items: [
            { to: '/exploit-database', icon: Bug, label: 'Exploit Database' },
            { to: '/poc-repository', icon: Code, label: 'PoC Repository' },
            { to: '/research-workspaces', icon: Folder, label: 'Research Workspaces' },
            { to: '/binary-analysis', icon: Binary, label: 'Binary Analysis' },
            { to: '/malware-analysis', icon: Biohazard, label: 'Malware Analysis' },
          ],
        },
        {
          id: 'execution',
          label: 'Execution',
          items: [
            { to: '/exploitation', icon: Target, label: 'Exploitation' },
            { to: '/fuzzing', icon: Zap, label: 'Fuzzing' },
            { to: '/cracking', icon: Key, label: 'Password Cracking' },
            { to: '/privesc', icon: TrendingUp, label: 'Privilege Escalation' },
            { to: '/bloodhound', icon: GitBranch, label: 'BloodHound AD' },
          ],
        },
        {
          id: 'operations',
          label: 'Operations',
          items: [
            { to: '/phishing', icon: Target, label: 'Phishing Campaigns' },
            { to: '/c2', icon: Radio, label: 'C2 Management' },
            { to: '/wireless', icon: Wifi, label: 'Wireless Attacks' },
            { to: '/attack-simulation', icon: Crosshair, label: 'Attack Simulation' },
          ],
        },
      ],
    },
    // DETECT - Monitoring, threat hunting, detection
    {
      id: 'detect',
      label: 'Detect',
      icon: Radar,
      categoryColor: 'amber',
      requiredRoles: ['blue_team'],
      subsections: [
        {
          id: 'monitoring',
          label: 'Monitoring',
          items: [
            { to: '/siem', icon: Activity, label: 'SIEM' },
            { to: '/ueba', icon: UserCog, label: 'UEBA' },
            { to: '/traffic-analysis', icon: Network, label: 'Traffic Analysis' },
            { to: '/netflow-analysis', icon: Activity, label: 'NetFlow Analysis' },
            { to: '/dns-analytics', icon: Globe, label: 'DNS Analytics' },
          ],
        },
        {
          id: 'hunting',
          label: 'Threat Hunting',
          items: [
            { to: '/detection-engineering', icon: ScanSearch, label: 'Detection Engineering' },
            { to: '/threat-hunting', icon: Fingerprint, label: 'Threat Hunting' },
            { to: '/threat-intel', icon: ShieldAlert, label: 'Threat Intel' },
            { to: '/yara', icon: Braces, label: 'YARA Rules' },
            { to: '/sigma-rules', icon: FileCode, label: 'Sigma Rules' },
          ],
        },
        {
          id: 'specialized',
          label: 'Specialized',
          items: [
            { to: '/ot-ics-security', icon: Factory, label: 'OT/ICS Security' },
            { to: '/iot-security', icon: Lightbulb, label: 'IoT Security' },
            { to: '/agents', icon: Radio, label: 'Scan Agents' },
          ],
        },
      ],
    },
    // RESPOND - Incident response, automation
    {
      id: 'respond',
      label: 'Respond',
      icon: ZapIcon,
      categoryColor: 'orange',
      requiredRoles: ['blue_team', 'green_team'],
      subsections: [
        {
          id: 'incident',
          label: 'Incident Management',
          items: [
            { to: '/incident-response', icon: AlertCircle, label: 'Incident Response' },
            { to: '/forensics', icon: HardDrive, label: 'Forensics' },
          ],
        },
        {
          id: 'automation',
          label: 'Automation',
          items: [
            { to: '/green-team', icon: Workflow, label: 'SOAR Dashboard' },
            { to: '/soar-playbooks', icon: Play, label: 'Playbooks' },
            { to: '/workflows', icon: Workflow, label: 'Workflows' },
            { to: '/remediation', icon: Layers, label: 'Remediation' },
          ],
        },
      ],
    },
    // GOVERN - Compliance, GRC, reporting
    {
      id: 'govern',
      label: 'Govern',
      icon: Gavel,
      categoryColor: 'slate',
      requiredRoles: ['white_team'],
      subsections: [
        {
          id: 'compliance',
          label: 'Compliance',
          items: [
            { to: '/white-team', icon: ShieldCheck, label: 'GRC Dashboard' },
            { to: '/compliance', icon: ShieldCheck, label: 'Compliance' },
            { to: '/client-compliance', icon: ClipboardCheck, label: 'Client Checklists' },
            { to: '/legal/documents', icon: Gavel, label: 'Legal Documents' },
            { to: '/evidence', icon: FileStack, label: 'Evidence' },
            { to: '/manual-assessments', icon: ClipboardCheck, label: 'Assessments' },
          ],
        },
        {
          id: 'authorization',
          label: 'Authorization',
          items: [
            { to: '/ato-map', icon: Map, label: 'ATO Map' },
            { to: '/cato-network-map', icon: Network, label: 'cATO Network Map' },
            { to: '/methodology', icon: BookOpenCheck, label: 'Methodology' },
          ],
        },
        {
          id: 'reporting',
          label: 'Reporting',
          items: [
            { to: '/finding-templates', icon: FileWarning, label: 'Finding Templates' },
            { to: '/executive-dashboard', icon: BarChart3, label: 'Executive Dashboard' },
            { to: '/reports', icon: FileText, label: 'Reports' },
          ],
        },
        {
          id: 'acas',
          label: 'ACAS / RMF',
          items: [
            { to: '/scap', icon: Shield, label: 'SCAP Scanner' },
            { to: '/emass', icon: Building2, label: 'eMASS Integration' },
            { to: '/windows-audit', icon: Monitor, label: 'Windows Audit' },
            { to: '/audit-files', icon: FileCheck, label: 'Audit Files' },
          ],
        },
      ],
    },
    // COLLABORATE - Cross-functional activities
    {
      id: 'collaborate',
      label: 'Collaborate',
      icon: UsersIcon,
      categoryColor: 'purple',
      requiredRoles: ['purple_team', 'red_team', 'blue_team'],
      items: [
        { to: '/purple-team', icon: Eye, label: 'Purple Team Dashboard' },
        { to: '/orange-team', icon: GraduationCap, label: 'Security Awareness' },
      ],
    },
  ];

  const quickAccessItems: NavItem[] = [
    { to: '/crm', icon: Building2, label: 'CRM Dashboard' },
    { to: '/referrals', icon: Gift, label: 'Referral Program' },
    { to: '/admin', icon: Users, label: 'Admin' },
    { to: '/settings', icon: Settings, label: 'Settings' },
    { to: '/plugins', icon: Puzzle, label: 'Plugins' },
  ];

  // Filter sections based on user's team roles
  // Admin sees all, otherwise filter by role requirements
  const visibleSections = allSections.filter((section) => {
    // Admin sees all sections
    if (isAdminUser) return true;

    // Check if user has required role for this section
    const requiredRoles = section.requiredRoles || SECTION_ROLES[section.id];
    if (!requiredRoles || requiredRoles.length === 0) return true;

    return hasAnyTeamRole(requiredRoles);
  });

  // Filter quick access items
  const visibleQuickAccess = quickAccessItems.filter((item) => {
    // Admin link only for admins
    if (item.to === '/admin') return isAdminUser;
    // CRM available to admin or white team
    if (item.to === '/crm') return isAdminUser || hasAnyTeamRole(['white_team']);
    // Settings and plugins available to all authenticated users
    return true;
  });

  // Determine width
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

          {/* Category Sections (filtered by user's roles) */}
          <div className="space-y-1">
            {visibleSections.map((section) => (
              <CategorySection
                key={section.id}
                section={section}
                collapsed={sidebarCollapsed}
                expandedSections={expandedSections}
                onToggleSection={toggleSection}
              />
            ))}
          </div>

          {/* Divider */}
          <div className="my-4 border-t border-light-border dark:border-dark-border" />

          {/* Quick Access (filtered by user's roles) */}
          {!sidebarCollapsed && visibleQuickAccess.length > 0 && (
            <div className="mb-2 px-3">
              <span className="text-xs font-semibold text-slate-500 dark:text-slate-500 uppercase tracking-wide">
                Quick Access
              </span>
            </div>
          )}
          <div className="space-y-0.5">
            {visibleQuickAccess.map((item) => (
              <NavItemComponent
                key={item.to}
                item={item}
                collapsed={sidebarCollapsed}
                categoryColor="default"
              />
            ))}
          </div>
        </div>
      </aside>
    </>
  );
};

export default Sidebar;
