import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { useAuthStore } from './store/authStore';
import { portalAuthAPI } from './services/portalApi';
import { ThemeProvider, useTheme } from './contexts/ThemeContext';

// Create a client for React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      retry: 1,
    },
  },
});
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';

// Lazy load less frequently used pages
const AdminPage = lazy(() => import('./pages/AdminPage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));
const SalesPage = lazy(() => import('./pages/SalesPage'));
const AssetsPage = lazy(() => import('./pages/AssetsPage'));
const WebAppScanPage = lazy(() => import('./pages/WebAppScanPage'));
const DnsToolsPage = lazy(() => import('./pages/DnsToolsPage'));
const CompliancePage = lazy(() => import('./pages/CompliancePage'));
const RemediationPage = lazy(() => import('./pages/RemediationPage'));
const ManualAssessmentPage = lazy(() => import('./pages/ManualAssessmentPage'));
const AssessmentDetailPage = lazy(() => import('./pages/AssessmentDetailPage'));
const MethodologyPage = lazy(() => import('./pages/MethodologyPage'));
const ExecutiveDashboardPage = lazy(() => import('./pages/ExecutiveDashboardPage'));
const ApiSecurityPage = lazy(() => import('./pages/ApiSecurityPage'));
const AttackPathsPage = lazy(() => import('./pages/AttackPathsPage'));
const ScanComparisonPage = lazy(() => import('./pages/ScanComparisonPage'));
const WorkflowsPage = lazy(() => import('./pages/WorkflowsPage'));
const ContainerSecurityPage = lazy(() => import('./pages/ContainerSecurityPage'));
const IacSecurityPage = lazy(() => import('./pages/IacSecurityPage'));
const PluginsPage = lazy(() => import('./pages/PluginsPage'));
const AgentsPage = lazy(() => import('./pages/AgentsPage'));
const MeshAgentsPage = lazy(() => import('./pages/MeshAgentsPage'));
const EvidencePage = lazy(() => import('./pages/EvidencePage'));
const SiemPage = lazy(() => import('./pages/SiemPage'));
const AttackSimulationPage = lazy(() => import('./pages/AttackSimulationPage'));
const ExploitationPage = lazy(() => import('./pages/ExploitationPage'));
const NucleiPage = lazy(() => import('./pages/NucleiPage'));
const ReportsPage = lazy(() => import('./pages/ReportsPage'));
const AssetDiscoveryPage = lazy(() => import('./pages/AssetDiscoveryPage'));
const PrivescPage = lazy(() => import('./pages/PrivescPage'));
const BloodHoundPage = lazy(() => import('./pages/BloodHoundPage'));
const PhishingPage = lazy(() => import('./pages/PhishingPage'));
const C2Page = lazy(() => import('./pages/C2Page'));
const WirelessPage = lazy(() => import('./pages/WirelessPage'));
const FindingTemplatesPage = lazy(() => import('./pages/FindingTemplatesPage'));
const CrackingPage = lazy(() => import('./pages/CrackingPage'));
const AttackSurfacePage = lazy(() => import('./pages/AttackSurfacePage'));
const PurpleTeamPage = lazy(() => import('./pages/PurpleTeamPage'));
const OrangeTeamPage = lazy(() => import('./pages/OrangeTeamPage'));
const GreenTeamPage = lazy(() => import('./pages/GreenTeamPage'));
const YellowTeamPage = lazy(() => import('./pages/YellowTeamPage'));
const WhiteTeamPage = lazy(() => import('./pages/WhiteTeamPage'));
const OrganizationPage = lazy(() => import('./pages/OrganizationPage'));

// SAST Page (Yellow Team - dedicated)
const SastPage = lazy(() => import('./pages/SastPage'));

// Blue Team pages
const ForensicsPage = lazy(() => import('./pages/ForensicsPage'));
const IncidentResponsePage = lazy(() => import('./pages/IncidentResponsePage'));
const DetectionEngineeringPage = lazy(() => import('./pages/DetectionEngineeringPage'));
const ThreatHuntingPage = lazy(() => import('./pages/ThreatHuntingPage'));
const ThreatIntelPage = lazy(() => import('./pages/ThreatIntelPage'));

// Exploit Research pages
const ExploitDatabasePage = lazy(() => import('./pages/ExploitDatabasePage'));
const PocRepositoryPage = lazy(() => import('./pages/PocRepositoryPage'));
const ResearchWorkspacePage = lazy(() => import('./pages/ResearchWorkspacePage'));

// Binary Analysis
const BinaryAnalysisPage = lazy(() => import('./pages/BinaryAnalysisPage'));

// Fuzzing
const FuzzingPage = lazy(() => import('./pages/FuzzingPage'));

// Malware Analysis
const MalwareAnalysisPage = lazy(() => import('./pages/MalwareAnalysisPage'));

// YARA Rule Management
const YaraPage = lazy(() => import('./pages/YaraPage'));

// Sigma Rules (Sprint 2)
const SigmaRulesPage = lazy(() => import('./pages/SigmaRulesPage'));

// Traffic Analysis
const TrafficAnalysisPage = lazy(() => import('./pages/TrafficAnalysisPage'));

// UEBA (User Entity Behavior Analytics)
const UebaPage = lazy(() => import('./pages/UebaPage'));

// NetFlow Analysis
const NetFlowAnalysisPage = lazy(() => import('./pages/NetFlowAnalysisPage'));
const DnsAnalyticsPage = lazy(() => import('./pages/DnsAnalyticsPage'));

// OT/ICS and IoT Security (Sprint 13-14)
const OtIcsSecurityPage = lazy(() => import('./pages/OtIcsSecurityPage'));
const IotSecurityPage = lazy(() => import('./pages/IotSecurityPage'));

// SCA & CI/CD Integration (Sprint 8-10 - Priority 2)
const ScaPage = lazy(() => import('./pages/ScaPage'));
const CicdIntegrationPage = lazy(() => import('./pages/CicdIntegrationPage'));

// SOAR Playbooks (Sprint 11-12 - Priority 2)
const SoarPlaybooksPage = lazy(() => import('./pages/SoarPlaybooksPage'));

// AI/ML Security (Sprint 15 - Priority 2)
const AiSecurityPage = lazy(() => import('./pages/AiSecurityPage'));
const LlmTestingPage = lazy(() => import('./pages/LlmTestingPage'));

// CRM pages
const CrmDashboard = lazy(() => import('./pages/crm/CrmDashboard'));

// Legal pages
const TermsPage = lazy(() => import('./pages/legal/TermsPage'));
const PrivacyPage = lazy(() => import('./pages/legal/PrivacyPage'));
const AcceptableUsePage = lazy(() => import('./pages/legal/AcceptableUsePage'));
const CookiePage = lazy(() => import('./pages/legal/CookiePage'));
const CustomerList = lazy(() => import('./pages/crm/CustomerList'));
const CustomerDetail = lazy(() => import('./pages/crm/CustomerDetail'));
const EngagementsPage = lazy(() => import('./pages/crm/EngagementsPage'));
const ContractsPage = lazy(() => import('./pages/crm/ContractsPage'));
const TimeTrackingPage = lazy(() => import('./pages/crm/TimeTrackingPage'));

// Portal pages
const PortalLogin = lazy(() => import('./pages/portal/PortalLogin'));
const PortalForgotPassword = lazy(() => import('./pages/portal/PortalForgotPassword'));
const PortalResetPassword = lazy(() => import('./pages/portal/PortalResetPassword'));
const PortalDashboard = lazy(() => import('./pages/portal/PortalDashboard'));
const PortalEngagementList = lazy(() => import('./pages/portal/PortalEngagementList'));
const PortalEngagementDetail = lazy(() => import('./pages/portal/PortalEngagementDetail'));
const PortalVulnerabilityList = lazy(() => import('./pages/portal/PortalVulnerabilityList'));
const PortalVulnerabilityDetail = lazy(() => import('./pages/portal/PortalVulnerabilityDetail'));
const PortalReportList = lazy(() => import('./pages/portal/PortalReportList'));
const PortalProfile = lazy(() => import('./pages/portal/PortalProfile'));

// Loading fallback component
const PageLoader: React.FC = () => (
  <div className="min-h-screen bg-light-bg dark:bg-gray-900 flex items-center justify-center">
    <div className="flex flex-col items-center gap-4">
      <div className="w-12 h-12 border-4 border-primary border-t-transparent rounded-full animate-spin" />
      <p className="text-gray-500 dark:text-gray-400 text-sm">Loading...</p>
    </div>
  </div>
);

// Protected Route wrapper
const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  if (!isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
};

// Admin Route wrapper
const AdminRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const isAdmin = useAuthStore((state) => state.isAdmin);

  if (!isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  if (!isAdmin()) {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
};

// Portal Protected Route wrapper
const PortalProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  if (!portalAuthAPI.isAuthenticated()) {
    return <Navigate to="/portal/login" replace />;
  }

  return <>{children}</>;
};

// Toast container that respects theme
const ThemedToastContainer: React.FC = () => {
  const { resolvedTheme } = useTheme();
  return (
    <ToastContainer
      position="top-right"
      autoClose={3000}
      hideProgressBar={false}
      newestOnTop
      closeOnClick
      rtl={false}
      pauseOnFocusLoss
      draggable
      pauseOnHover
      theme={resolvedTheme}
    />
  );
};

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider defaultTheme="system">
        <BrowserRouter>
          <Suspense fallback={<PageLoader />}>
            <Routes>
          <Route path="/" element={<LoginPage />} />
          <Route path="/sales" element={<SalesPage />} />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <DashboardPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/dashboard/:scanId"
            element={
              <ProtectedRoute>
                <DashboardPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin"
            element={
              <AdminRoute>
                <AdminPage />
              </AdminRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute>
                <SettingsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/assets"
            element={
              <ProtectedRoute>
                <AssetsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/webapp-scan"
            element={
              <ProtectedRoute>
                <WebAppScanPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/dns-tools"
            element={
              <ProtectedRoute>
                <DnsToolsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/compliance"
            element={
              <ProtectedRoute>
                <CompliancePage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/evidence"
            element={
              <ProtectedRoute>
                <EvidencePage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/remediation"
            element={
              <ProtectedRoute>
                <RemediationPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/reports"
            element={
              <ProtectedRoute>
                <ReportsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/workflows"
            element={
              <ProtectedRoute>
                <WorkflowsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/manual-assessments"
            element={
              <ProtectedRoute>
                <ManualAssessmentPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/manual-assessments/:assessmentId"
            element={
              <ProtectedRoute>
                <AssessmentDetailPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/methodology"
            element={
              <ProtectedRoute>
                <MethodologyPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/methodology/:checklistId"
            element={
              <ProtectedRoute>
                <MethodologyPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/finding-templates"
            element={
              <ProtectedRoute>
                <FindingTemplatesPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/cracking"
            element={
              <ProtectedRoute>
                <CrackingPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/executive-dashboard"
            element={
              <ProtectedRoute>
                <ExecutiveDashboardPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/api-security"
            element={
              <ProtectedRoute>
                <ApiSecurityPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/attack-paths"
            element={
              <ProtectedRoute>
                <AttackPathsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/attack-paths/:scanId"
            element={
              <ProtectedRoute>
                <AttackPathsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/compare"
            element={
              <ProtectedRoute>
                <ScanComparisonPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/container-security"
            element={
              <ProtectedRoute>
                <ContainerSecurityPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/iac-security"
            element={
              <ProtectedRoute>
                <IacSecurityPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/attack-simulation"
            element={
              <ProtectedRoute>
                <AttackSimulationPage />
              </ProtectedRoute>
            }
          />
          {/* Exploitation Framework Routes */}
          <Route
            path="/exploitation"
            element={
              <ProtectedRoute>
                <ExploitationPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/exploitation/:tab"
            element={
              <ProtectedRoute>
                <ExploitationPage />
              </ProtectedRoute>
            }
          />
          {/* Nuclei Scanner Routes */}
          <Route
            path="/nuclei"
            element={
              <ProtectedRoute>
                <NucleiPage />
              </ProtectedRoute>
            }
          />
          {/* Asset Discovery Routes */}
          <Route
            path="/discovery"
            element={
              <ProtectedRoute>
                <AssetDiscoveryPage />
              </ProtectedRoute>
            }
          />
          {/* Privilege Escalation Routes */}
          <Route
            path="/privesc"
            element={
              <ProtectedRoute>
                <PrivescPage />
              </ProtectedRoute>
            }
          />
          {/* BloodHound Routes */}
          <Route
            path="/bloodhound"
            element={
              <ProtectedRoute>
                <BloodHoundPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/bloodhound/:importId"
            element={
              <ProtectedRoute>
                <BloodHoundPage />
              </ProtectedRoute>
            }
          />
          {/* Phishing Campaign Routes */}
          <Route
            path="/phishing"
            element={
              <ProtectedRoute>
                <PhishingPage />
              </ProtectedRoute>
            }
          />
          {/* C2 Framework Routes */}
          <Route
            path="/c2"
            element={
              <ProtectedRoute>
                <C2Page />
              </ProtectedRoute>
            }
          />
          {/* Wireless Security Routes */}
          <Route
            path="/wireless"
            element={
              <ProtectedRoute>
                <WirelessPage />
              </ProtectedRoute>
            }
          />
          {/* Attack Surface Management Routes */}
          <Route
            path="/attack-surface"
            element={
              <ProtectedRoute>
                <AttackSurfacePage />
              </ProtectedRoute>
            }
          />
          {/* Purple Team Routes */}
          <Route
            path="/purple-team"
            element={
              <ProtectedRoute>
                <PurpleTeamPage />
              </ProtectedRoute>
            }
          />
          {/* Orange Team Routes (Security Awareness & Training) */}
          <Route
            path="/orange-team"
            element={
              <ProtectedRoute>
                <OrangeTeamPage />
              </ProtectedRoute>
            }
          />
          {/* Green Team Routes (SOAR) */}
          <Route
            path="/green-team"
            element={
              <ProtectedRoute>
                <GreenTeamPage />
              </ProtectedRoute>
            }
          />
          {/* Yellow Team Routes (DevSecOps) */}
          <Route
            path="/yellow-team"
            element={
              <ProtectedRoute>
                <YellowTeamPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/sast"
            element={
              <ProtectedRoute>
                <SastPage />
              </ProtectedRoute>
            }
          />
          {/* White Team Routes (GRC) */}
          <Route
            path="/white-team"
            element={
              <ProtectedRoute>
                <WhiteTeamPage />
              </ProtectedRoute>
            }
          />

          {/* Blue Team Routes (Defense) */}
          <Route
            path="/forensics"
            element={
              <ProtectedRoute>
                <ForensicsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/incident-response"
            element={
              <ProtectedRoute>
                <IncidentResponsePage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/detection-engineering"
            element={
              <ProtectedRoute>
                <DetectionEngineeringPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/threat-hunting"
            element={
              <ProtectedRoute>
                <ThreatHuntingPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/threat-intel"
            element={
              <ProtectedRoute>
                <ThreatIntelPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/exploit-database"
            element={
              <ProtectedRoute>
                <ExploitDatabasePage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/poc-repository"
            element={
              <ProtectedRoute>
                <PocRepositoryPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/research-workspaces"
            element={
              <ProtectedRoute>
                <ResearchWorkspacePage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/binary-analysis"
            element={
              <ProtectedRoute>
                <BinaryAnalysisPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/fuzzing"
            element={
              <ProtectedRoute>
                <FuzzingPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/malware-analysis"
            element={
              <ProtectedRoute>
                <MalwareAnalysisPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/yara"
            element={
              <ProtectedRoute>
                <YaraPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/sigma-rules"
            element={
              <ProtectedRoute>
                <SigmaRulesPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/traffic-analysis"
            element={
              <ProtectedRoute>
                <TrafficAnalysisPage />
              </ProtectedRoute>
            }
          />
          {/* UEBA (User Entity Behavior Analytics) */}
          <Route
            path="/ueba"
            element={
              <ProtectedRoute>
                <UebaPage />
              </ProtectedRoute>
            }
          />
          {/* NetFlow Analysis */}
          <Route
            path="/netflow-analysis"
            element={
              <ProtectedRoute>
                <NetFlowAnalysisPage />
              </ProtectedRoute>
            }
          />
          {/* DNS Analytics */}
          <Route
            path="/dns-analytics"
            element={
              <ProtectedRoute>
                <DnsAnalyticsPage />
              </ProtectedRoute>
            }
          />

          {/* OT/ICS Security (Sprint 13-14) */}
          <Route
            path="/ot-ics-security"
            element={
              <ProtectedRoute>
                <OtIcsSecurityPage />
              </ProtectedRoute>
            }
          />

          {/* IoT Security (Sprint 13-14) */}
          <Route
            path="/iot-security"
            element={
              <ProtectedRoute>
                <IotSecurityPage />
              </ProtectedRoute>
            }
          />

          {/* SCA - Software Composition Analysis (Sprint 8) */}
          <Route
            path="/sca"
            element={
              <ProtectedRoute>
                <ScaPage />
              </ProtectedRoute>
            }
          />

          {/* CI/CD Integration (Sprint 9-10) */}
          <Route
            path="/cicd-integration"
            element={
              <ProtectedRoute>
                <CicdIntegrationPage />
              </ProtectedRoute>
            }
          />

          {/* SOAR Playbooks (Sprint 11-12) */}
          <Route
            path="/soar-playbooks"
            element={
              <ProtectedRoute>
                <SoarPlaybooksPage />
              </ProtectedRoute>
            }
          />

          {/* AI Security (Sprint 15) */}
          <Route
            path="/ai-security"
            element={
              <ProtectedRoute>
                <AiSecurityPage />
              </ProtectedRoute>
            }
          />

          {/* LLM Security Testing (Sprint 15) */}
          <Route
            path="/llm-testing"
            element={
              <ProtectedRoute>
                <LlmTestingPage />
              </ProtectedRoute>
            }
          />

          {/* Organization Routes */}
          <Route
            path="/organization/:id"
            element={
              <ProtectedRoute>
                <OrganizationPage />
              </ProtectedRoute>
            }
          />

          <Route
            path="/plugins"
            element={
              <ProtectedRoute>
                <PluginsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/agents"
            element={
              <ProtectedRoute>
                <AgentsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/agents/mesh"
            element={
              <ProtectedRoute>
                <MeshAgentsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/siem"
            element={
              <ProtectedRoute>
                <SiemPage />
              </ProtectedRoute>
            }
          />
          {/* CRM Routes */}
          <Route
            path="/crm"
            element={
              <ProtectedRoute>
                <CrmDashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/crm/customers"
            element={
              <ProtectedRoute>
                <CustomerList />
              </ProtectedRoute>
            }
          />
          <Route
            path="/crm/customers/:id"
            element={
              <ProtectedRoute>
                <CustomerDetail />
              </ProtectedRoute>
            }
          />
          <Route
            path="/crm/engagements"
            element={
              <ProtectedRoute>
                <EngagementsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/crm/contracts"
            element={
              <ProtectedRoute>
                <ContractsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/crm/time-tracking"
            element={
              <ProtectedRoute>
                <TimeTrackingPage />
              </ProtectedRoute>
            }
          />
          {/* Portal Routes (public) */}
          <Route path="/portal/login" element={<PortalLogin />} />
          <Route path="/portal/forgot-password" element={<PortalForgotPassword />} />
          <Route path="/portal/reset-password" element={<PortalResetPassword />} />
          {/* Portal Routes (protected) */}
          <Route
            path="/portal/dashboard"
            element={
              <PortalProtectedRoute>
                <PortalDashboard />
              </PortalProtectedRoute>
            }
          />
          <Route
            path="/portal/engagements"
            element={
              <PortalProtectedRoute>
                <PortalEngagementList />
              </PortalProtectedRoute>
            }
          />
          <Route
            path="/portal/engagements/:id"
            element={
              <PortalProtectedRoute>
                <PortalEngagementDetail />
              </PortalProtectedRoute>
            }
          />
          <Route
            path="/portal/vulnerabilities"
            element={
              <PortalProtectedRoute>
                <PortalVulnerabilityList />
              </PortalProtectedRoute>
            }
          />
          <Route
            path="/portal/vulnerabilities/:id"
            element={
              <PortalProtectedRoute>
                <PortalVulnerabilityDetail />
              </PortalProtectedRoute>
            }
          />
          <Route
            path="/portal/reports"
            element={
              <PortalProtectedRoute>
                <PortalReportList />
              </PortalProtectedRoute>
            }
          />
          <Route
            path="/portal/profile"
            element={
              <PortalProtectedRoute>
                <PortalProfile />
              </PortalProtectedRoute>
            }
          />
          {/* Legal Pages (public) */}
          <Route path="/legal/terms" element={<TermsPage />} />
          <Route path="/legal/privacy" element={<PrivacyPage />} />
          <Route path="/legal/acceptable-use" element={<AcceptableUsePage />} />
          <Route path="/legal/cookies" element={<CookiePage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense>
          <ThemedToastContainer />
        </BrowserRouter>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
