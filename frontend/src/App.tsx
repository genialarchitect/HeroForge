import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { useAuthStore } from './store/authStore';
import { portalAuthAPI } from './services/portalApi';
import { ThemeProvider, useTheme } from './contexts/ThemeContext';
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

// CRM pages
const CrmDashboard = lazy(() => import('./pages/crm/CrmDashboard'));
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
          <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense>
        <ThemedToastContainer />
      </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;
