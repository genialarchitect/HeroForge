import React from 'react';
import Header from './Header';
import Footer from './Footer';
import Sidebar from './Sidebar';
import { ChatWidget } from '../chat';
import { useAuth } from '../../hooks/useAuth';
import { useUIStore } from '../../store/uiStore';
import { useIsMobile } from '../../hooks/useMediaQuery';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const { user } = useAuth();
  const { sidebarCollapsed } = useUIStore();
  const isMobile = useIsMobile();

  // Calculate sidebar offset for desktop
  const sidebarOffset = user && !isMobile
    ? sidebarCollapsed
      ? 'lg:ml-16'
      : 'lg:ml-64'
    : '';

  return (
    <div className="min-h-screen bg-light-bg dark:bg-dark-bg transition-colors">
      {/* Sidebar (only for authenticated users) */}
      {user && <Sidebar />}

      {/* Main content area with sidebar offset */}
      <div className={`flex flex-col min-h-screen transition-all duration-300 ${sidebarOffset}`}>
        <Header />
        <main className="flex-1 px-4 sm:px-6 lg:px-8 py-6 w-full max-w-7xl mx-auto">
          {children}
        </main>
        <Footer />
      </div>

      <ChatWidget />
    </div>
  );
};

export { Layout };
export default Layout;
