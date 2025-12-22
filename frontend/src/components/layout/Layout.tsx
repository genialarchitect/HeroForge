import React from 'react';
import Header from './Header';
import { ChatWidget } from '../chat';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  return (
    <div className="min-h-screen bg-light-bg dark:bg-dark-bg transition-colors">
      <Header />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {children}
      </main>
      <ChatWidget />
    </div>
  );
};

export { Layout };
export default Layout;
