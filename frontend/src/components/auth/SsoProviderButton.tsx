import React from 'react';
import { SsoProviderForLogin, SsoProviderType } from '../../types';

interface SsoProviderButtonProps {
  provider: SsoProviderForLogin;
  onClick: (provider: SsoProviderForLogin) => void;
  loading?: boolean;
  disabled?: boolean;
}

// Provider icons - using inline SVG for common providers
const ProviderIcons: Record<string, React.ReactNode> = {
  okta: (
    <svg viewBox="0 0 24 24" className="w-5 h-5" fill="currentColor">
      <path d="M12 0C5.389 0 0 5.389 0 12s5.389 12 12 12 12-5.389 12-12S18.611 0 12 0zm0 18c-3.314 0-6-2.686-6-6s2.686-6 6-6 6 2.686 6 6-2.686 6-6 6z"/>
    </svg>
  ),
  azure_ad: (
    <svg viewBox="0 0 24 24" className="w-5 h-5" fill="currentColor">
      <path d="M0 0h11.377v11.372H0V0zm12.623 0H24v11.372H12.623V0zM0 12.623h11.377V24H0V12.623zm12.623 0H24V24H12.623V12.623z"/>
    </svg>
  ),
  google: (
    <svg viewBox="0 0 24 24" className="w-5 h-5">
      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
      <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
    </svg>
  ),
  onelogin: (
    <svg viewBox="0 0 24 24" className="w-5 h-5" fill="currentColor">
      <circle cx="12" cy="12" r="10"/>
    </svg>
  ),
  ping: (
    <svg viewBox="0 0 24 24" className="w-5 h-5" fill="currentColor">
      <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
    </svg>
  ),
  auth0: (
    <svg viewBox="0 0 24 24" className="w-5 h-5" fill="currentColor">
      <path d="M21.98 7.448L19.62 0H4.347L2.02 7.448c-1.352 4.312.03 9.206 3.815 12.015L12.007 24l6.157-4.552c3.755-2.81 5.182-7.688 3.815-12.015l-6.16 4.58 2.343 7.45-6.157-4.597-6.158 4.58 2.358-7.433-6.188-4.55 7.63-.045L12.008 0l2.356 7.404 7.615.044z"/>
    </svg>
  ),
  keycloak: (
    <svg viewBox="0 0 24 24" className="w-5 h-5" fill="currentColor">
      <path d="M12 0L3 4.5v15L12 24l9-4.5v-15L12 0zm0 3.75l6 3v10.5l-6 3-6-3V6.75l6-3z"/>
    </svg>
  ),
  jumpcloud: (
    <svg viewBox="0 0 24 24" className="w-5 h-5" fill="currentColor">
      <path d="M12 2a10 10 0 100 20 10 10 0 000-20zm0 5a5 5 0 110 10 5 5 0 010-10z"/>
    </svg>
  ),
};

// Get the appropriate icon for a provider
const getProviderIcon = (provider: SsoProviderForLogin): React.ReactNode => {
  // Check for custom icon first
  if (provider.icon) {
    // If it's a URL, render an image
    if (provider.icon.startsWith('http') || provider.icon.startsWith('/')) {
      return <img src={provider.icon} alt={provider.display_name} className="w-5 h-5 object-contain" />;
    }
    // If it matches a known icon key
    if (ProviderIcons[provider.icon]) {
      return ProviderIcons[provider.icon];
    }
  }

  // Map provider type to icon
  const typeToIcon: Partial<Record<SsoProviderType, string>> = {
    okta: 'okta',
    azure_ad: 'azure_ad',
    google: 'google',
    onelogin: 'onelogin',
    ping: 'ping',
    auth0: 'auth0',
    keycloak: 'keycloak',
    jumpcloud: 'jumpcloud',
  };

  const iconKey = typeToIcon[provider.provider_type];
  if (iconKey && ProviderIcons[iconKey]) {
    return ProviderIcons[iconKey];
  }

  // Default SSO icon
  return (
    <svg viewBox="0 0 24 24" className="w-5 h-5" fill="currentColor">
      <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
    </svg>
  );
};

// Get provider-specific button colors
const getProviderColors = (providerType: SsoProviderType): string => {
  switch (providerType) {
    case 'okta':
      return 'bg-[#007dc1] hover:bg-[#006ba1] text-white';
    case 'azure_ad':
      return 'bg-[#0078d4] hover:bg-[#006cbe] text-white';
    case 'google':
      return 'bg-white hover:bg-gray-50 text-gray-700 border border-gray-300 dark:bg-gray-800 dark:hover:bg-gray-700 dark:text-gray-200 dark:border-gray-600';
    case 'onelogin':
      return 'bg-[#2c3e50] hover:bg-[#1a252f] text-white';
    case 'ping':
      return 'bg-[#00843d] hover:bg-[#006b31] text-white';
    case 'auth0':
      return 'bg-[#eb5424] hover:bg-[#d94c1f] text-white';
    case 'keycloak':
      return 'bg-[#4d4d4d] hover:bg-[#3d3d3d] text-white';
    case 'jumpcloud':
      return 'bg-[#1e90ff] hover:bg-[#1a7dd9] text-white';
    case 'saml':
      return 'bg-indigo-600 hover:bg-indigo-700 text-white';
    case 'oidc':
      return 'bg-purple-600 hover:bg-purple-700 text-white';
    default:
      return 'bg-gray-600 hover:bg-gray-700 text-white';
  }
};

const SsoProviderButton: React.FC<SsoProviderButtonProps> = ({
  provider,
  onClick,
  loading = false,
  disabled = false,
}) => {
  const handleClick = () => {
    if (!loading && !disabled) {
      onClick(provider);
    }
  };

  return (
    <button
      type="button"
      onClick={handleClick}
      disabled={loading || disabled}
      className={`
        w-full flex items-center justify-center gap-3 px-4 py-3 rounded-lg
        font-medium transition-all duration-200
        ${getProviderColors(provider.provider_type)}
        ${loading || disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
        focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary
        dark:focus:ring-offset-dark-bg
      `}
    >
      {loading ? (
        <svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
      ) : (
        getProviderIcon(provider)
      )}
      <span>
        {loading ? 'Redirecting...' : `Continue with ${provider.display_name}`}
      </span>
    </button>
  );
};

export default SsoProviderButton;
