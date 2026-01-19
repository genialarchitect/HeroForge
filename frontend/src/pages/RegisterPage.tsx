import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { toast } from 'react-toastify';
import { Check, ArrowLeft, ArrowRight, Loader2, Shield, Users, Building2, Mail, Lock, User } from 'lucide-react';
import { useRegistrationStore, SubscriptionTier, BillingCycle } from '../store/registrationStore';
import { registrationAPI } from '../services/api';
import { useAuthStore } from '../store/authStore';

// Tier card component
function TierCard({
  tier,
  selected,
  billingCycle,
  onSelect,
}: {
  tier: SubscriptionTier;
  selected: boolean;
  billingCycle: BillingCycle;
  onSelect: () => void;
}) {
  const price = billingCycle === 'yearly' ? tier.yearly_price : tier.monthly_price;
  const isEnterprise = tier.name === 'enterprise';

  return (
    <button
      onClick={onSelect}
      className={`relative p-6 rounded-xl border-2 text-left transition-all duration-200 ${
        selected
          ? 'border-cyan-500 bg-cyan-500/10 ring-2 ring-cyan-500/50'
          : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'
      }`}
    >
      {tier.name === 'professional' && (
        <span className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 text-xs font-medium bg-cyan-500 text-white rounded-full">
          Most Popular
        </span>
      )}

      <div className="flex items-center gap-3 mb-4">
        {tier.name === 'solo' && <User className="h-6 w-6 text-cyan-400" />}
        {tier.name === 'professional' && <Shield className="h-6 w-6 text-cyan-400" />}
        {tier.name === 'team' && <Users className="h-6 w-6 text-cyan-400" />}
        {tier.name === 'enterprise' && <Building2 className="h-6 w-6 text-cyan-400" />}
        <h3 className="text-xl font-bold text-white">{tier.display_name}</h3>
      </div>

      <div className="mb-4">
        {isEnterprise ? (
          <p className="text-2xl font-bold text-white">Custom</p>
        ) : (
          <div className="flex items-baseline gap-1">
            <span className="text-3xl font-bold text-white">
              ${price?.toFixed(0)}
            </span>
            <span className="text-gray-400">/{billingCycle === 'yearly' ? 'year' : 'month'}</span>
          </div>
        )}
      </div>

      <p className="text-gray-400 text-sm mb-4">{tier.description}</p>

      <ul className="space-y-2 text-sm">
        <li className="flex items-center gap-2 text-gray-300">
          <Check className="h-4 w-4 text-cyan-500" />
          {tier.max_users === -1 ? 'Unlimited' : tier.max_users} user{tier.max_users !== 1 ? 's' : ''}
        </li>
        <li className="flex items-center gap-2 text-gray-300">
          <Check className="h-4 w-4 text-cyan-500" />
          {tier.max_scans_per_day === -1 ? 'Unlimited' : tier.max_scans_per_day} scans/day
        </li>
        <li className="flex items-center gap-2 text-gray-300">
          <Check className="h-4 w-4 text-cyan-500" />
          {tier.max_assets === -1 ? 'Unlimited' : tier.max_assets} assets
        </li>
        {tier.features.scheduling && (
          <li className="flex items-center gap-2 text-gray-300">
            <Check className="h-4 w-4 text-cyan-500" />
            Scheduled scans
          </li>
        )}
        {tier.features.team_management && (
          <li className="flex items-center gap-2 text-gray-300">
            <Check className="h-4 w-4 text-cyan-500" />
            Team management
          </li>
        )}
        {tier.features.crm && (
          <li className="flex items-center gap-2 text-gray-300">
            <Check className="h-4 w-4 text-cyan-500" />
            CRM & customer portals
          </li>
        )}
        {tier.features.sso && (
          <li className="flex items-center gap-2 text-gray-300">
            <Check className="h-4 w-4 text-cyan-500" />
            SSO integration
          </li>
        )}
      </ul>
    </button>
  );
}

// Step indicator
function StepIndicator({ currentStep }: { currentStep: string }) {
  const steps = [
    { key: 'tier', label: 'Select Plan' },
    { key: 'email', label: 'Your Email' },
    { key: 'payment', label: 'Payment' },
    { key: 'details', label: 'Account Details' },
  ];

  const currentIndex = steps.findIndex((s) => s.key === currentStep);

  return (
    <div className="flex items-center justify-center gap-2 mb-8">
      {steps.map((step, index) => (
        <div key={step.key} className="flex items-center">
          <div
            className={`flex items-center justify-center w-8 h-8 rounded-full text-sm font-medium ${
              index < currentIndex
                ? 'bg-cyan-500 text-white'
                : index === currentIndex
                ? 'bg-cyan-500/20 text-cyan-400 border-2 border-cyan-500'
                : 'bg-gray-700 text-gray-400'
            }`}
          >
            {index < currentIndex ? <Check className="h-4 w-4" /> : index + 1}
          </div>
          <span
            className={`hidden sm:block ml-2 text-sm ${
              index === currentIndex ? 'text-white font-medium' : 'text-gray-500'
            }`}
          >
            {step.label}
          </span>
          {index < steps.length - 1 && (
            <div
              className={`w-8 sm:w-16 h-0.5 mx-2 ${
                index < currentIndex ? 'bg-cyan-500' : 'bg-gray-700'
              }`}
            />
          )}
        </div>
      ))}
    </div>
  );
}

export default function RegisterPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { login: authLogin } = useAuthStore();

  const {
    step,
    selectedTier,
    tierInfo,
    billingCycle,
    email,
    verificationToken,
    emailVerified,
    setStep,
    selectTier,
    setBillingCycle,
    setEmail,
    setVerificationToken,
    setEmailVerified,
    reset,
  } = useRegistrationStore();

  const [tiers, setTiers] = useState<SubscriptionTier[]>([]);
  const [loading, setLoading] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [acceptTerms, setAcceptTerms] = useState(false);

  // Load tiers on mount
  useEffect(() => {
    const loadTiers = async () => {
      try {
        const response = await registrationAPI.getTiers();
        setTiers(response.data);
      } catch {
        // Use fallback tiers if API fails
        setTiers([
          {
            id: 'tier_solo',
            name: 'solo',
            display_name: 'Solo',
            description: 'Perfect for individual security professionals',
            monthly_price: 99,
            yearly_price: 990,
            max_users: 1,
            max_scans_per_day: 10,
            max_assets: 100,
            features: { scanning: true, reporting: true },
          },
          {
            id: 'tier_professional',
            name: 'professional',
            display_name: 'Professional',
            description: 'For growing security teams',
            monthly_price: 299,
            yearly_price: 2990,
            max_users: 5,
            max_scans_per_day: 50,
            max_assets: 500,
            features: { scanning: true, reporting: true, scheduling: true, team_management: true },
          },
          {
            id: 'tier_team',
            name: 'team',
            display_name: 'Team',
            description: 'For established security teams',
            monthly_price: 599,
            yearly_price: 5990,
            max_users: 15,
            max_scans_per_day: 200,
            max_assets: 2000,
            features: { scanning: true, reporting: true, scheduling: true, team_management: true, crm: true },
          },
          {
            id: 'tier_enterprise',
            name: 'enterprise',
            display_name: 'Enterprise',
            description: 'Custom solutions for large organizations',
            max_users: -1,
            max_scans_per_day: -1,
            max_assets: -1,
            features: { scanning: true, reporting: true, scheduling: true, team_management: true, crm: true, sso: true },
          },
        ]);
      }
    };

    loadTiers();

    // Check for tier from URL
    const tierParam = searchParams.get('tier');
    if (tierParam) {
      selectTier(tierParam);
    }
  }, [searchParams, selectTier]);

  // Handle tier selection
  const handleTierSelect = (tier: SubscriptionTier) => {
    if (tier.name === 'enterprise') {
      navigate('/contact-sales');
      return;
    }
    selectTier(tier.name, tier);
  };

  // Handle continue from tier selection
  const handleTierContinue = () => {
    if (!selectedTier) {
      toast.error('Please select a plan');
      return;
    }
    setStep('email');
  };

  // Handle email submission
  const handleEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !email.includes('@')) {
      toast.error('Please enter a valid email');
      return;
    }

    setLoading(true);
    try {
      // Check if email is available
      const checkResponse = await registrationAPI.checkEmail(email);
      if (!checkResponse.data.available) {
        toast.error('An account with this email already exists');
        setLoading(false);
        return;
      }

      // Initialize registration
      const response = await registrationAPI.initRegistration({
        email,
        tier: selectedTier!,
        billing_cycle: billingCycle,
      });

      if (response.data.checkout_url) {
        // Redirect to Stripe checkout
        window.location.href = response.data.checkout_url;
      } else {
        // No payment required or Stripe not configured
        toast.success('Check your email to verify your account');
        setStep('payment');
      }
    } catch (err: any) {
      toast.error(err.response?.data?.error || 'Failed to start registration');
    } finally {
      setLoading(false);
    }
  };

  // Handle registration completion
  const handleComplete = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!username || username.length < 3) {
      toast.error('Username must be at least 3 characters');
      return;
    }
    if (!password || password.length < 8) {
      toast.error('Password must be at least 8 characters');
      return;
    }
    if (password !== confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }
    if (!acceptTerms) {
      toast.error('You must accept the terms of service');
      return;
    }

    setLoading(true);
    try {
      const response = await registrationAPI.completeRegistration({
        token: verificationToken!,
        username,
        password,
        accept_terms: acceptTerms,
      });

      if (response.data.success) {
        // Store the JWT token and log in
        localStorage.setItem('heroforge_token', response.data.token);
        authLogin({ id: response.data.user_id, username, email }, response.data.token);
        toast.success('Registration complete! Welcome to HeroForge.');
        reset();
        navigate('/dashboard');
      }
    } catch (err: any) {
      toast.error(err.response?.data?.error || 'Failed to complete registration');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 flex flex-col">
      {/* Header */}
      <div className="border-b border-gray-800 bg-gray-900/80 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <button
            onClick={() => navigate('/')}
            className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="h-5 w-5" />
            Back
          </button>
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-cyan-500" />
            <span className="text-xl font-bold text-white">HeroForge</span>
          </div>
          <button
            onClick={() => navigate('/login')}
            className="text-sm text-gray-400 hover:text-white transition-colors"
          >
            Already have an account? Sign in
          </button>
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 py-12 px-4">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-white mb-2">Create Your Account</h1>
            <p className="text-gray-400">Get started with HeroForge security platform</p>
          </div>

          <StepIndicator currentStep={step} />

          {/* Step 1: Tier Selection */}
          {step === 'tier' && (
            <div className="space-y-8">
              {/* Billing toggle */}
              <div className="flex items-center justify-center gap-4">
                <button
                  onClick={() => setBillingCycle('monthly')}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    billingCycle === 'monthly'
                      ? 'bg-cyan-500 text-white'
                      : 'bg-gray-800 text-gray-400 hover:text-white'
                  }`}
                >
                  Monthly
                </button>
                <button
                  onClick={() => setBillingCycle('yearly')}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    billingCycle === 'yearly'
                      ? 'bg-cyan-500 text-white'
                      : 'bg-gray-800 text-gray-400 hover:text-white'
                  }`}
                >
                  Yearly
                  <span className="ml-1 text-xs text-cyan-300">(Save 17%)</span>
                </button>
              </div>

              {/* Tier cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {tiers.map((tier) => (
                  <TierCard
                    key={tier.id}
                    tier={tier}
                    selected={selectedTier === tier.name}
                    billingCycle={billingCycle}
                    onSelect={() => handleTierSelect(tier)}
                  />
                ))}
              </div>

              <div className="flex justify-center">
                <button
                  onClick={handleTierContinue}
                  disabled={!selectedTier}
                  className="flex items-center gap-2 px-8 py-3 bg-cyan-500 text-white font-medium rounded-lg hover:bg-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  Continue
                  <ArrowRight className="h-5 w-5" />
                </button>
              </div>
            </div>
          )}

          {/* Step 2: Email */}
          {step === 'email' && (
            <div className="max-w-md mx-auto">
              <form onSubmit={handleEmailSubmit} className="space-y-6">
                <div className="bg-gray-800/50 p-6 rounded-xl border border-gray-700">
                  <h2 className="text-xl font-bold text-white mb-4">Enter your email</h2>
                  <p className="text-gray-400 text-sm mb-6">
                    We'll send you a verification link to confirm your email address.
                  </p>

                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="you@company.com"
                      className="w-full pl-10 pr-4 py-3 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
                      required
                    />
                  </div>
                </div>

                <div className="flex items-center justify-between">
                  <button
                    type="button"
                    onClick={() => setStep('tier')}
                    className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
                  >
                    <ArrowLeft className="h-5 w-5" />
                    Back
                  </button>
                  <button
                    type="submit"
                    disabled={loading}
                    className="flex items-center gap-2 px-8 py-3 bg-cyan-500 text-white font-medium rounded-lg hover:bg-cyan-600 disabled:opacity-50 transition-colors"
                  >
                    {loading ? (
                      <Loader2 className="h-5 w-5 animate-spin" />
                    ) : (
                      <>
                        Continue to Payment
                        <ArrowRight className="h-5 w-5" />
                      </>
                    )}
                  </button>
                </div>
              </form>
            </div>
          )}

          {/* Step 3: Payment (waiting for verification) */}
          {step === 'payment' && !emailVerified && (
            <div className="max-w-md mx-auto text-center">
              <div className="bg-gray-800/50 p-8 rounded-xl border border-gray-700">
                <Mail className="h-16 w-16 text-cyan-500 mx-auto mb-4" />
                <h2 className="text-xl font-bold text-white mb-4">Check Your Email</h2>
                <p className="text-gray-400 mb-6">
                  We've sent a verification link to <span className="text-white">{email}</span>.
                  Click the link to continue with your registration.
                </p>
                <p className="text-sm text-gray-500">
                  Didn't receive the email? Check your spam folder or{' '}
                  <button
                    onClick={() => setStep('email')}
                    className="text-cyan-400 hover:text-cyan-300"
                  >
                    try a different email
                  </button>
                </p>
              </div>
            </div>
          )}

          {/* Step 4: Account Details */}
          {step === 'details' && (
            <div className="max-w-md mx-auto">
              <form onSubmit={handleComplete} className="space-y-6">
                <div className="bg-gray-800/50 p-6 rounded-xl border border-gray-700 space-y-4">
                  <h2 className="text-xl font-bold text-white mb-4">Create Your Account</h2>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Username</label>
                    <div className="relative">
                      <User className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
                      <input
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="Choose a username"
                        className="w-full pl-10 pr-4 py-3 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
                        required
                        minLength={3}
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Password</label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
                      <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Create a password"
                        className="w-full pl-10 pr-4 py-3 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
                        required
                        minLength={8}
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Confirm Password
                    </label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
                      <input
                        type="password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        placeholder="Confirm your password"
                        className="w-full pl-10 pr-4 py-3 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
                        required
                      />
                    </div>
                  </div>

                  <div className="flex items-start gap-3 pt-2">
                    <input
                      type="checkbox"
                      id="terms"
                      checked={acceptTerms}
                      onChange={(e) => setAcceptTerms(e.target.checked)}
                      className="mt-1 h-4 w-4 rounded border-gray-600 bg-gray-900 text-cyan-500 focus:ring-cyan-500"
                    />
                    <label htmlFor="terms" className="text-sm text-gray-400">
                      I agree to the{' '}
                      <a href="/legal/terms" className="text-cyan-400 hover:text-cyan-300">
                        Terms of Service
                      </a>{' '}
                      and{' '}
                      <a href="/legal/privacy" className="text-cyan-400 hover:text-cyan-300">
                        Privacy Policy
                      </a>
                    </label>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full flex items-center justify-center gap-2 px-8 py-3 bg-cyan-500 text-white font-medium rounded-lg hover:bg-cyan-600 disabled:opacity-50 transition-colors"
                >
                  {loading ? (
                    <Loader2 className="h-5 w-5 animate-spin" />
                  ) : (
                    <>
                      Create Account
                      <ArrowRight className="h-5 w-5" />
                    </>
                  )}
                </button>
              </form>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
