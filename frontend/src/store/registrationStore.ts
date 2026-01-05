import { create } from 'zustand';

export type RegistrationStep = 'tier' | 'email' | 'payment' | 'details' | 'complete';
export type BillingCycle = 'monthly' | 'yearly';

export interface SubscriptionTier {
  id: string;
  name: string;
  display_name: string;
  description?: string;
  monthly_price?: number;
  yearly_price?: number;
  max_users: number;
  max_scans_per_day: number;
  max_assets: number;
  features: Record<string, boolean>;
}

interface RegistrationState {
  // Current step in registration flow
  step: RegistrationStep;

  // Selected tier
  selectedTier: string | null;
  tierInfo: SubscriptionTier | null;

  // Billing info
  billingCycle: BillingCycle;

  // User email
  email: string;

  // Verification state
  verificationToken: string | null;
  verificationId: string | null;
  emailVerified: boolean;
  paymentVerified: boolean;

  // Stripe session
  stripeSessionId: string | null;
  checkoutUrl: string | null;

  // Actions
  setStep: (step: RegistrationStep) => void;
  selectTier: (tier: string, tierInfo?: SubscriptionTier) => void;
  setBillingCycle: (cycle: BillingCycle) => void;
  setEmail: (email: string) => void;
  setVerificationToken: (token: string) => void;
  setVerificationId: (id: string) => void;
  setEmailVerified: (verified: boolean) => void;
  setPaymentVerified: (verified: boolean) => void;
  setStripeSession: (sessionId: string, checkoutUrl: string) => void;
  reset: () => void;
}

const initialState = {
  step: 'tier' as RegistrationStep,
  selectedTier: null,
  tierInfo: null,
  billingCycle: 'monthly' as BillingCycle,
  email: '',
  verificationToken: null,
  verificationId: null,
  emailVerified: false,
  paymentVerified: false,
  stripeSessionId: null,
  checkoutUrl: null,
};

export const useRegistrationStore = create<RegistrationState>((set) => ({
  ...initialState,

  setStep: (step) => set({ step }),

  selectTier: (tier, tierInfo) => set({
    selectedTier: tier,
    tierInfo: tierInfo || null,
  }),

  setBillingCycle: (billingCycle) => set({ billingCycle }),

  setEmail: (email) => set({ email }),

  setVerificationToken: (token) => set({ verificationToken: token }),

  setVerificationId: (id) => set({ verificationId: id }),

  setEmailVerified: (verified) => set({ emailVerified: verified }),

  setPaymentVerified: (verified) => set({ paymentVerified: verified }),

  setStripeSession: (sessionId, checkoutUrl) => set({
    stripeSessionId: sessionId,
    checkoutUrl
  }),

  reset: () => set(initialState),
}));
