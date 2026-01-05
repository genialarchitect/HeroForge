import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { toast } from 'react-toastify';
import { CheckCircle, XCircle, Loader2, Shield, Mail, ArrowRight, AlertCircle } from 'lucide-react';
import { registrationAPI } from '../services/api';
import { useRegistrationStore } from '../store/registrationStore';

export default function VerifyEmailPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { setVerificationToken, setEmailVerified, setStep } = useRegistrationStore();

  const [status, setStatus] = useState<'loading' | 'success' | 'error' | 'payment_required'>('loading');
  const [email, setEmail] = useState('');
  const [tier, setTier] = useState('');
  const [message, setMessage] = useState('');

  useEffect(() => {
    const verifyToken = async () => {
      const token = searchParams.get('token');

      if (!token) {
        setStatus('error');
        setMessage('Missing verification token');
        return;
      }

      try {
        const response = await registrationAPI.verifyEmail(token);
        const { verified, email: verifiedEmail, tier: tierName, payment_required, payment_verified } = response.data;

        setEmail(verifiedEmail);
        setTier(tierName);

        if (verified) {
          setVerificationToken(token);
          setEmailVerified(true);

          if (payment_required && !payment_verified) {
            setStatus('payment_required');
            setMessage('Your email is verified! Please complete payment to continue.');
          } else {
            setStatus('success');
            setMessage('Your email has been verified! You can now complete your account setup.');
            // Move to details step
            setStep('details');
          }
        } else {
          setStatus('error');
          setMessage('Verification failed. Please try again.');
        }
      } catch (err: any) {
        setStatus('error');
        setMessage(err.response?.data?.error || 'Failed to verify email. The link may have expired.');
      }
    };

    verifyToken();
  }, [searchParams, setVerificationToken, setEmailVerified, setStep]);

  const handleContinue = () => {
    navigate('/register');
  };

  return (
    <div className="min-h-screen bg-gray-900 flex flex-col items-center justify-center px-4">
      {/* Logo */}
      <div className="flex items-center gap-2 mb-8">
        <Shield className="h-10 w-10 text-cyan-500" />
        <span className="text-2xl font-bold text-white">HeroForge</span>
      </div>

      <div className="w-full max-w-md">
        <div className="bg-gray-800/50 rounded-xl border border-gray-700 p-8 text-center">
          {/* Loading state */}
          {status === 'loading' && (
            <>
              <Loader2 className="h-16 w-16 text-cyan-500 mx-auto mb-4 animate-spin" />
              <h2 className="text-xl font-bold text-white mb-2">Verifying your email...</h2>
              <p className="text-gray-400">Please wait while we verify your email address.</p>
            </>
          )}

          {/* Success state */}
          {status === 'success' && (
            <>
              <CheckCircle className="h-16 w-16 text-green-500 mx-auto mb-4" />
              <h2 className="text-xl font-bold text-white mb-2">Email Verified!</h2>
              <p className="text-gray-400 mb-6">{message}</p>

              {email && (
                <div className="flex items-center justify-center gap-2 text-gray-300 mb-6">
                  <Mail className="h-5 w-5 text-cyan-400" />
                  <span>{email}</span>
                </div>
              )}

              <button
                onClick={handleContinue}
                className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-cyan-500 text-white font-medium rounded-lg hover:bg-cyan-600 transition-colors"
              >
                Continue to Account Setup
                <ArrowRight className="h-5 w-5" />
              </button>
            </>
          )}

          {/* Payment required state */}
          {status === 'payment_required' && (
            <>
              <AlertCircle className="h-16 w-16 text-yellow-500 mx-auto mb-4" />
              <h2 className="text-xl font-bold text-white mb-2">Payment Required</h2>
              <p className="text-gray-400 mb-6">{message}</p>

              {email && (
                <div className="flex items-center justify-center gap-2 text-gray-300 mb-2">
                  <Mail className="h-5 w-5 text-cyan-400" />
                  <span>{email}</span>
                </div>
              )}

              {tier && (
                <p className="text-sm text-gray-500 mb-6">
                  Selected plan: <span className="text-cyan-400 capitalize">{tier}</span>
                </p>
              )}

              <button
                onClick={handleContinue}
                className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-cyan-500 text-white font-medium rounded-lg hover:bg-cyan-600 transition-colors"
              >
                Complete Payment
                <ArrowRight className="h-5 w-5" />
              </button>
            </>
          )}

          {/* Error state */}
          {status === 'error' && (
            <>
              <XCircle className="h-16 w-16 text-red-500 mx-auto mb-4" />
              <h2 className="text-xl font-bold text-white mb-2">Verification Failed</h2>
              <p className="text-gray-400 mb-6">{message}</p>

              <div className="space-y-3">
                <button
                  onClick={() => navigate('/register')}
                  className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-cyan-500 text-white font-medium rounded-lg hover:bg-cyan-600 transition-colors"
                >
                  Try Again
                  <ArrowRight className="h-5 w-5" />
                </button>
                <button
                  onClick={() => navigate('/login')}
                  className="w-full px-6 py-3 text-gray-400 hover:text-white transition-colors"
                >
                  Already have an account? Sign in
                </button>
              </div>
            </>
          )}
        </div>

        {/* Help text */}
        <p className="text-center text-gray-500 text-sm mt-6">
          Need help?{' '}
          <a href="mailto:support@heroforge.io" className="text-cyan-400 hover:text-cyan-300">
            Contact support
          </a>
        </p>
      </div>
    </div>
  );
}
