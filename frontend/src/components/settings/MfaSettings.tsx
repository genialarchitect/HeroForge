import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { mfaAPI, authAPI } from '../../services/api';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Input from '../ui/Input';
import LoadingSpinner from '../ui/LoadingSpinner';
import { Shield, Smartphone, Key, Download, Copy, CheckCircle, AlertTriangle, Lock } from 'lucide-react';

type SetupStep = 'idle' | 'scan-qr' | 'verify-code' | 'show-recovery';

const MfaSettings: React.FC = () => {
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [setupStep, setSetupStep] = useState<SetupStep>('idle');

  // Setup flow state
  const [secret, setSecret] = useState('');
  const [qrCodeUrl, setQrCodeUrl] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [verifyCode, setVerifyCode] = useState('');
  const [verifying, setVerifying] = useState(false);

  // Disable MFA state
  const [showDisableForm, setShowDisableForm] = useState(false);
  const [disablePassword, setDisablePassword] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [disabling, setDisabling] = useState(false);

  // Regenerate codes state
  const [showRegenerateForm, setShowRegenerateForm] = useState(false);
  const [regeneratePassword, setRegeneratePassword] = useState('');
  const [regenerateCode, setRegenerateCode] = useState('');
  const [regenerating, setRegenerating] = useState(false);

  useEffect(() => {
    checkMfaStatus();
  }, []);

  const checkMfaStatus = async () => {
    setLoading(true);
    try {
      const response = await authAPI.me();
      setMfaEnabled(response.data.mfa_enabled || false);
    } catch (error) {
      console.error('Failed to check MFA status:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleStartSetup = async () => {
    try {
      const response = await mfaAPI.setup();
      setSecret(response.data.secret);
      setQrCodeUrl(response.data.qr_code_url);
      setRecoveryCodes(response.data.recovery_codes);
      setSetupStep('scan-qr');
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to initialize MFA setup');
    }
  };

  const handleVerifySetup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!verifyCode || verifyCode.length !== 6) {
      toast.error('Please enter a valid 6-digit code');
      return;
    }

    setVerifying(true);
    try {
      await mfaAPI.verifySetup({ totp_code: verifyCode });
      toast.success('MFA enabled successfully!');
      setSetupStep('show-recovery');
      setMfaEnabled(true);
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Invalid verification code');
    } finally {
      setVerifying(false);
    }
  };

  const handleFinishSetup = () => {
    setSetupStep('idle');
    setSecret('');
    setQrCodeUrl('');
    setRecoveryCodes([]);
    setVerifyCode('');
  };

  const handleDisableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!disablePassword || !disableCode) {
      toast.error('Password and TOTP code are required');
      return;
    }

    setDisabling(true);
    try {
      await mfaAPI.disable({
        password: disablePassword,
        totp_code: disableCode,
      });
      toast.success('MFA disabled successfully');
      setMfaEnabled(false);
      setShowDisableForm(false);
      setDisablePassword('');
      setDisableCode('');
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to disable MFA');
    } finally {
      setDisabling(false);
    }
  };

  const handleRegenerateCodes = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!regeneratePassword || !regenerateCode) {
      toast.error('Password and TOTP code are required');
      return;
    }

    setRegenerating(true);
    try {
      const response = await mfaAPI.regenerateRecoveryCodes({
        password: regeneratePassword,
        totp_code: regenerateCode,
      });
      setRecoveryCodes(response.data.recovery_codes);
      toast.success('Recovery codes regenerated successfully');
      setShowRegenerateForm(false);
      setRegeneratePassword('');
      setRegenerateCode('');
      setSetupStep('show-recovery');
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to regenerate recovery codes');
    } finally {
      setRegenerating(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  const downloadRecoveryCodes = () => {
    const blob = new Blob([recoveryCodes.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'heroforge-recovery-codes.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success('Recovery codes downloaded');
  };

  if (loading) {
    return (
      <Card>
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner />
        </div>
      </Card>
    );
  }

  // Setup flow rendering
  if (setupStep !== 'idle') {
    return (
      <div className="space-y-6">
        {/* Setup progress indicator */}
        <Card>
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <Shield className="h-6 w-6 text-primary" />
              <h3 className="text-xl font-semibold text-white">Enable Two-Factor Authentication</h3>
            </div>
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <span className={setupStep === 'scan-qr' ? 'text-primary' : ''}>1. Scan QR</span>
              <span>→</span>
              <span className={setupStep === 'verify-code' ? 'text-primary' : ''}>2. Verify</span>
              <span>→</span>
              <span className={setupStep === 'show-recovery' ? 'text-primary' : ''}>3. Save Codes</span>
            </div>
          </div>

          {setupStep === 'scan-qr' && (
            <div className="space-y-6">
              <div className="bg-dark-bg rounded-lg p-6">
                <div className="flex flex-col items-center">
                  <h4 className="text-lg font-medium text-white mb-4">
                    Step 1: Scan QR Code
                  </h4>
                  <p className="text-slate-400 text-sm text-center mb-6 max-w-md">
                    Use an authenticator app like Google Authenticator, Authy, or 1Password to scan this QR code:
                  </p>
                  {qrCodeUrl && (
                    <div className="bg-white p-4 rounded-lg mb-4">
                      <img src={qrCodeUrl} alt="MFA QR Code" className="w-64 h-64" />
                    </div>
                  )}
                  <div className="mt-4 w-full max-w-md">
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Or enter this secret manually:
                    </label>
                    <div className="flex gap-2">
                      <Input
                        type="text"
                        value={secret}
                        readOnly
                        className="font-mono text-sm flex-1"
                      />
                      <Button
                        variant="secondary"
                        onClick={() => copyToClipboard(secret)}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex justify-end">
                <Button
                  variant="primary"
                  onClick={() => setSetupStep('verify-code')}
                >
                  Next: Verify Code
                </Button>
              </div>
            </div>
          )}

          {setupStep === 'verify-code' && (
            <form onSubmit={handleVerifySetup} className="space-y-6">
              <div className="bg-dark-bg rounded-lg p-6">
                <div className="flex flex-col items-center">
                  <Smartphone className="h-12 w-12 text-primary mb-4" />
                  <h4 className="text-lg font-medium text-white mb-4">
                    Step 2: Verify Your Code
                  </h4>
                  <p className="text-slate-400 text-sm text-center mb-6 max-w-md">
                    Enter the 6-digit code from your authenticator app to confirm setup:
                  </p>
                  <div className="w-full max-w-xs">
                    <Input
                      type="text"
                      value={verifyCode}
                      onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      placeholder="000000"
                      className="text-center text-2xl tracking-widest font-mono"
                      maxLength={6}
                      autoFocus
                    />
                  </div>
                </div>
              </div>
              <div className="flex justify-between">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => setSetupStep('scan-qr')}
                >
                  Back
                </Button>
                <Button
                  type="submit"
                  variant="primary"
                  loading={verifying}
                  disabled={verifying || verifyCode.length !== 6}
                >
                  Verify & Enable MFA
                </Button>
              </div>
            </form>
          )}

          {setupStep === 'show-recovery' && (
            <div className="space-y-6">
              <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-6">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="h-6 w-6 text-yellow-400 flex-shrink-0 mt-1" />
                  <div>
                    <h4 className="text-lg font-medium text-yellow-400 mb-2">
                      Save Your Recovery Codes
                    </h4>
                    <p className="text-slate-300 text-sm mb-4">
                      Store these recovery codes in a safe place. Each code can be used once to access your account if you lose your authenticator device.
                    </p>
                    <div className="grid grid-cols-2 gap-2 bg-dark-bg rounded-lg p-4 font-mono text-sm mb-4">
                      {recoveryCodes.map((code, idx) => (
                        <div key={idx} className="text-white">
                          {idx + 1}. {code}
                        </div>
                      ))}
                    </div>
                    <div className="flex gap-2">
                      <Button
                        variant="secondary"
                        onClick={() => copyToClipboard(recoveryCodes.join('\n'))}
                      >
                        <Copy className="h-4 w-4 mr-2" />
                        Copy Codes
                      </Button>
                      <Button
                        variant="secondary"
                        onClick={downloadRecoveryCodes}
                      >
                        <Download className="h-4 w-4 mr-2" />
                        Download Codes
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex justify-end">
                <Button
                  variant="primary"
                  onClick={handleFinishSetup}
                >
                  <CheckCircle className="h-4 w-4 mr-2" />
                  Finish Setup
                </Button>
              </div>
            </div>
          )}
        </Card>
      </div>
    );
  }

  // Main MFA status view
  return (
    <div className="space-y-6">
      {/* MFA Status Card */}
      <Card>
        <div className="flex items-center gap-3 mb-6">
          <Shield className="h-6 w-6 text-primary" />
          <h3 className="text-xl font-semibold text-white">Two-Factor Authentication</h3>
        </div>

        <div className="flex items-start justify-between mb-6 p-4 bg-dark-bg rounded-lg">
          <div className="flex items-start gap-3">
            {mfaEnabled ? (
              <CheckCircle className="h-6 w-6 text-green-400 flex-shrink-0" />
            ) : (
              <AlertTriangle className="h-6 w-6 text-yellow-400 flex-shrink-0" />
            )}
            <div>
              <h4 className="font-medium text-white mb-1">
                {mfaEnabled ? 'MFA Enabled' : 'MFA Disabled'}
              </h4>
              <p className="text-sm text-slate-400">
                {mfaEnabled
                  ? 'Your account is protected with two-factor authentication.'
                  : 'Enable MFA to add an extra layer of security to your account.'}
              </p>
            </div>
          </div>
          <div className={`w-3 h-3 rounded-full ${mfaEnabled ? 'bg-green-400' : 'bg-yellow-400'}`} />
        </div>

        {!mfaEnabled ? (
          <div className="space-y-4">
            <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
              <h5 className="text-white font-medium mb-2">Why enable MFA?</h5>
              <ul className="text-sm text-slate-300 space-y-1 list-disc list-inside">
                <li>Adds an extra layer of security beyond your password</li>
                <li>Prevents unauthorized access even if your password is compromised</li>
                <li>Uses time-based codes from your smartphone</li>
                <li>Industry standard for securing sensitive accounts</li>
              </ul>
            </div>
            <Button variant="primary" onClick={handleStartSetup}>
              <Smartphone className="h-4 w-4 mr-2" />
              Enable Two-Factor Authentication
            </Button>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Regenerate Recovery Codes */}
              <div className="bg-dark-bg rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Key className="h-5 w-5 text-primary" />
                  <h5 className="font-medium text-white">Recovery Codes</h5>
                </div>
                <p className="text-sm text-slate-400 mb-3">
                  Generate new recovery codes if you've lost the originals or used them.
                </p>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => setShowRegenerateForm(true)}
                >
                  Regenerate Codes
                </Button>
              </div>

              {/* Disable MFA */}
              <div className="bg-dark-bg rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Lock className="h-5 w-5 text-red-400" />
                  <h5 className="font-medium text-white">Disable MFA</h5>
                </div>
                <p className="text-sm text-slate-400 mb-3">
                  Turn off two-factor authentication for your account.
                </p>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={() => setShowDisableForm(true)}
                >
                  Disable MFA
                </Button>
              </div>
            </div>
          </div>
        )}
      </Card>

      {/* Disable MFA Form */}
      {showDisableForm && (
        <Card>
          <form onSubmit={handleDisableMfa} className="space-y-4">
            <div className="flex items-center justify-between mb-4">
              <h4 className="text-lg font-medium text-white">Disable Two-Factor Authentication</h4>
              <button
                type="button"
                onClick={() => {
                  setShowDisableForm(false);
                  setDisablePassword('');
                  setDisableCode('');
                }}
                className="text-slate-400 hover:text-white"
              >
                <span className="sr-only">Close</span>
                ✕
              </button>
            </div>
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 mb-4">
              <p className="text-sm text-yellow-300">
                Disabling MFA will make your account less secure. You'll need to provide your password and a TOTP code to confirm.
              </p>
            </div>
            <Input
              label="Password"
              type="password"
              value={disablePassword}
              onChange={(e) => setDisablePassword(e.target.value)}
              placeholder="Your account password"
              autoComplete="current-password"
            />
            <Input
              label="TOTP Code"
              type="text"
              value={disableCode}
              onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="000000"
              className="text-center tracking-widest font-mono"
              maxLength={6}
            />
            <div className="flex justify-end gap-2">
              <Button
                type="button"
                variant="secondary"
                onClick={() => {
                  setShowDisableForm(false);
                  setDisablePassword('');
                  setDisableCode('');
                }}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                variant="danger"
                loading={disabling}
                disabled={disabling || !disablePassword || disableCode.length !== 6}
              >
                Disable MFA
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* Regenerate Recovery Codes Form */}
      {showRegenerateForm && (
        <Card>
          <form onSubmit={handleRegenerateCodes} className="space-y-4">
            <div className="flex items-center justify-between mb-4">
              <h4 className="text-lg font-medium text-white">Regenerate Recovery Codes</h4>
              <button
                type="button"
                onClick={() => {
                  setShowRegenerateForm(false);
                  setRegeneratePassword('');
                  setRegenerateCode('');
                }}
                className="text-slate-400 hover:text-white"
              >
                <span className="sr-only">Close</span>
                ✕
              </button>
            </div>
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 mb-4">
              <p className="text-sm text-yellow-300">
                This will invalidate all existing recovery codes. Make sure to save the new codes in a safe place.
              </p>
            </div>
            <Input
              label="Password"
              type="password"
              value={regeneratePassword}
              onChange={(e) => setRegeneratePassword(e.target.value)}
              placeholder="Your account password"
              autoComplete="current-password"
            />
            <Input
              label="TOTP Code"
              type="text"
              value={regenerateCode}
              onChange={(e) => setRegenerateCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="000000"
              className="text-center tracking-widest font-mono"
              maxLength={6}
            />
            <div className="flex justify-end gap-2">
              <Button
                type="button"
                variant="secondary"
                onClick={() => {
                  setShowRegenerateForm(false);
                  setRegeneratePassword('');
                  setRegenerateCode('');
                }}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                variant="primary"
                loading={regenerating}
                disabled={regenerating || !regeneratePassword || regenerateCode.length !== 6}
              >
                Generate New Codes
              </Button>
            </div>
          </form>
        </Card>
      )}
    </div>
  );
};

export default MfaSettings;
