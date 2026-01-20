import React, { useEffect, useState } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import {
  Shield, CheckCircle, XCircle, Search, Award, Calendar,
  User, BookOpen, ArrowLeft
} from 'lucide-react';
import { academyPublicApi } from '../services/academyApi';
import { CertificateVerification } from '../types/academy';

const CertificateVerifyPage: React.FC = () => {
  const { number } = useParams<{ number: string }>();
  const navigate = useNavigate();

  const [certificateNumber, setCertificateNumber] = useState(number || '');
  const [isLoading, setIsLoading] = useState(false);
  const [verification, setVerification] = useState<CertificateVerification | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hasSearched, setHasSearched] = useState(false);

  // Verify on mount if number provided
  useEffect(() => {
    if (number) {
      handleVerify(number);
    }
  }, [number]);

  // Verify certificate
  const handleVerify = async (numToVerify?: string) => {
    const num = numToVerify || certificateNumber.trim();
    if (!num) {
      setError('Please enter a certificate number');
      return;
    }

    setIsLoading(true);
    setError(null);
    setHasSearched(true);

    try {
      const result = await academyPublicApi.verifyCertificate(num);
      setVerification(result);

      // Update URL if not already there
      if (!number || number !== num) {
        navigate(`/certificates/verify/${num}`, { replace: true });
      }
    } catch (err) {
      setError('Failed to verify certificate. Please try again.');
      setVerification(null);
    } finally {
      setIsLoading(false);
    }
  };

  // Format date
  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  };

  // Handle form submit
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleVerify();
  };

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link to="/" className="flex items-center space-x-2">
            <Shield className="w-8 h-8 text-cyan-400" />
            <span className="text-2xl font-bold text-cyan-400">HeroForge</span>
          </Link>
          <nav className="flex items-center space-x-6">
            <Link to="/academy" className="text-gray-300 hover:text-white">
              Academy
            </Link>
          </nav>
        </div>
      </header>

      <main className="max-w-2xl mx-auto px-4 py-12">
        {/* Back link */}
        <Link
          to="/academy"
          className="inline-flex items-center text-gray-400 hover:text-white mb-8"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Academy
        </Link>

        {/* Title */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center bg-cyan-900/30 text-cyan-400 px-4 py-2 rounded-full text-sm font-medium mb-4">
            <Award className="w-4 h-4 mr-2" />
            Certificate Verification
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">Verify a Certificate</h1>
          <p className="text-gray-400">
            Enter a certificate number to verify its authenticity
          </p>
        </div>

        {/* Search form */}
        <form onSubmit={handleSubmit} className="mb-8">
          <div className="flex gap-4">
            <div className="flex-1 relative">
              <input
                type="text"
                value={certificateNumber}
                onChange={(e) => setCertificateNumber(e.target.value.toUpperCase())}
                placeholder="e.g., HFA-2026-ABC123"
                className="w-full bg-gray-800 border border-gray-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent placeholder-gray-500 font-mono"
              />
            </div>
            <button
              type="submit"
              disabled={isLoading}
              className="bg-cyan-600 hover:bg-cyan-700 text-white font-medium px-6 py-3 rounded-lg transition-colors flex items-center disabled:opacity-50"
            >
              {isLoading ? (
                <>
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                  Verifying...
                </>
              ) : (
                <>
                  <Search className="w-5 h-5 mr-2" />
                  Verify
                </>
              )}
            </button>
          </div>
          {error && <p className="text-red-400 text-sm mt-2">{error}</p>}
        </form>

        {/* Results */}
        {hasSearched && !isLoading && (
          <div className="bg-gray-800 rounded-xl overflow-hidden">
            {verification?.valid ? (
              <>
                {/* Valid certificate */}
                <div className="bg-green-900/30 border-b border-green-700 p-6 text-center">
                  <CheckCircle className="w-16 h-16 text-green-400 mx-auto mb-4" />
                  <h2 className="text-2xl font-bold text-white mb-2">Certificate Verified</h2>
                  <p className="text-green-400">This certificate is authentic and valid</p>
                </div>

                <div className="p-6 space-y-6">
                  {/* Holder */}
                  <div className="flex items-start">
                    <User className="w-5 h-5 text-gray-400 mr-3 mt-0.5" />
                    <div>
                      <p className="text-sm text-gray-500 mb-1">Certified To</p>
                      <p className="text-white font-medium">
                        {verification.holder_name || 'Certificate Holder'}
                      </p>
                    </div>
                  </div>

                  {/* Course */}
                  {verification.path && (
                    <div className="flex items-start">
                      <BookOpen className="w-5 h-5 text-gray-400 mr-3 mt-0.5" />
                      <div>
                        <p className="text-sm text-gray-500 mb-1">Course Completed</p>
                        <p className="text-white font-medium">{verification.path.title}</p>
                        <p className="text-sm text-gray-400">{verification.path.level} Level</p>
                      </div>
                    </div>
                  )}

                  {/* Certificate details */}
                  {verification.certificate && (
                    <>
                      <div className="flex items-start">
                        <Award className="w-5 h-5 text-gray-400 mr-3 mt-0.5" />
                        <div>
                          <p className="text-sm text-gray-500 mb-1">Certificate Number</p>
                          <p className="text-white font-mono">
                            {verification.certificate.certificate_number}
                          </p>
                        </div>
                      </div>

                      <div className="flex items-start">
                        <Calendar className="w-5 h-5 text-gray-400 mr-3 mt-0.5" />
                        <div>
                          <p className="text-sm text-gray-500 mb-1">Issue Date</p>
                          <p className="text-white">
                            {formatDate(verification.certificate.issued_at)}
                          </p>
                          {verification.certificate.expires_at && (
                            <p className="text-sm text-gray-400 mt-1">
                              Expires: {formatDate(verification.certificate.expires_at)}
                            </p>
                          )}
                        </div>
                      </div>
                    </>
                  )}
                </div>

                {/* Credential name */}
                {verification.path?.certificate_name && (
                  <div className="bg-gradient-to-r from-cyan-900/30 to-purple-900/30 border-t border-gray-700 p-6 text-center">
                    <p className="text-gray-400 text-sm mb-1">Credential Earned</p>
                    <p className="text-xl font-semibold text-white">
                      {verification.path.certificate_name}
                    </p>
                  </div>
                )}
              </>
            ) : (
              <>
                {/* Invalid certificate */}
                <div className="bg-red-900/30 border-b border-red-700 p-6 text-center">
                  <XCircle className="w-16 h-16 text-red-400 mx-auto mb-4" />
                  <h2 className="text-2xl font-bold text-white mb-2">Certificate Not Found</h2>
                  <p className="text-red-400">
                    This certificate number could not be verified
                  </p>
                </div>

                <div className="p-6 text-center">
                  <p className="text-gray-400 mb-4">
                    The certificate number you entered was not found in our system. Please check the
                    number and try again.
                  </p>
                  <p className="text-sm text-gray-500">
                    If you believe this is an error, please contact{' '}
                    <a href="mailto:support@genialarchitect.io" className="text-cyan-400 hover:underline">
                      support@genialarchitect.io
                    </a>
                  </p>
                </div>
              </>
            )}
          </div>
        )}

        {/* Info section */}
        {!hasSearched && (
          <div className="bg-gray-800 rounded-xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4">About Certificate Verification</h3>
            <div className="space-y-4 text-gray-400 text-sm">
              <p>
                All HeroForge Academy certificates are digitally signed and can be verified using
                this tool. Each certificate has a unique certificate number in the format:
              </p>
              <div className="bg-gray-900 rounded p-3 font-mono text-center text-cyan-400">
                HFA-YYYY-XXXXXX
              </div>
              <p>
                Where <code className="text-cyan-400">YYYY</code> is the year and{' '}
                <code className="text-cyan-400">XXXXXX</code> is a unique identifier.
              </p>
              <p>
                Certificate verification helps employers and organizations confirm that a credential
                is authentic and was legitimately earned by completing all required coursework and
                assessments.
              </p>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 mt-16">
        <div className="max-w-4xl mx-auto px-4 py-8">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <p className="text-gray-400 text-sm">
              &copy; 2026 Genial Architect Cybersecurity Research Associates. All rights reserved.
            </p>
            <div className="flex space-x-6 mt-4 md:mt-0">
              <Link to="/legal/terms" className="text-gray-400 hover:text-white text-sm">
                Terms
              </Link>
              <Link to="/legal/privacy" className="text-gray-400 hover:text-white text-sm">
                Privacy
              </Link>
              <Link to="/academy" className="text-gray-400 hover:text-white text-sm">
                Academy
              </Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default CertificateVerifyPage;
