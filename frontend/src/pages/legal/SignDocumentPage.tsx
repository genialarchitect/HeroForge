import React, { useState, useEffect } from 'react';
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import {
  FileText,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Shield,
  RefreshCw,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { signingApi } from '../../services/legalApi';
import type { SigningData, SignatureInfo } from '../../types/legal';
import { getDocumentTypeLabel } from '../../types/legal';
import { DocumentPreview, SignatureCapture } from '../../components/legal';

type PageState = 'loading' | 'ready' | 'signed' | 'declined' | 'already_signed' | 'error' | 'expired';

const SignDocumentPage: React.FC = () => {
  const { token } = useParams<{ token: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const [pageState, setPageState] = useState<PageState>('loading');
  const [signingData, setSigningData] = useState<SigningData | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string>('');

  // Get email from query params
  const email = searchParams.get('email') || '';

  useEffect(() => {
    const loadDocument = async () => {
      if (!token || !email) {
        setErrorMessage('Invalid signing link. Please check your email for the correct link.');
        setPageState('error');
        return;
      }

      try {
        const data = await signingApi.getDocument(token, email);
        setSigningData(data);

        // Check if this signer has already signed
        const currentSigner = data.all_signatures.find((s) => s.signer_email === email);
        if (currentSigner?.status === 'signed') {
          setPageState('already_signed');
        } else if (currentSigner?.status === 'declined') {
          setPageState('declined');
        } else {
          setPageState('ready');
        }
      } catch (error: any) {
        console.error('Failed to load document:', error);
        if (error.response?.status === 404) {
          setErrorMessage('This signing link is invalid or has expired.');
          setPageState('expired');
        } else if (error.response?.status === 403) {
          setErrorMessage('You are not authorized to sign this document.');
          setPageState('error');
        } else {
          setErrorMessage('Failed to load document. Please try again later.');
          setPageState('error');
        }
      }
    };

    loadDocument();
  }, [token, email]);

  const handleSign = async (data: { signerName: string; signatureImage: string; acknowledgment: boolean }) => {
    if (!token) return;

    setIsSubmitting(true);
    try {
      const result = await signingApi.submitSignature(token, {
        signer_email: email,
        signer_name: data.signerName,
        signature_image: data.signatureImage,
        acknowledgment: data.acknowledgment,
      });
      toast.success('Document signed successfully!');
      setPageState('signed');
    } catch (error: any) {
      console.error('Failed to sign:', error);
      toast.error(error.response?.data?.message || 'Failed to sign document');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDecline = async (reason: string) => {
    if (!token) return;

    setIsSubmitting(true);
    try {
      await signingApi.declineSignature(token, {
        signer_email: email,
        reason,
      });
      toast.info('Signature declined');
      setPageState('declined');
    } catch (error: any) {
      console.error('Failed to decline:', error);
      toast.error(error.response?.data?.message || 'Failed to decline signature');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Loading state
  if (pageState === 'loading') {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <RefreshCw className="w-10 h-10 text-cyan-400 animate-spin mx-auto mb-4" />
          <p className="text-gray-400">Loading document...</p>
        </div>
      </div>
    );
  }

  // Error state
  if (pageState === 'error' || pageState === 'expired') {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full text-center">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-red-900/30 flex items-center justify-center">
            <AlertTriangle className="w-8 h-8 text-red-400" />
          </div>
          <h1 className="text-xl font-bold text-white mb-2">
            {pageState === 'expired' ? 'Link Expired' : 'Error'}
          </h1>
          <p className="text-gray-400 mb-6">{errorMessage}</p>
          <p className="text-gray-500 text-sm">
            If you believe this is an error, please contact the document sender.
          </p>
        </div>
      </div>
    );
  }

  // Signed state
  if (pageState === 'signed' || pageState === 'already_signed') {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full text-center">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-green-900/30 flex items-center justify-center">
            <CheckCircle className="w-8 h-8 text-green-400" />
          </div>
          <h1 className="text-xl font-bold text-white mb-2">
            {pageState === 'already_signed' ? 'Already Signed' : 'Document Signed'}
          </h1>
          <p className="text-gray-400 mb-4">
            {pageState === 'already_signed'
              ? 'You have already signed this document.'
              : 'Thank you for signing! A copy will be sent to your email once all parties have signed.'}
          </p>
          {signingData && (
            <div className="bg-gray-700/50 rounded-lg p-4 text-left">
              <p className="text-sm text-gray-300">
                <strong>Document:</strong> {signingData.document_name}
              </p>
              <p className="text-sm text-gray-400 mt-1">
                <strong>Engagement:</strong> {signingData.engagement_name}
              </p>
            </div>
          )}
        </div>
      </div>
    );
  }

  // Declined state
  if (pageState === 'declined') {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 max-w-md w-full text-center">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-yellow-900/30 flex items-center justify-center">
            <XCircle className="w-8 h-8 text-yellow-400" />
          </div>
          <h1 className="text-xl font-bold text-white mb-2">Signature Declined</h1>
          <p className="text-gray-400 mb-4">
            You have declined to sign this document. The document sender has been notified.
          </p>
          {signingData && (
            <div className="bg-gray-700/50 rounded-lg p-4 text-left">
              <p className="text-sm text-gray-300">
                <strong>Document:</strong> {signingData.document_name}
              </p>
            </div>
          )}
        </div>
      </div>
    );
  }

  // Ready to sign state
  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-cyan-600 rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-white">HeroForge</h1>
              <p className="text-xs text-gray-400">Secure Document Signing</p>
            </div>
          </div>
          <div className="text-right">
            <p className="text-sm text-gray-300">{signingData?.customer_name}</p>
            <p className="text-xs text-gray-500">{signingData?.engagement_name}</p>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto p-6">
        {/* Document Info */}
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-6">
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <FileText className="w-5 h-5 text-cyan-400" />
                <h2 className="text-xl font-semibold text-white">{signingData?.document_name}</h2>
              </div>
              <p className="text-gray-400 text-sm">
                {signingData && getDocumentTypeLabel(signingData.document_type)}
              </p>
            </div>
            <div className="text-right">
              <p className="text-sm text-gray-300">
                Signing as: <span className="text-cyan-400">{signingData?.signer_role}</span>
              </p>
              <p className="text-xs text-gray-500">{signingData?.signer_email}</p>
            </div>
          </div>

          {/* Signature Status */}
          {signingData && signingData.all_signatures.length > 1 && (
            <div className="mt-4 pt-4 border-t border-gray-700">
              <p className="text-xs text-gray-500 uppercase tracking-wide mb-2">Signature Status</p>
              <div className="flex flex-wrap gap-2">
                {signingData.all_signatures.map((sig, idx) => (
                  <div
                    key={idx}
                    className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs ${
                      sig.status === 'signed'
                        ? 'bg-green-900/30 text-green-400'
                        : sig.status === 'declined'
                        ? 'bg-red-900/30 text-red-400'
                        : 'bg-gray-700 text-gray-400'
                    }`}
                  >
                    {sig.status === 'signed' ? (
                      <CheckCircle className="w-3 h-3" />
                    ) : sig.status === 'declined' ? (
                      <XCircle className="w-3 h-3" />
                    ) : (
                      <div className="w-3 h-3 rounded-full border border-current" />
                    )}
                    {sig.signer_role}
                    {sig.signer_email === email && ' (You)'}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Document Preview */}
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-6">
          <h3 className="text-lg font-semibold text-white mb-4">Document Preview</h3>
          <div className="max-h-[600px] overflow-y-auto rounded-lg">
            {signingData && (
              <DocumentPreview
                contentHtml={signingData.content_html}
                signatures={signingData.all_signatures.map((s) => ({
                  id: '',
                  document_id: signingData.document_id,
                  signer_type: s.signer_type,
                  signer_role: s.signer_role,
                  signer_name: s.signer_name,
                  signer_email: s.signer_email,
                  status: s.status,
                  signed_at: s.signed_at,
                  signed_ip: null,
                  signature_image: null,
                  decline_reason: null,
                  signature_order: 0,
                }))}
                showSignatureBlocks={true}
              />
            )}
          </div>
        </div>

        {/* Signature Capture */}
        {signingData && (
          <SignatureCapture
            signerRole={signingData.signer_role}
            signerEmail={signingData.signer_email}
            onSubmit={handleSign}
            onDecline={handleDecline}
            isSubmitting={isSubmitting}
          />
        )}

        {/* Security Notice */}
        <div className="mt-6 p-4 bg-gray-800/50 border border-gray-700 rounded-lg">
          <div className="flex items-start gap-3">
            <Shield className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
            <div className="text-sm text-gray-400">
              <p className="font-medium text-gray-300 mb-1">Secure Signing</p>
              <p>
                Your signature is protected using industry-standard encryption. We record your IP address
                and timestamp for legal verification purposes. This electronic signature is legally binding.
              </p>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="mt-12 py-6 border-t border-gray-800">
        <div className="max-w-5xl mx-auto px-6 text-center text-xs text-gray-500">
          <p>Powered by HeroForge Security Platform</p>
          <p className="mt-1">
            Questions about this document? Contact the sender or your account representative.
          </p>
        </div>
      </footer>
    </div>
  );
};

export default SignDocumentPage;
