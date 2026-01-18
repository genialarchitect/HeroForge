import React from 'react';
import { Check, Clock, X } from 'lucide-react';
import type { LegalDocumentSignature, SignatureStatus } from '../../types/legal';

interface SignatureBlock {
  signerType: 'client' | 'provider';
  signerRole: string;
  signerName: string | null;
  signerEmail: string;
  status: SignatureStatus;
  signedAt: string | null;
  signatureImage?: string | null;
}

interface DocumentPreviewProps {
  contentHtml: string;
  signatures?: LegalDocumentSignature[];
  showSignatureBlocks?: boolean;
  className?: string;
}

const StatusIcon: React.FC<{ status: SignatureStatus }> = ({ status }) => {
  switch (status) {
    case 'signed':
      return <Check className="w-4 h-4 text-green-500" />;
    case 'declined':
      return <X className="w-4 h-4 text-red-500" />;
    default:
      return <Clock className="w-4 h-4 text-yellow-500" />;
  }
};

const SignatureBlockDisplay: React.FC<{ signature: SignatureBlock }> = ({ signature }) => {
  const statusColors = {
    pending: 'border-yellow-500/30 bg-yellow-500/5',
    signed: 'border-green-500/30 bg-green-500/5',
    declined: 'border-red-500/30 bg-red-500/5',
  };

  return (
    <div
      className={`border-2 rounded-lg p-4 ${statusColors[signature.status]}`}
      style={{ minWidth: '280px' }}
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm font-medium text-gray-700">
          {signature.signerType === 'client' ? 'Client' : 'Provider'} - {signature.signerRole}
        </span>
        <div className="flex items-center gap-1">
          <StatusIcon status={signature.status} />
          <span
            className={`text-xs font-medium ${
              signature.status === 'signed'
                ? 'text-green-600'
                : signature.status === 'declined'
                ? 'text-red-600'
                : 'text-yellow-600'
            }`}
          >
            {signature.status === 'signed'
              ? 'Signed'
              : signature.status === 'declined'
              ? 'Declined'
              : 'Pending'}
          </span>
        </div>
      </div>

      {signature.status === 'signed' && signature.signatureImage ? (
        <div className="space-y-2">
          <div className="bg-white border border-gray-200 rounded p-2">
            <img
              src={signature.signatureImage}
              alt={`Signature of ${signature.signerName}`}
              className="max-h-16 mx-auto"
            />
          </div>
          <div className="text-sm">
            <p className="font-medium text-gray-800">{signature.signerName}</p>
            <p className="text-gray-500 text-xs">{signature.signerEmail}</p>
            {signature.signedAt && (
              <p className="text-gray-400 text-xs mt-1">
                Signed: {new Date(signature.signedAt).toLocaleString()}
              </p>
            )}
          </div>
        </div>
      ) : signature.status === 'declined' ? (
        <div className="text-sm">
          <p className="text-gray-500">{signature.signerEmail}</p>
          <p className="text-red-500 text-xs mt-1">This signer has declined to sign.</p>
        </div>
      ) : (
        <div className="space-y-2">
          <div className="h-16 border-b-2 border-dashed border-gray-300 flex items-end justify-center pb-1">
            <span className="text-gray-400 text-xs">Signature</span>
          </div>
          <div className="text-sm text-gray-500">
            <p>{signature.signerEmail}</p>
            <p className="text-xs text-gray-400 mt-1">Awaiting signature</p>
          </div>
        </div>
      )}
    </div>
  );
};

const DocumentPreview: React.FC<DocumentPreviewProps> = ({
  contentHtml,
  signatures = [],
  showSignatureBlocks = true,
  className = '',
}) => {
  const signatureBlocks: SignatureBlock[] = signatures.map((sig) => ({
    signerType: sig.signer_type,
    signerRole: sig.signer_role,
    signerName: sig.signer_name,
    signerEmail: sig.signer_email,
    status: sig.status,
    signedAt: sig.signed_at,
    signatureImage: sig.signature_image,
  }));

  // Group signatures by type
  const clientSignatures = signatureBlocks.filter((s) => s.signerType === 'client');
  const providerSignatures = signatureBlocks.filter((s) => s.signerType === 'provider');

  return (
    <div className={`document-preview ${className}`}>
      {/* Document Content */}
      <div
        className="bg-white text-gray-900 p-8 rounded-lg shadow-lg prose prose-sm max-w-none"
        style={{
          fontFamily: 'Georgia, "Times New Roman", Times, serif',
          lineHeight: 1.6,
        }}
      >
        {/* Render HTML content */}
        <div
          dangerouslySetInnerHTML={{ __html: contentHtml }}
          className="document-content"
        />

        {/* Signature Blocks */}
        {showSignatureBlocks && signatureBlocks.length > 0 && (
          <div className="mt-8 pt-8 border-t border-gray-200">
            <h3 className="text-lg font-semibold mb-6 text-gray-800">Signatures</h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Client Signatures */}
              {clientSignatures.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-gray-600 mb-3 uppercase tracking-wide">
                    Client
                  </h4>
                  <div className="space-y-4">
                    {clientSignatures.map((sig, idx) => (
                      <SignatureBlockDisplay key={`client-${idx}`} signature={sig} />
                    ))}
                  </div>
                </div>
              )}

              {/* Provider Signatures */}
              {providerSignatures.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-gray-600 mb-3 uppercase tracking-wide">
                    Provider
                  </h4>
                  <div className="space-y-4">
                    {providerSignatures.map((sig, idx) => (
                      <SignatureBlockDisplay key={`provider-${idx}`} signature={sig} />
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Document Styles */}
      <style>{`
        .document-content h1 {
          font-size: 1.5rem;
          font-weight: 700;
          margin-bottom: 1rem;
          text-align: center;
        }
        .document-content h2 {
          font-size: 1.25rem;
          font-weight: 600;
          margin-top: 1.5rem;
          margin-bottom: 0.75rem;
          border-bottom: 1px solid #e5e7eb;
          padding-bottom: 0.25rem;
        }
        .document-content h3 {
          font-size: 1rem;
          font-weight: 600;
          margin-top: 1rem;
          margin-bottom: 0.5rem;
        }
        .document-content p {
          margin-bottom: 0.75rem;
        }
        .document-content ul, .document-content ol {
          margin-left: 1.5rem;
          margin-bottom: 0.75rem;
        }
        .document-content li {
          margin-bottom: 0.25rem;
        }
        .document-content table {
          width: 100%;
          border-collapse: collapse;
          margin: 1rem 0;
        }
        .document-content th, .document-content td {
          border: 1px solid #e5e7eb;
          padding: 0.5rem;
          text-align: left;
        }
        .document-content th {
          background-color: #f9fafb;
          font-weight: 600;
        }
        .document-content .placeholder {
          background-color: #fef3c7;
          padding: 0 0.25rem;
          border-radius: 0.125rem;
        }
      `}</style>
    </div>
  );
};

export default DocumentPreview;
