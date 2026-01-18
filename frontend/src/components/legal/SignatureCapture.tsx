import React, { useRef, useState } from 'react';
import { Eraser, Check } from 'lucide-react';
import SignaturePad, { SignaturePadRef } from './SignaturePad';

interface SignatureCaptureProps {
  signerRole: string;
  signerEmail: string;
  onSubmit: (data: { signerName: string; signatureImage: string; acknowledgment: boolean }) => void;
  onDecline?: (reason: string) => void;
  isSubmitting?: boolean;
  className?: string;
}

const SignatureCapture: React.FC<SignatureCaptureProps> = ({
  signerRole,
  signerEmail,
  onSubmit,
  onDecline,
  isSubmitting = false,
  className = '',
}) => {
  const signaturePadRef = useRef<SignaturePadRef>(null);
  const [signerName, setSignerName] = useState('');
  const [acknowledgment, setAcknowledgment] = useState(false);
  const [signatureEmpty, setSignatureEmpty] = useState(true);
  const [showDeclineModal, setShowDeclineModal] = useState(false);
  const [declineReason, setDeclineReason] = useState('');
  const [errors, setErrors] = useState<{ name?: string; signature?: string; acknowledgment?: string }>({});

  const validateForm = (): boolean => {
    const newErrors: { name?: string; signature?: string; acknowledgment?: string } = {};

    if (!signerName.trim()) {
      newErrors.name = 'Please enter your legal name';
    } else if (signerName.trim().length < 2) {
      newErrors.name = 'Name must be at least 2 characters';
    }

    if (signatureEmpty) {
      newErrors.signature = 'Please draw your signature';
    }

    if (!acknowledgment) {
      newErrors.acknowledgment = 'You must acknowledge that this is a legally binding signature';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) return;

    const signatureImage = signaturePadRef.current?.toDataURL() || '';
    onSubmit({
      signerName: signerName.trim(),
      signatureImage,
      acknowledgment,
    });
  };

  const handleClear = () => {
    signaturePadRef.current?.clear();
    setSignatureEmpty(true);
    setErrors((prev) => ({ ...prev, signature: undefined }));
  };

  const handleDeclineSubmit = () => {
    if (!declineReason.trim()) return;
    onDecline?.(declineReason.trim());
    setShowDeclineModal(false);
  };

  return (
    <div className={`bg-gray-800 rounded-lg p-6 ${className}`}>
      <div className="mb-6">
        <h3 className="text-lg font-semibold text-white mb-2">Sign Document</h3>
        <p className="text-gray-400 text-sm">
          Signing as <span className="text-cyan-400">{signerRole}</span> ({signerEmail})
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Legal Name Input */}
        <div>
          <label htmlFor="signerName" className="block text-sm font-medium text-gray-300 mb-2">
            Full Legal Name <span className="text-red-400">*</span>
          </label>
          <input
            type="text"
            id="signerName"
            value={signerName}
            onChange={(e) => {
              setSignerName(e.target.value);
              setErrors((prev) => ({ ...prev, name: undefined }));
            }}
            className={`w-full px-4 py-2 bg-gray-700 border rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 ${
              errors.name ? 'border-red-500' : 'border-gray-600'
            }`}
            placeholder="Enter your full legal name"
            disabled={isSubmitting}
          />
          {errors.name && <p className="mt-1 text-sm text-red-400">{errors.name}</p>}
        </div>

        {/* Signature Pad */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="block text-sm font-medium text-gray-300">
              Signature <span className="text-red-400">*</span>
            </label>
            <button
              type="button"
              onClick={handleClear}
              className="flex items-center gap-1 text-sm text-gray-400 hover:text-white transition-colors"
              disabled={isSubmitting}
            >
              <Eraser className="w-4 h-4" />
              Clear
            </button>
          </div>
          <div
            className={`border rounded-lg overflow-hidden ${
              errors.signature ? 'border-red-500' : 'border-gray-600'
            }`}
          >
            <SignaturePad
              ref={signaturePadRef}
              width={500}
              height={150}
              penColor="#000000"
              backgroundColor="#ffffff"
              onChange={(isEmpty) => {
                setSignatureEmpty(isEmpty);
                if (!isEmpty) {
                  setErrors((prev) => ({ ...prev, signature: undefined }));
                }
              }}
            />
          </div>
          <p className="mt-1 text-xs text-gray-500">Draw your signature using your mouse or touchscreen</p>
          {errors.signature && <p className="mt-1 text-sm text-red-400">{errors.signature}</p>}
        </div>

        {/* Acknowledgment Checkbox */}
        <div>
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={acknowledgment}
              onChange={(e) => {
                setAcknowledgment(e.target.checked);
                setErrors((prev) => ({ ...prev, acknowledgment: undefined }));
              }}
              className="mt-1 w-4 h-4 rounded border-gray-600 bg-gray-700 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-gray-800"
              disabled={isSubmitting}
            />
            <span className="text-sm text-gray-300">
              I acknowledge that by clicking "Sign Document" I am agreeing to be legally bound by the terms of this
              document. My electronic signature has the same legal effect as a handwritten signature.
            </span>
          </label>
          {errors.acknowledgment && <p className="mt-1 text-sm text-red-400">{errors.acknowledgment}</p>}
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-4 pt-4 border-t border-gray-700">
          <button
            type="submit"
            disabled={isSubmitting}
            className="flex items-center gap-2 px-6 py-2 bg-cyan-600 hover:bg-cyan-700 text-white font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Check className="w-4 h-4" />
            {isSubmitting ? 'Signing...' : 'Sign Document'}
          </button>

          {onDecline && (
            <button
              type="button"
              onClick={() => setShowDeclineModal(true)}
              disabled={isSubmitting}
              className="px-6 py-2 text-gray-300 hover:text-white transition-colors disabled:opacity-50"
            >
              Decline to Sign
            </button>
          )}
        </div>
      </form>

      {/* Decline Modal */}
      {showDeclineModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4">
            <h4 className="text-lg font-semibold text-white mb-4">Decline to Sign</h4>
            <p className="text-gray-400 text-sm mb-4">
              Please provide a reason for declining to sign this document.
            </p>
            <textarea
              value={declineReason}
              onChange={(e) => setDeclineReason(e.target.value)}
              className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 resize-none"
              rows={3}
              placeholder="Enter your reason..."
            />
            <div className="flex items-center gap-3 mt-4">
              <button
                onClick={handleDeclineSubmit}
                disabled={!declineReason.trim()}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Confirm Decline
              </button>
              <button
                onClick={() => {
                  setShowDeclineModal(false);
                  setDeclineReason('');
                }}
                className="px-4 py-2 text-gray-300 hover:text-white transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SignatureCapture;
