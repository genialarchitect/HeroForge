import React, { useState } from 'react';
import { Plus, Trash2, GripVertical, User, Building } from 'lucide-react';
import type { LegalDocumentSignature, SignerType, AddSignatureRequest } from '../../types/legal';

interface SignerConfig {
  id?: string;
  signerType: SignerType;
  signerRole: string;
  signerEmail: string;
  signatureOrder: number;
}

interface SignatureBlockConfigProps {
  signatures: LegalDocumentSignature[];
  onAdd: (signer: AddSignatureRequest) => Promise<void>;
  onRemove: (signatureId: string) => Promise<void>;
  isEditable?: boolean;
  className?: string;
}

const COMMON_ROLES = {
  client: ['Authorized Representative', 'CEO', 'CTO', 'CISO', 'Legal Counsel', 'IT Director', 'Security Manager'],
  provider: ['Security Consultant', 'Project Lead', 'Account Manager', 'Technical Director'],
};

const SignatureBlockConfig: React.FC<SignatureBlockConfigProps> = ({
  signatures,
  onAdd,
  onRemove,
  isEditable = true,
  className = '',
}) => {
  const [isAddingClient, setIsAddingClient] = useState(false);
  const [isAddingProvider, setIsAddingProvider] = useState(false);
  const [newSigner, setNewSigner] = useState<Partial<SignerConfig>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errors, setErrors] = useState<{ role?: string; email?: string }>({});

  const clientSignatures = signatures.filter((s) => s.signer_type === 'client');
  const providerSignatures = signatures.filter((s) => s.signer_type === 'provider');

  const validateSigner = (): boolean => {
    const newErrors: { role?: string; email?: string } = {};

    if (!newSigner.signerRole?.trim()) {
      newErrors.role = 'Role is required';
    }

    if (!newSigner.signerEmail?.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newSigner.signerEmail)) {
      newErrors.email = 'Invalid email format';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleAddSigner = async (type: SignerType) => {
    if (!validateSigner()) return;

    setIsSubmitting(true);
    try {
      const order = type === 'client' ? clientSignatures.length + 1 : providerSignatures.length + 1;
      await onAdd({
        signer_type: type,
        signer_role: newSigner.signerRole!.trim(),
        signer_email: newSigner.signerEmail!.trim(),
        signature_order: order,
      });
      setNewSigner({});
      setIsAddingClient(false);
      setIsAddingProvider(false);
      setErrors({});
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRemove = async (signatureId: string) => {
    if (confirm('Are you sure you want to remove this signer?')) {
      await onRemove(signatureId);
    }
  };

  const renderSignerForm = (type: SignerType) => (
    <div className="bg-gray-700/50 rounded-lg p-4 mt-3">
      <div className="space-y-3">
        <div>
          <label className="block text-xs font-medium text-gray-400 mb-1">Role</label>
          <div className="flex gap-2">
            <select
              value={newSigner.signerRole || ''}
              onChange={(e) => {
                setNewSigner({ ...newSigner, signerRole: e.target.value });
                setErrors((prev) => ({ ...prev, role: undefined }));
              }}
              className={`flex-1 px-3 py-2 bg-gray-700 border rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 ${
                errors.role ? 'border-red-500' : 'border-gray-600'
              }`}
            >
              <option value="">Select or type a role...</option>
              {COMMON_ROLES[type].map((role) => (
                <option key={role} value={role}>
                  {role}
                </option>
              ))}
            </select>
          </div>
          <input
            type="text"
            value={newSigner.signerRole || ''}
            onChange={(e) => {
              setNewSigner({ ...newSigner, signerRole: e.target.value });
              setErrors((prev) => ({ ...prev, role: undefined }));
            }}
            placeholder="Or enter custom role"
            className={`mt-2 w-full px-3 py-2 bg-gray-700 border rounded-lg text-sm text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 ${
              errors.role ? 'border-red-500' : 'border-gray-600'
            }`}
          />
          {errors.role && <p className="mt-1 text-xs text-red-400">{errors.role}</p>}
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-400 mb-1">Email</label>
          <input
            type="email"
            value={newSigner.signerEmail || ''}
            onChange={(e) => {
              setNewSigner({ ...newSigner, signerEmail: e.target.value });
              setErrors((prev) => ({ ...prev, email: undefined }));
            }}
            placeholder="signer@example.com"
            className={`w-full px-3 py-2 bg-gray-700 border rounded-lg text-sm text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 ${
              errors.email ? 'border-red-500' : 'border-gray-600'
            }`}
          />
          {errors.email && <p className="mt-1 text-xs text-red-400">{errors.email}</p>}
        </div>

        <div className="flex items-center gap-2 pt-2">
          <button
            type="button"
            onClick={() => handleAddSigner(type)}
            disabled={isSubmitting}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
          >
            {isSubmitting ? 'Adding...' : 'Add Signer'}
          </button>
          <button
            type="button"
            onClick={() => {
              type === 'client' ? setIsAddingClient(false) : setIsAddingProvider(false);
              setNewSigner({});
              setErrors({});
            }}
            className="px-4 py-2 text-gray-400 hover:text-white text-sm transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );

  const renderSignerList = (signers: LegalDocumentSignature[], type: SignerType) => (
    <div className="space-y-2">
      {signers.map((signer, index) => (
        <div
          key={signer.id}
          className="flex items-center gap-3 p-3 bg-gray-700/30 rounded-lg group"
        >
          <div className="text-gray-500">
            <GripVertical className="w-4 h-4" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-white">{signer.signer_role}</span>
              <span
                className={`text-xs px-2 py-0.5 rounded ${
                  signer.status === 'signed'
                    ? 'bg-green-900/50 text-green-400'
                    : signer.status === 'declined'
                    ? 'bg-red-900/50 text-red-400'
                    : 'bg-yellow-900/50 text-yellow-400'
                }`}
              >
                {signer.status}
              </span>
            </div>
            <p className="text-xs text-gray-400 truncate">{signer.signer_email}</p>
          </div>
          {isEditable && signer.status === 'pending' && (
            <button
              type="button"
              onClick={() => handleRemove(signer.id)}
              className="p-1.5 text-gray-500 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-all"
              title="Remove signer"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          )}
        </div>
      ))}

      {signers.length === 0 && (
        <p className="text-sm text-gray-500 text-center py-4">No {type} signers added</p>
      )}
    </div>
  );

  return (
    <div className={`bg-gray-800 rounded-lg p-6 ${className}`}>
      <h3 className="text-lg font-semibold text-white mb-6">Signature Configuration</h3>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Client Signers */}
        <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <User className="w-5 h-5 text-blue-400" />
              <h4 className="font-medium text-white">Client Signers</h4>
              <span className="text-xs text-gray-500">({clientSignatures.length})</span>
            </div>
            {isEditable && !isAddingClient && (
              <button
                type="button"
                onClick={() => {
                  setIsAddingClient(true);
                  setIsAddingProvider(false);
                  setNewSigner({});
                }}
                className="flex items-center gap-1 text-sm text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                <Plus className="w-4 h-4" />
                Add
              </button>
            )}
          </div>

          {renderSignerList(clientSignatures, 'client')}
          {isAddingClient && renderSignerForm('client')}
        </div>

        {/* Provider Signers */}
        <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Building className="w-5 h-5 text-purple-400" />
              <h4 className="font-medium text-white">Provider Signers</h4>
              <span className="text-xs text-gray-500">({providerSignatures.length})</span>
            </div>
            {isEditable && !isAddingProvider && (
              <button
                type="button"
                onClick={() => {
                  setIsAddingProvider(true);
                  setIsAddingClient(false);
                  setNewSigner({});
                }}
                className="flex items-center gap-1 text-sm text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                <Plus className="w-4 h-4" />
                Add
              </button>
            )}
          </div>

          {renderSignerList(providerSignatures, 'provider')}
          {isAddingProvider && renderSignerForm('provider')}
        </div>
      </div>

      {/* Help Text */}
      <p className="mt-4 text-xs text-gray-500">
        Add signers from both the client and provider sides. Each signer will receive an email with a unique signing link.
        Signatures are collected in the order displayed.
      </p>
    </div>
  );
};

export default SignatureBlockConfig;
