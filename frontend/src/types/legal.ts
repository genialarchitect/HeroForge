// Legal Documents Types

export type DocumentType = 'roe' | 'ato' | 'nda' | 'sow' | 'msa';

export type DocumentStatus =
  | 'draft'
  | 'pending_signature'
  | 'partially_signed'
  | 'fully_signed'
  | 'voided';

export type SignatureStatus = 'pending' | 'signed' | 'declined';

export type SignerType = 'client' | 'provider';

export interface LegalDocumentTemplate {
  id: string;
  name: string;
  document_type: string;
  description: string | null;
  content_html: string;
  is_system: boolean;
  user_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface LegalDocument {
  id: string;
  template_id: string | null;
  engagement_id: string;
  customer_id: string;
  document_type: string;
  name: string;
  content_html: string;
  status: DocumentStatus;
  signature_token: string | null;
  signature_token_expires_at: string | null;
  final_pdf_path: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface LegalDocumentSignature {
  id: string;
  document_id: string;
  signer_type: SignerType;
  signer_role: string;
  signer_name: string | null;
  signer_email: string;
  status: SignatureStatus;
  signed_at: string | null;
  signed_ip: string | null;
  signature_image: string | null;
  decline_reason: string | null;
  signature_order: number;
}

export interface LegalDocumentHistory {
  id: string;
  document_id: string;
  action: string;
  actor_email: string | null;
  ip_address: string | null;
  details: string | null;
  created_at: string;
}

export interface DocumentListItem {
  id: string;
  name: string;
  document_type: string;
  status: DocumentStatus;
  customer_name: string;
  engagement_name: string;
  created_at: string;
  updated_at: string;
  signature_count: number;
  signed_count: number;
}

export interface DocumentDetail {
  document: LegalDocument;
  signatures: LegalDocumentSignature[];
  history: LegalDocumentHistory[];
}

export interface DocumentStats {
  draft: number;
  pending_signature: number;
  partially_signed: number;
  fully_signed: number;
  voided: number;
}

export interface PlaceholderInfo {
  key: string;
  description: string;
  source: string;
  example: string;
}

export interface SigningData {
  document_id: string;
  document_name: string;
  document_type: string;
  content_html: string;
  signer_email: string;
  signer_role: string;
  signer_type: SignerType;
  customer_name: string;
  engagement_name: string;
  all_signatures: SignatureInfo[];
}

export interface SignatureInfo {
  signer_type: SignerType;
  signer_role: string;
  signer_name: string | null;
  signer_email: string;
  status: SignatureStatus;
  signed_at: string | null;
}

// Request Types

export interface CreateTemplateRequest {
  name: string;
  document_type: DocumentType;
  description?: string;
  content_html: string;
}

export interface UpdateTemplateRequest {
  name?: string;
  description?: string;
  content_html?: string;
}

export interface CreateDocumentRequest {
  template_id?: string;
  engagement_id: string;
  customer_id: string;
  document_type: DocumentType;
  name: string;
  content_html?: string;
}

export interface UpdateDocumentRequest {
  name?: string;
  content_html?: string;
}

export interface AddSignatureRequest {
  signer_type: SignerType;
  signer_role: string;
  signer_email: string;
  signature_order?: number;
}

export interface SendForSignatureRequest {
  message?: string;
}

export interface SubmitSignatureRequest {
  signer_email: string;
  signer_name: string;
  signature_image: string;
  acknowledgment: boolean;
}

export interface DeclineSignatureRequest {
  signer_email: string;
  reason: string;
}

export interface VoidDocumentRequest {
  reason: string;
}

// Helper function to get document type display name
export function getDocumentTypeLabel(type: string): string {
  const labels: Record<string, string> = {
    roe: 'Rules of Engagement',
    ato: 'Authorization to Test',
    nda: 'Non-Disclosure Agreement',
    sow: 'Statement of Work',
    msa: 'Master Service Agreement',
  };
  return labels[type] || type.toUpperCase();
}

// Helper function to get status display label and color
export function getStatusConfig(status: DocumentStatus): { label: string; color: string } {
  const configs: Record<DocumentStatus, { label: string; color: string }> = {
    draft: { label: 'Draft', color: 'bg-gray-100 text-gray-800' },
    pending_signature: { label: 'Pending Signature', color: 'bg-yellow-100 text-yellow-800' },
    partially_signed: { label: 'Partially Signed', color: 'bg-blue-100 text-blue-800' },
    fully_signed: { label: 'Fully Signed', color: 'bg-green-100 text-green-800' },
    voided: { label: 'Voided', color: 'bg-red-100 text-red-800' },
  };
  return configs[status] || { label: status, color: 'bg-gray-100 text-gray-800' };
}

// Helper function to get signature status config
export function getSignatureStatusConfig(status: SignatureStatus): { label: string; color: string } {
  const configs: Record<SignatureStatus, { label: string; color: string }> = {
    pending: { label: 'Pending', color: 'text-yellow-600' },
    signed: { label: 'Signed', color: 'text-green-600' },
    declined: { label: 'Declined', color: 'text-red-600' },
  };
  return configs[status] || { label: status, color: 'text-gray-600' };
}
