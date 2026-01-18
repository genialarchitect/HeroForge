import axios from 'axios';
import type {
  LegalDocumentTemplate,
  LegalDocument,
  DocumentListItem,
  DocumentDetail,
  DocumentStats,
  PlaceholderInfo,
  SigningData,
  CreateTemplateRequest,
  UpdateTemplateRequest,
  CreateDocumentRequest,
  UpdateDocumentRequest,
  AddSignatureRequest,
  SendForSignatureRequest,
  SubmitSignatureRequest,
  DeclineSignatureRequest,
  VoidDocumentRequest,
  LegalDocumentSignature,
} from '../types/legal';

const API_BASE = '/api';

// Get auth header from localStorage
const getAuthHeader = () => {
  const token = localStorage.getItem('token');
  return token ? { Authorization: `Bearer ${token}` } : {};
};

// ============================================================================
// Template Endpoints
// ============================================================================

export const templatesApi = {
  list: async (): Promise<LegalDocumentTemplate[]> => {
    const response = await axios.get(`${API_BASE}/legal/templates`, {
      headers: getAuthHeader(),
    });
    return response.data;
  },

  get: async (id: string): Promise<LegalDocumentTemplate> => {
    const response = await axios.get(`${API_BASE}/legal/templates/${id}`, {
      headers: getAuthHeader(),
    });
    return response.data;
  },

  create: async (data: CreateTemplateRequest): Promise<LegalDocumentTemplate> => {
    const response = await axios.post(`${API_BASE}/legal/templates`, data, {
      headers: getAuthHeader(),
    });
    return response.data;
  },

  update: async (id: string, data: UpdateTemplateRequest): Promise<LegalDocumentTemplate> => {
    const response = await axios.put(`${API_BASE}/legal/templates/${id}`, data, {
      headers: getAuthHeader(),
    });
    return response.data;
  },

  delete: async (id: string): Promise<void> => {
    await axios.delete(`${API_BASE}/legal/templates/${id}`, {
      headers: getAuthHeader(),
    });
  },
};

// ============================================================================
// Document Endpoints
// ============================================================================

export const documentsApi = {
  list: async (status?: string): Promise<DocumentListItem[]> => {
    const params = status ? { status } : {};
    const response = await axios.get(`${API_BASE}/legal/documents`, {
      headers: getAuthHeader(),
      params,
    });
    return response.data;
  },

  getStats: async (): Promise<DocumentStats> => {
    const response = await axios.get(`${API_BASE}/legal/documents/stats`, {
      headers: getAuthHeader(),
    });
    return response.data;
  },

  get: async (id: string): Promise<DocumentDetail> => {
    const response = await axios.get(`${API_BASE}/legal/documents/${id}`, {
      headers: getAuthHeader(),
    });
    return response.data;
  },

  create: async (data: CreateDocumentRequest): Promise<LegalDocument> => {
    const response = await axios.post(`${API_BASE}/legal/documents`, data, {
      headers: getAuthHeader(),
    });
    return response.data;
  },

  update: async (id: string, data: UpdateDocumentRequest): Promise<LegalDocument> => {
    const response = await axios.put(`${API_BASE}/legal/documents/${id}`, data, {
      headers: getAuthHeader(),
    });
    return response.data;
  },

  delete: async (id: string): Promise<void> => {
    await axios.delete(`${API_BASE}/legal/documents/${id}`, {
      headers: getAuthHeader(),
    });
  },

  void: async (id: string, data: VoidDocumentRequest): Promise<void> => {
    await axios.post(`${API_BASE}/legal/documents/${id}/void`, data, {
      headers: getAuthHeader(),
    });
  },

  // Signature management
  addSignature: async (documentId: string, data: AddSignatureRequest): Promise<LegalDocumentSignature> => {
    const response = await axios.post(`${API_BASE}/legal/documents/${documentId}/signatures`, data, {
      headers: getAuthHeader(),
    });
    return response.data;
  },

  removeSignature: async (documentId: string, signatureId: string): Promise<void> => {
    await axios.delete(`${API_BASE}/legal/documents/${documentId}/signatures/${signatureId}`, {
      headers: getAuthHeader(),
    });
  },

  // Sending and reminders
  sendForSignature: async (id: string, data?: SendForSignatureRequest): Promise<{ status: string; signing_url: string; token: string }> => {
    const response = await axios.post(`${API_BASE}/legal/documents/${id}/send`, data || {}, {
      headers: getAuthHeader(),
    });
    return response.data;
  },

  sendReminder: async (id: string): Promise<{ reminders_sent: number }> => {
    const response = await axios.post(`${API_BASE}/legal/documents/${id}/remind`, {}, {
      headers: getAuthHeader(),
    });
    return response.data;
  },

  // PDF download
  downloadPdf: async (id: string): Promise<Blob> => {
    const response = await axios.get(`${API_BASE}/legal/documents/${id}/pdf`, {
      headers: getAuthHeader(),
      responseType: 'blob',
    });
    return response.data;
  },
};

// ============================================================================
// Placeholder Endpoints
// ============================================================================

export const placeholdersApi = {
  list: async (): Promise<PlaceholderInfo[]> => {
    const response = await axios.get(`${API_BASE}/legal/placeholders`, {
      headers: getAuthHeader(),
    });
    return response.data;
  },
};

// ============================================================================
// Public Signing Endpoints (No Auth)
// ============================================================================

export const signingApi = {
  getDocument: async (token: string, email: string): Promise<SigningData> => {
    const response = await axios.get(`${API_BASE}/legal/sign/${token}`, {
      params: { email },
    });
    return response.data;
  },

  submitSignature: async (token: string, data: SubmitSignatureRequest): Promise<{ status: string; document_status: string }> => {
    const response = await axios.post(`${API_BASE}/legal/sign/${token}`, data);
    return response.data;
  },

  declineSignature: async (token: string, data: DeclineSignatureRequest): Promise<{ status: string }> => {
    const response = await axios.post(`${API_BASE}/legal/sign/${token}/decline`, data);
    return response.data;
  },
};

// Combined export for convenience
export const legalApi = {
  templates: templatesApi,
  documents: documentsApi,
  placeholders: placeholdersApi,
  signing: signingApi,
};

export default legalApi;
