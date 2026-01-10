// ============================================================================
// Authentication Types - User, Login, Registration, MFA
// ============================================================================

import type { UserRole } from './common';

export interface User {
  id: string;
  username: string;
  email: string;
  roles?: UserRole[]; // Added for admin console
  is_active?: boolean; // Added for admin console
  created_at?: string;
  mfa_enabled?: boolean; // MFA/TOTP enabled status
  is_locked?: boolean; // Account lockout status
  locked_until?: string; // Lockout expiration time
  failed_attempts?: number; // Number of failed login attempts
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  first_name?: string;
  last_name?: string;
  accept_terms: boolean;
}

export interface LoginResponse {
  token: string;
  user: User;
}

// Profile Types

export interface UpdateProfileRequest {
  email?: string;
}

export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
}

// MFA Types

export interface MfaSetupResponse {
  secret: string;
  qr_code_url: string;
  recovery_codes: string[];
}

export interface MfaVerifySetupRequest {
  totp_code: string;
}

export interface MfaDisableRequest {
  password: string;
  totp_code?: string;
  recovery_code?: string;
}

export interface MfaRegenerateRecoveryCodesRequest {
  password: string;
  totp_code: string;
}

export interface MfaRegenerateRecoveryCodesResponse {
  recovery_codes: string[];
}

export interface MfaVerifyRequest {
  mfa_token: string;
  totp_code?: string;
  recovery_code?: string;
}

export interface MfaLoginResponse extends LoginResponse {
  mfa_required?: boolean;
  mfa_token?: string;
}
