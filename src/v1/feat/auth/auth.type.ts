import { Types } from 'mongoose';

export interface ISignin {
  email: string;
  password: string;
  rememberMe: boolean;
}

export interface ISignup {
  email: string;
  password: string;
}

export interface IVerifyEmail {
  email: string;
  otp: string;
}

export interface ISetPassword {
  email: string;
  password: string;
  // confirmPassword: string;
}

export enum TokenType {
  ACCESS = 'access',
  REFRESH = 'refresh',
  EMAIL_VERIFICATION = 'Email Verification',
  RESET_PASSWORD = 'Reset Password',
  INVITATION = 'Invitation',
}

export interface IToken {
  userId: Types.ObjectId;
  token: string;
  tokenType: TokenType;
  createdAt: Date;
}

export interface TokenPayload {
  sub: string;
  appRole: string;
  iat: number;
  exp: number;
  type: TokenType;
  rememberMe: boolean;
}

export interface ILoginAttempt extends Document {
  email: string;
  success: boolean;
  timestamp: Date;
  ipAddress: string;
}
