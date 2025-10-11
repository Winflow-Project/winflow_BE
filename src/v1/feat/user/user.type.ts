import { IAccount } from '@account/account.types';
import { AuthProvider } from '@auth/auth.type';
import { Document, Types } from 'mongoose';

export interface IUser {
  googleId?: string;
  firstName: string;
  lastName: string;
  password?: string;
  email: string;
  phone: {
    dialCode: string;
    number: number;
  };
  profileImg?: string;
  gender?: string;
  authProvider: AuthProvider;
  appRole: AppRoles;
  isVerified: boolean;
  reAuth?: boolean;
  interests?: string[];
  porfolio?: string[];
  skills?: string[];
  socials?: string[];
  account: IAccount;
  deletedAt?: Date;
  isAccountActive: boolean;
  lastLoginDate: Date;
  loginAttempts: number;
  allowedLoginAttempts: number;
  loginCooldown: Date;
  comparePassword: (candidatePassword: string) => Promise<boolean>;
}

export interface IUserDocument extends IUser, Document<Types.ObjectId> {
  isPasswordMatch(inputPassword: string): Promise<boolean>;
}

export enum AppRoles {
  SUPER_ADMIN = 'superAdmin',
  ADMIN = 'admin',
  USER = 'user',
  GUEST = 'guest',
}
