import { Document, Types } from 'mongoose';

export interface IUser {
  firstName: string;
  lastName: string;
  password: string;
  email: string;
  phone: {
    dialCode: string;
    number: number;
  };
  appRole: AppRoles;
  isVerified: boolean;
  reAuth?: boolean;
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
