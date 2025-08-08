import crypto from 'crypto';
import bcrypt from 'bcryptjs';
export const generateOTP = (): string => {
  return crypto.randomInt(1000, 10000).toString();
};

export const verifyOTP = (otp: string, hashedOTP: string): boolean => {
  return bcrypt.compareSync(otp, hashedOTP);
};
