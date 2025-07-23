import { Schema, model } from 'mongoose';
import { ILoginAttempt, IToken, TokenType } from './auth.type';

// used for password reset
const tokenSchema = new Schema<IToken>({
  userId: {
    type: Schema.Types.ObjectId,
    required: true,
    ref: 'User',
  },
  token: {
    type: String,
    required: true,
  },
  tokenType: {
    type: String,
    required: true,
    enum: Object.values(TokenType),
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 1800, // 30 minutes in seconds
  },
});

export const TokenModel = model('Token', tokenSchema);

const LoginAttemptSchema: Schema = new Schema<ILoginAttempt>({
  email: { type: String, required: true },
  success: { type: Boolean, required: true },
  timestamp: { type: Date, default: Date.now },
  ipAddress: { type: String, required: true },
});

export const LoginAttempt = model<ILoginAttempt>(
  'LoginAttempt',
  LoginAttemptSchema
);
