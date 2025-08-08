import bcrypt from 'bcrypt';
import paginate from 'mongoose-paginate-v2';
import { PaginateModel, Schema, model } from 'mongoose';
import { Types } from 'mongoose';
import { IUser, IUserDocument, AppRoles } from './user.type';
import Config from '@config/dotenv.config';
import { ServerError } from '@middlewares/error.middleware';
import { AuthProvider } from '@auth/auth.type';
const userSchema = new Schema<IUserDocument>(
  {
    googleId: { type: String, default: null },
    firstName: { type: String, default: null },
    lastName: { type: String, default: null },
    email: { type: String, required: true, unique: true, index: true },
    password: { type: String, default: null },
    phone: {
      dialCode: { type: String },
      number: { type: Number },
    },
    profileImg: { type: String, default: null },
    gender: { type: String, default: null },
    authProvider: {
      type: String,
      enum: Object.values(AuthProvider),
      default: AuthProvider.LOCAL,
    },
    appRole: { type: String, enum: AppRoles, default: AppRoles.USER },
    reAuth: { type: Boolean, default: false },
    interests: { type: [String], default: [] },
    deletedAt: { type: Date, default: null },
    isVerified: { type: Boolean, default: false },
    isAccountActive: { type: Boolean, default: true },
    lastLoginDate: { type: Date, default: null },
    loginAttempts: { type: Number, default: 0 },
    allowedLoginAttempts: { type: Number, default: 3 },
    loginCooldown: { type: Date },
  },
  { timestamps: true }
);

userSchema.pre('save', async function (next) {
  const user = this as IUserDocument;
  if (user.isModified('password') && user.password) {
    user.password = await bcrypt.hash(user.password, Config.BcryptSalt);
  }
  next();
});

const comparePassword = async (
  password: string,
  hashedPassword?: string | null
) => {
  if (!hashedPassword) return false;
  return await bcrypt.compare(password, hashedPassword);
};

userSchema.methods.isPasswordMatch = async function (inputPassword: string) {
  return await comparePassword(inputPassword, this.password);
};

userSchema.methods.comparePassword = async function (
  candidatePassword: string
): Promise<boolean> {
  try {
    const user = this as IUser;
    if (!user.password) return false;
    return bcrypt.compare(candidatePassword, user.password);
  } catch (error: any) {
    throw new ServerError('Error comparing password', error);
  }
};

userSchema.methods.toJSON = function () {
  const user = this.toObject();
  delete user.password;
  delete user.__v;
  delete user.deletedAt;
  // delete user.createdAt;
  // delete user.updatedAt;
  return user;
};

userSchema.plugin(paginate);

export const UserModel = model<IUserDocument, PaginateModel<IUserDocument>>(
  'User',
  userSchema
);
export { IUserDocument };
