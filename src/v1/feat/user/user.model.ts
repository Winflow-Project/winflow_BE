import bcrypt from 'bcrypt';
import paginate from 'mongoose-paginate-v2';
import { PaginateModel, Schema, model } from 'mongoose';
import { Types } from 'mongoose';
import { IUser, IUserDocument, AppRoles } from './user.type';
import Config from '@config/dotenv.config';
import { ServerError } from '@middlewares/error.middleware';

const userSchema = new Schema<IUserDocument>(
  {
    email: { type: String, required: true, unique: true, index: true },
    firstName: { type: String, default: '' },
    lastName: { type: String, default: '' },
    password: { type: String, default: '' },
    phone: {
      dialCode: { type: String },
      number: { type: Number },
    },
    appRole: { type: String, enum: AppRoles, default: AppRoles.USER },
    reAuth: { type: Boolean, default: false },
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
  const user = this;
  if (user.isModified('password')) {
    user.password = await bcrypt.hash(user.password, Config.BcryptSalt);
  }
  next();
});

const comparePassword = async (password: string, hashedPassword: string) => {
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
