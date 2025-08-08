import bcrypt from 'bcryptjs';
import jwt, { SignOptions, JwtPayload } from 'jsonwebtoken';
import DotenvConfig from '@config/dotenv.config';
import {
  BadRequest,
  InvalidInput,
  ResourceNotFound,
  Unauthorized,
  TooManyRequests,
} from '@middlewares/error.middleware';
import {
  ISignup,
  TokenType,
  TokenPayload,
  ISignin,
  IVerifyEmail,
  IPersonaliseAccount,
} from './auth.type';
import { UserModel, IUserDocument } from '@user/user.model';
import { LoginAttempt, TokenModel } from './auth.model';
import { generateRandomHexString } from '@utils/crypto.utils';
import { generateOTP, verifyOTP } from '@utils/otp.utils';
import sendEmail from '@services/email/email.service';

import {
  personaliseAccountValidationSchema,
  signinValidationSchema,
  signupValidationSchema,
  userPasswordSchema,
  verifyOTPValidationSchema,
} from '@validations/auth.validations';
import { isValidObjectId } from 'mongoose';

export default class AuthService {
  private static JWT_OPTIONS: SignOptions = {
    issuer: DotenvConfig.JWTHeader.issuer,
    audience: DotenvConfig.JWTHeader.audience,
    algorithm: DotenvConfig.JWTHeader.algorithm,
  };

  static async signup(payload: ISignup): Promise<IUserDocument> {
    const { error } = signupValidationSchema.validate(payload);
    if (error) {
      const errorMessages: string[] = error.details.map(
        (detail) => detail.message
      );
      throw new InvalidInput(errorMessages.join(', '));
    }

    const existingUser = await UserModel.findOne({ email: payload.email });
    if (existingUser) throw new BadRequest('Email already exists');

    const otp = generateOTP();
    const hashedOTP = await bcrypt.hash(otp, DotenvConfig.BcryptSalt);

    const newUser = await UserModel.create(payload);

    const userId = newUser._id?.toHexString()!;

    await TokenModel.create({
      userId: userId,
      token: hashedOTP,
      tokenType: TokenType.EMAIL_VERIFICATION,
    });

    await sendEmail({
      to: payload.email,
      subject: 'Email Verification',
      templateName: 'email.verification',
      placeholders: {
        otp: otp,
        verification_page_url: `${DotenvConfig.frontendBaseURL}/verifyemail?id=${userId}&token=${otp}`,
      },
    });

    return newUser;
  }

  static async verifyEmail(payload: IVerifyEmail): Promise<void> {
    const { error } = verifyOTPValidationSchema.validate(payload);
    if (error) {
      const errorMessages: string[] = error.details.map(
        (detail) => detail.message
      );
      throw new InvalidInput(errorMessages.join(', '));
    }

    const user = await UserModel.findOne({ email: payload.email });
    if (!user) throw new ResourceNotFound('User not found');

    if (user.isVerified) throw new BadRequest('Email already verified');

    const existingToken = await TokenModel.findOne({
      userId: user._id,
      tokenType: TokenType.EMAIL_VERIFICATION,
    });
    if (!existingToken) throw new ResourceNotFound('OTP not found');

    const isTokenValid = verifyOTP(payload.otp, existingToken.token);
    if (!isTokenValid) throw new Unauthorized('Invalid or expired otp');

    user.isVerified = true;
    await user.save();

    await TokenModel.findByIdAndDelete(existingToken._id);
  }

  static async personaliseAccount(payload: IPersonaliseAccount): Promise<{
    accessToken: string;
    refreshToken: string;
    user: IUserDocument;
  }> {
    const { error } = personaliseAccountValidationSchema.validate(payload);
    if (error) {
      const errorMessages: string[] = error.details.map(
        (detail) => detail.message
      );
      throw new InvalidInput(errorMessages.join(', '));
    }

    const existingUser = await UserModel.findOne({ email: payload.email });
    if (!existingUser) throw new ResourceNotFound('User not found');

    if (!existingUser.isVerified)
      throw new Unauthorized('Email not verified. Please verify your email.');

    if (!existingUser.isAccountActive)
      throw new Unauthorized('Account is deactivated. Please contact support.');

    existingUser.gender = payload.gender;
    existingUser.interests = payload.interests || [];
    await existingUser.save();

    const { accessToken, refreshToken } =
      await this.generateTokens(existingUser);

    return { accessToken, refreshToken, user: existingUser };
  }

  static async signin(
    payload: ISignin,
    ipAddress: string
  ): Promise<{
    accessToken: string;
    refreshToken: string;
    user: IUserDocument;
  }> {
    const { error } = signinValidationSchema.validate(payload);
    if (error) {
      const errorMessages: string[] = error.details.map(
        (detail) => detail.message
      );
      throw new InvalidInput(errorMessages.join(', '));
    }
    const existingUser = await UserModel.findOne({ email: payload.email });
    if (!existingUser) {
      await this.logFailedAttempt(payload.email, ipAddress);
      throw new Unauthorized("Account doesn't exist");
    }

    if (!existingUser.password)
      throw new Unauthorized(
        'Account was created via Google. Use Google Sign-in.'
      );

    this.checkLoginCooldown(existingUser, ipAddress);

    const isPasswordValid = await existingUser.comparePassword(
      payload.password
    );
    if (!isPasswordValid) {
      await this.handleInvalidPassword(existingUser, payload.email, ipAddress);
    }

    if (!existingUser.isVerified)
      await this.handleUnverifiedAccount(existingUser);

    if (!existingUser.isAccountActive)
      await this.handleDeactivatedAccount(existingUser);

    await this.resetLoginAttempts(existingUser);

    const { accessToken, refreshToken } =
      await this.generateTokens(existingUser);

    await LoginAttempt.create({
      email: payload.email,
      success: true,
      ipAddress,
    });

    return { accessToken, refreshToken, user: existingUser };
  }

  static async forgotPassword(email: string) {
    const existingUser = await UserModel.findOne({ email });
    if (!existingUser)
      throw new ResourceNotFound('No account found with the provided email');

    if (!existingUser.isVerified)
      throw new Unauthorized(
        'Email not verified. Please verify your email before resetting password.'
      );

    if (!existingUser.isAccountActive)
      throw new Unauthorized('Account is deactivated. Please contact support.');

    const existingToken = await TokenModel.findOne({
      userId: existingUser.id,
    });
    if (existingToken) await TokenModel.findByIdAndDelete(existingToken._id);

    const resetToken = generateRandomHexString(32);
    const hashedToken = await bcrypt.hash(resetToken, DotenvConfig.BcryptSalt);

    const token = await TokenModel.create({
      userId: existingUser._id,
      token: hashedToken,
      tokenType: TokenType.RESET_PASSWORD,
    });

    const resetURL = `${DotenvConfig.frontendBaseURL}/resetpassword?id=${token._id}&token=${resetToken}`;

    await sendEmail({
      to: email,
      subject: 'Password Reset',
      templateName: 'forgot.password',
      placeholders: {
        name: existingUser.firstName,
        email: existingUser.email,
        reset_link: resetURL,
      },
    });
  }

  static async resetPassword(
    token: string,
    tokenId: string,
    password: string
  ): Promise<void> {
    if (!(token && password && tokenId)) {
      throw new BadRequest('token, id and password are required');
    }

    if (!isValidObjectId(tokenId)) {
      throw new BadRequest('Invalid token Id');
    }

    const existingToken = await TokenModel.findById(tokenId);
    if (!existingToken) {
      throw new Unauthorized('Reset token not found or expired');
    }

    const tokenMatch = await bcrypt.compare(token, existingToken.token);
    if (!tokenMatch) {
      throw new Unauthorized('Invalid or expired token');
    }

    const { error: passwordError } = userPasswordSchema.validate(password);
    if (passwordError) {
      throw new InvalidInput('Invalid input', {
        message: passwordError.message,
      });
    }

    const user = await UserModel.findById(existingToken.userId);
    if (!user) {
      throw new ResourceNotFound(
        'User associated with this token was not found'
      );
    }

    if (!user.isVerified) throw new Unauthorized('Account is not verified');

    if (!user.isAccountActive) throw new Unauthorized('Account is deactivated');

    user.password = password;
    await user.save();

    await TokenModel.findByIdAndDelete(tokenId);
  }

  static async handleGoogleCallback(user: IUserDocument): Promise<{
    accessToken: string;
    refreshToken: string;
    user: IUserDocument;
    isNewUser: boolean;
  }> {
    const isNewUser = !user.gender || !user.interests?.length;

    const { accessToken, refreshToken } =
      await AuthService['generateTokens'](user);

    user.lastLoginDate = new Date();
    if (user.reAuth) user.reAuth = false;
    await user.save();

    return {
      accessToken,
      refreshToken,
      user,
      isNewUser,
    };
  }

  static async linkGoogleAccount(
    userId: IUserDocument['_id'],
    googleId: string
  ): Promise<void> {
    const user = await UserModel.findById(userId);
    if (!user) throw new ResourceNotFound('User not found');

    // Check if Google ID is already linked to another account
    const existingGoogleUser = await UserModel.findOne({ googleId });
    if (existingGoogleUser && existingGoogleUser.id !== userId)
      throw new BadRequest(
        'This Google account is already linked to another user'
      );

    user.googleId = googleId;
    await user.save();
  }

  private static async logFailedAttempt(email: string, ipAddress: string) {
    await LoginAttempt.create({ email, success: false, ipAddress });
  }

  private static checkLoginCooldown(user: IUserDocument, ipAddress: string) {
    if (user.loginCooldown && Date.now() < user.loginCooldown.getTime()) {
      this.logFailedAttempt(user.email, ipAddress);
      throw new TooManyRequests(
        `Account locked due to multiple failed login attempts. Try again after ${user.loginCooldown}`,
        { cooldown: user.loginCooldown }
      );
    }
  }

  private static async handleInvalidPassword(
    user: IUserDocument,
    email: string,
    ipAddress: string
  ) {
    user.loginAttempts += 1;

    if (user.loginAttempts >= user.allowedLoginAttempts) {
      user.loginCooldown = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
      user.loginAttempts = 0;

      await user.save();
      throw new TooManyRequests(
        `Account locked due to multiple failed login attempts. Try again after ${user.loginCooldown}`
      );
    }

    await user.save();
    this.logFailedAttempt(email, ipAddress);
    throw new Unauthorized(
      `Invalid credentials. ${user.allowedLoginAttempts - user.loginAttempts} attempt(s) remaining`
    );
  }

  private static async handleUnverifiedAccount(user: IUserDocument) {
    const verifyToken = generateRandomHexString(32);
    const hashedToken = await bcrypt.hash(verifyToken, DotenvConfig.BcryptSalt);

    const token = await TokenModel.create({
      userId: user.id,
      token: hashedToken,
      tokenType: TokenType.EMAIL_VERIFICATION,
    });

    // const verifyURL = `${DotenvConfig.frontendBaseURL}/verifyemail?id=${token._id}&token=${verifyToken}`;
    // await EmailService.sendMailTemplate('verifyEmailTemplate', user.email, { username: user.firstName, link: verifyURL });

    throw new Unauthorized(
      `Account not verified. A verification link has been sent to ${user.email}.`
    );
  }

  private static async handleDeactivatedAccount(user: IUserDocument) {
    if (!user.isAccountActive) throw new Unauthorized('Account is deactivated');
  }

  private static async resetLoginAttempts(user: IUserDocument) {
    user.loginAttempts = 0;
    user.lastLoginDate = new Date();
    if (user.reAuth) user.reAuth = false;
    await user.save();
  }

  private static async generateTokens(user: IUserDocument) {
    const accessTokenPayload: TokenPayload = {
      sub: user.id,
      appRole: user.appRole,
      iat: Date.now(),
      exp: Date.now() + DotenvConfig.TokenExpiry.accessToken,
      type: TokenType.ACCESS,
      rememberMe: false,
    };

    const refreshTokenPayload: TokenPayload = {
      sub: user.id,
      appRole: user.appRole,
      iat: Date.now(),
      exp: Date.now() + DotenvConfig.TokenExpiry.refreshToken,
      type: TokenType.REFRESH,
      rememberMe: false,
    };

    const accessToken = this.generateJWT(
      accessTokenPayload,
      DotenvConfig.JWTHeader.accessTokenSecret
    );
    const refreshToken = this.generateJWT(
      refreshTokenPayload,
      DotenvConfig.JWTHeader.refreshTokenSecret
    );

    return { accessToken, refreshToken };
  }

  private static async generateAccessToken(
    userId: string,
    appRole: string,
    rememberMe: boolean
  ): Promise<string> {
    const payload: TokenPayload = {
      sub: userId,
      appRole,
      iat: Date.now(),
      exp: Date.now() + DotenvConfig.TokenExpiry.accessToken,
      type: TokenType.ACCESS,
      rememberMe,
    };

    return this.generateJWT(payload, DotenvConfig.JWTHeader.accessTokenSecret);
  }

  private static async generateRefreshToken(
    userId: string,
    appRole: string,
    rememberMe: boolean
  ): Promise<string> {
    const exp = rememberMe
      ? DotenvConfig.TokenExpiry.rememberMe
      : DotenvConfig.TokenExpiry.refreshToken;
    const payload: TokenPayload = {
      sub: userId,
      appRole,
      iat: Date.now(),
      exp: Date.now() + exp,
      type: TokenType.REFRESH,
      rememberMe,
    };

    return this.generateJWT(payload, DotenvConfig.JWTHeader.refreshTokenSecret);
  }

  private static generateJWT(payload: TokenPayload, secret: string): string {
    return jwt.sign(payload, secret, this.JWT_OPTIONS);
  }

  static async verifyJWT(token: string, type: TokenType): Promise<JwtPayload> {
    const secret =
      type === TokenType.REFRESH
        ? DotenvConfig.JWTHeader.refreshTokenSecret
        : DotenvConfig.JWTHeader.accessTokenSecret;

    try {
      const verifyOptions = {
        issuer: DotenvConfig.JWTHeader.issuer,
        audience: Array.isArray(DotenvConfig.JWTHeader.audience)
          ? DotenvConfig.JWTHeader.audience.length === 1
            ? DotenvConfig.JWTHeader.audience[0]
            : DotenvConfig.JWTHeader.audience
          : DotenvConfig.JWTHeader.audience,
        algorithms: [DotenvConfig.JWTHeader.algorithm],
      };
      const decoded = jwt.verify(token, secret, verifyOptions) as JwtPayload;
      return decoded;
    } catch (error: any) {
      this.handleTokenError(error);
      throw new Unauthorized('Invalid or expired token');
    }
  }

  private static handleTokenError(error: any) {
    if (error.name === 'TokenExpiredError') {
      throw new Unauthorized('Token has expired');
    } else if (error.name === 'JsonWebTokenError') {
      throw new Unauthorized('Invalid token');
    } else {
      throw new Unauthorized('Authentication failed');
    }
  }

  //   static async refreshToken(token: string) {
  //     const decoded = await this.verifyJWT(token, TokenType.REFRESH);

  //     const accessToken = await this.generateAccessToken(
  //       decoded.sub!,
  //       decoded.role,
  //       decoded.rememberMe
  //     );

  //     const refreshToken = await this.generateRefreshToken(
  //       decoded.sub!,
  //       decoded.appRole,
  //       decoded.rememberMe
  //     );

  //     return { accessToken, refreshToken };
  //   }
}
