import { Request, Response, NextFunction } from 'express';
import AuthService from './auth.service';
import { InvalidInput, Unauthorized } from '@middlewares/error.middleware';
import passport from '@config/passport.config';
import DotenvConfig from '@config/dotenv.config';
export default class AuthController {
  static async signup(req: Request, res: Response, next: NextFunction) {
    try {
      const payload = req.body;

      await AuthService.signup(payload);

      res.status(201).json({
        success: true,
        message:
          'User created successfully. A verification email has been sent to your email address. ',
      });
    } catch (error) {
      next(error);
    }
  }

  static async verifyEmail(req: Request, res: Response, next: NextFunction) {
    try {
      const payload = req.body;

      await AuthService.verifyEmail(payload);

      res.status(200).json({
        success: true,
        message: 'Email verified successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async signin(req: Request, res: Response, next: NextFunction) {
    try {
      let { email, password, rememberMe, deviceToken, deviceType } = req.body;

      const { accessToken, refreshToken, user } = await AuthService.signin(
        {
          email,
          password,
          rememberMe,
        },
        req.ip as string
        // deviceToken as string,
        // deviceType as deviceType
      );

      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('at', accessToken);
      res.setHeader('rt', refreshToken);

      res.status(200).json({
        success: true,
        message: 'Signin successful',
        accessToken,
        refreshToken,
        user,
      });
    } catch (error) {
      next(error);
    }
  }

  static async personaliseAccount(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    try {
      let { email, gender, interests } = req.body;

      const { accessToken, refreshToken, user } =
        await AuthService.personaliseAccount({ email, gender, interests });

      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('at', accessToken);
      res.setHeader('rt', refreshToken);

      res.status(200).json({
        success: true,
        message: 'Account personalised successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async forgotPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const { email } = req.body;

      await AuthService.forgotPassword(email);

      // Response is sent before the email is sent to avoid timing attacks
      res.status(200).json({
        success: true,
        message:
          'If that email address is in our database, we will send you an email to reset your password.',
      });
    } catch (error) {
      next(error);
    }
  }

  static async resetPassword(req: Request, res: Response, next: NextFunction) {
    try {
      let { token, id, password } = req.body;

      await AuthService.resetPassword(token, id, password);
      res
        .status(200)
        .json({ success: true, message: 'Password reset successfully' });
    } catch (error) {
      next(error);
    }
  }

  // static async resendResetPasswordEmail(
  //   req: Request,
  //   res: Response,
  //   next: NextFunction
  // ) {
  //   try {
  //     const { email } = req.body;

  //     await AuthService.resendResetPasswordEmail(email);

  //     res.status(200).json({
  //       success: true,
  //       message:
  //         'If that email address is in our database, we will send you an email to reset your password.',
  //     });
  //   } catch (error) {
  //     next(error);
  //   }
  // }

  static googleAuth = passport.authenticate('google', {
    scope: ['profile', 'email'],
  });

  static async googleCallback(req: Request, res: Response, next: NextFunction) {
    passport.authenticate('google', { session: false }, async (err, user) => {
      try {
        if (err) {
          console.error('Google authentication error:', err);
          return res.redirect(
            `${DotenvConfig.frontendBaseURL}/auth/error?message=${encodeURIComponent(err.message)}`
          );
        }

        if (!user) {
          return res.redirect(
            `${DotenvConfig.frontendBaseURL}/auth/error?message=Authentication failed`
          );
        }

        const {
          accessToken,
          refreshToken,
          user: userData,
          isNewUser,
        } = await AuthService.handleGoogleCallback(user);

        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('at', accessToken);
        res.setHeader('rt', refreshToken);

        const redirectUrl = isNewUser
          ? `${DotenvConfig.frontendBaseURL}/onboarding?token=${accessToken}`
          : `${DotenvConfig.frontendBaseURL}/dashboard?token=${accessToken}`;

        res.redirect(redirectUrl);
      } catch (error) {
        console.error('Google callback error:', error);
        next(error);
      }
    })(req, res, next);
  }

  static async linkGoogle(req: Request, res: Response, next: NextFunction) {
    try {
      const userId = req.authUser!;
      const { googleId } = req.body;

      await AuthService.linkGoogleAccount(userId._id, googleId);

      res.status(200).json({
        success: true,
        message: 'Google account linked successfully',
      });
    } catch (error) {
      next(error);
    }
  }
}
