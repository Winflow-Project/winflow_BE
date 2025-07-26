import { Request, Response, NextFunction } from 'express';
import AuthService from './auth.service';
import { InvalidInput, Unauthorized } from '@middlewares/error.middleware';

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
}
