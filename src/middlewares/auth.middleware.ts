import { Request, Response, NextFunction } from 'express';
import { ResourceNotFound, Unauthorized } from './error.middleware';
import { TokenType } from '@auth/auth.type';
import AuthService from '@auth/auth.service';
import { IUserDocument, UserModel } from '@user/user.model';

declare global {
  namespace Express {
    interface Request {
      authUser?: IUserDocument;
    }
  }
}

export default class AuthMiddleware {
  static async authorizeUser(req: Request, res: Response, next: NextFunction) {
    try {
      const accessToken = req.headers['at'] as string;
      if (!accessToken) throw new Unauthorized('Authorization token required');

      const decoded = await AuthService.verifyJWT(
        accessToken,
        TokenType.ACCESS
      );

      const userId = decoded.sub as string;

      const existingUser = await UserModel.findById(userId);
      if (!existingUser) throw new ResourceNotFound('User not found');

      if (existingUser.reAuth) {
        throw new Unauthorized('Access denied, please re-authenticate');
      }

      req.authUser = existingUser;
      next();
    } catch (error) {
      console.log(error);
      next(error);
    }
  }

  static checkRole(role: string[]) {
    return (req: Request, res: Response, next: NextFunction) => {
      if (!role.some((r) => req.authUser?.appRole.includes(r))) {
        return next(
          new Unauthorized('You do not have access to this resource')
        );
      }
      next();
    };
  }
}
