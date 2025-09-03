import UserService from './user.service';
import { Request, Response, NextFunction } from 'express';

export default class UserController {
  static async getUser(req: Request, res: Response, next: NextFunction) {
    try {
      const user = await UserService.getUser(req.authUser!);

      res.status(200).json({
        success: true,
        message: 'User profile fetched successfully',
        user,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updateUser(req: Request, res: Response, next: NextFunction) {
    try {
      const payload = req.body;

      const updatedUser = await UserService.updateUser(req.authUser!, payload);

      res.status(200).json({
        success: true,
        message: 'User profile updated successfully',
        user: updatedUser,
      });
    } catch (error) {
      next(error);
    }
  }
}
