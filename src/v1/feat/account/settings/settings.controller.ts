import { Request, Response, NextFunction } from 'express';
import SettingsService from './settings.service';

export default class SettingsController {
  static async changePassword(req: Request, res: Response, next: NextFunction) {
    try {
      const user = req.authUser!;
      const { currentPassword, newPassword } = req.body;

      const updatedUser = await SettingsService.changePassword(
        user,
        currentPassword,
        newPassword
      );
      res.status(200).json({
        success: true,
        message: 'Password changed successfully',
        updatedUser,
      });
    } catch (error) {
      next(error);
    }
  }
}
