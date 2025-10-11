import {
  ResourceNotFound,
  Conflict,
  InvalidInput,
} from '@middlewares/error.middleware';
import { UserModel } from '@user/user.model';
import { IUserDocument } from '@user/user.type';
import { changePasswordValidationSchema } from '@validations/settings.validations';

export default class SettingsService {
  static async changePassword(
    authUser: IUserDocument,
    currentPassword: string,
    newPassword: string
  ) {
    const user = await UserModel.findById(authUser._id);
    if (!user) throw new ResourceNotFound('User not found');

    const { error } = changePasswordValidationSchema.validate({
      currentPassword,
      newPassword,
    });
    if (error) {
      const errorMessages: string[] = error.details.map(
        (detail) => detail.message
      );
      throw new InvalidInput(errorMessages.join(', '));
    }

    const isPasswordMatch = await user.isPasswordMatch(currentPassword);
    if (!isPasswordMatch)
      throw new InvalidInput('Current password is incorrect');

    user.password = newPassword;
    await user.save();
    return user;
  }

  static async updateMultifactorAuth(
    authUser: IUserDocument,
    isEnabled: boolean
  ) {
    const user = await UserModel.findByIdAndUpdate(
      authUser,
      { 'account.settings.multifactorAuth.isEnabled': isEnabled },
      { new: true }
    );
    if (!user) throw new ResourceNotFound('User not found');

    return user.account?.settings ?? null;
  }

  //     static async addGoogleAuthenticator(
  //     authUser: IUserDocument,
  //     secret: string
  //   ) {
  //     const user = await UserModel.findById(authUser._id);
  //     if (!user) throw new ResourceNotFound('User not found');

  //     if (user.account?.settings.multifactorAuth.googleAuthenticator?.secret) {
  //       throw new Conflict('Google Authenticator is already set up');
  //     }

  //     user.account = user.account || {};
  //     user.account.settings = user.account.settings || {};
  //     user.account.settings.multifactorAuth =
  //       user.account.settings.multifactorAuth || {};
  //     user.account.settings.multifactorAuth.googleAuthenticator = {
  //       secret,
  //       isEnabled: false,
  //     };

  //     await user.save();
  //     return user.account.settings;
  //   }
}
