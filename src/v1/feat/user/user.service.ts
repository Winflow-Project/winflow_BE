import { UserModel } from './user.model';
import { IUser, IUserDocument } from './user.type';
import { ResourceNotFound } from '@middlewares/error.middleware';

export default class UserService {
  static async updateUser(user: IUserDocument, payload: IUserDocument) {
    const updatedUser = await UserModel.findByIdAndUpdate(user._id, payload, {
      new: true,
    });

    if (!updatedUser) throw new ResourceNotFound('User not found');
    return updatedUser;
  }
}
