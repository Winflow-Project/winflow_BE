import { Router } from 'express';
import UserController from './user.controller';
import AuthMiddleware from '@middlewares/auth.middleware';
const userRouter = Router();

userRouter.get('/', UserController.getUser.bind(UserController));

userRouter.put('/', UserController.updateUser.bind(UserController));

userRouter.get(
  '/all',
  AuthMiddleware.checkRole(['admin']),
  UserController.getAllUsers.bind(UserController)
);

export default userRouter;
