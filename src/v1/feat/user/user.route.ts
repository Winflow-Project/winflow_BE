import { Router } from 'express';
import UserController from './user.controller';

const userRouter = Router();

userRouter.get('/', UserController.getUser.bind(UserController));
userRouter.put('/', UserController.updateUser.bind(UserController));

export default userRouter;
