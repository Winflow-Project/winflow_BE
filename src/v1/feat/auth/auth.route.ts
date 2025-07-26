import { Router } from 'express';
import AuthController from './auth.controller';

const authRouter = Router();

authRouter.post('/signup', AuthController.signup.bind(AuthController));

authRouter.post(
  '/verify-email',
  AuthController.verifyEmail.bind(AuthController)
);
authRouter.post('/signin', AuthController.signin.bind(AuthController));

export default authRouter;
