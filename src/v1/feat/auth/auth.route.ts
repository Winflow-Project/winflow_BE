import { Router } from 'express';
import AuthController from './auth.controller';

const authRouter = Router();

authRouter.post('/signup', AuthController.signup.bind(AuthController));

authRouter.post(
  '/verify-email',
  AuthController.verifyEmail.bind(AuthController)
);

authRouter.post(
  '/personalise-account',
  AuthController.personaliseAccount.bind(AuthController)
);

authRouter.post('/signin', AuthController.signin.bind(AuthController));

authRouter.post(
  '/forgot-password',
  AuthController.forgotPassword.bind(AuthController)
);

authRouter.post(
  '/reset-password',
  AuthController.resetPassword.bind(AuthController)
);

export default authRouter;
