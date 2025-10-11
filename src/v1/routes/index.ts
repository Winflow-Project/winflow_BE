import { Router } from 'express';
import authRouter from '@auth/auth.route';
import userRouter from '@user/user.route';
import threadRouter from '@thread/thread.route';
import accountRouter from '@account/account-routes';
import AuthMiddleware from '@middlewares/auth.middleware';

const indexRouter = Router();

indexRouter.use('/auth', authRouter);

indexRouter.use(AuthMiddleware.authorizeUser);

indexRouter.use('/user', userRouter);
indexRouter.use('/thread', threadRouter);
indexRouter.use('/account', accountRouter);

export default indexRouter;
