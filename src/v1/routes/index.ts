import { Router } from 'express';
import authRouter from '@auth/auth.route';
import userRouter from '@user/user.route';
import threadRouter from '@thread/thread.route';
import AuthMiddleware from '@middlewares/auth.middleware';
const indexRouter = Router();

indexRouter.use('/auth', authRouter);

indexRouter.use(AuthMiddleware.authorizeUser);

indexRouter.use('/user', userRouter);
indexRouter.use('/thread', threadRouter);

export default indexRouter;
