import { Router } from 'express';
import ThreadController from './thread.controller';

const threadRouter = Router();

threadRouter
  .route('/')
  .post(ThreadController.createThread.bind(ThreadController))
  .get(ThreadController.getThreads.bind(ThreadController));

threadRouter
  .route('/:threadId')
  .get(ThreadController.getThread.bind(ThreadController))
  .put(ThreadController.updateThread.bind(ThreadController));
// .delete(ThreadController.de.bind(ThreadController));

threadRouter
  .route('/:threadId/like')
  .post(ThreadController.likeThread.bind(ThreadController));

threadRouter
  .route('/:threadId/dislike')
  .post(ThreadController.dislikeThread.bind(ThreadController));

threadRouter
  .route('/:threadId/comment')
  .post(ThreadController.commentThread.bind(ThreadController))
  .get(ThreadController.getComments.bind(ThreadController));

threadRouter
  .route('/comment/:commentId')
  .put(ThreadController.updateComment.bind(ThreadController))
  .delete(ThreadController.deleteComment.bind(ThreadController));
export default threadRouter;
