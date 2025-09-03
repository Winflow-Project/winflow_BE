import { Request, Response, NextFunction } from 'express';
import ThreadService from './thread.service';
import { Types } from 'mongoose';

export default class ThreadController {
  static async createThread(req: Request, res: Response, next: NextFunction) {
    try {
      const user = req.authUser!;
      const payload = req.body;
      const reqFile = req.file;

      const bulletin = await ThreadService.createThread(payload, user, reqFile);
      res.status(201).json({
        success: true,
        message: 'Thread created successfully',
        bulletin,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getThreads(req: Request, res: Response, next: NextFunction) {
    try {
      const authUser = req.authUser!;
      const threads = await ThreadService.getThreads(1, 10, authUser);
      res.status(200).json({
        success: true,
        message: 'Threads retrieved successfully',
        threads,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getThread(req: Request, res: Response, next: NextFunction) {
    try {
      const threadId = new Types.ObjectId(req.params.threadId);
      const authUser = req.authUser!;

      const thread = await ThreadService.getThread(threadId, authUser);
      res.status(200).json({
        success: true,
        message: 'Thread retrieved successfully',
        thread,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updateThread(req: Request, res: Response, next: NextFunction) {
    try {
      const threadId = new Types.ObjectId(req.params.threadId);
      const user = req.authUser!;
      const payload = req.body;

      const updatedThread = await ThreadService.updateThread(
        threadId,
        payload,
        user
      );
      res.status(200).json({
        success: true,
        message: 'Thread updated successfully',
        updatedThread,
      });
    } catch (error) {
      next(error);
    }
  }

  static async commentThread(req: Request, res: Response, next: NextFunction) {
    try {
      const user = req.authUser!;
      const threadId = new Types.ObjectId(req.params.threadId);
      const { comment } = req.body;

      const newComment = await ThreadService.commentThread(
        user,
        threadId,
        comment
      );
      res.status(201).json({
        success: true,
        message: 'Comment added successfully',
        newComment,
      });
    } catch (error) {
      next(error);
    }
  }

  static async getComments(req: Request, res: Response, next: NextFunction) {
    try {
      const threadId = new Types.ObjectId(req.params.threadId);

      const comments = await ThreadService.getComments(threadId);
      res.status(200).json({
        success: true,
        message: 'Comments retrieved successfully',
        comments,
      });
    } catch (error) {
      next(error);
    }
  }

  static async updateComment(req: Request, res: Response, next: NextFunction) {
    try {
      const authUser = req.authUser!;
      const commentId = new Types.ObjectId(req.params.commentId);
      const payload = req.body;

      const updatedComment = await ThreadService.updateComment(
        commentId,
        payload,
        authUser
      );
      res.status(200).json({
        success: true,
        message: 'Comment updated successfully',
        updatedComment,
      });
    } catch (error) {
      next(error);
    }
  }

  static async deleteComment(req: Request, res: Response, next: NextFunction) {
    try {
      const commentId = new Types.ObjectId(req.params.commentId);

      await ThreadService.deleteComment(commentId);
      res.status(200).json({
        success: true,
        message: 'Comment deleted successfully',
      });
    } catch (error) {
      next(error);
    }
  }

  static async likeThread(req: Request, res: Response, next: NextFunction) {
    try {
      const threadId = new Types.ObjectId(req.params.threadId);
      const user = req.authUser!;

      const likedThread = await ThreadService.likethread(threadId, user);
      res.status(200).json({
        success: true,
        message: 'Thread liked successfully',
        likedThread,
      });
    } catch (error) {
      next(error);
    }
  }

  static async dislikeThread(req: Request, res: Response, next: NextFunction) {
    try {
      const threadId = new Types.ObjectId(req.params.threadId);
      const user = req.authUser!;

      const dislikedThread = await ThreadService.dislikethread(threadId, user);
      res.status(200).json({
        success: true,
        message: 'Thread disliked successfully',
        dislikedThread,
      });
    } catch (error) {
      next(error);
    }
  }
}
