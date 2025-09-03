import {
  BadRequest,
  InvalidInput,
  ResourceNotFound,
} from '@middlewares/error.middleware';
import { Types } from 'mongoose';
import { IThreadDocument, IThreadCommentDocument } from './thread.type';
import { ThreadModel, ThreadCommentModel } from './thread.model';
import { IUserDocument } from '@user/user.type';
import { uploadToCloudinary } from '@utils/cloudinary.utils';

export default class ThreadService {
  static async createThread(
    payload: IThreadDocument,
    user: IUserDocument,
    reqFile?: Express.Multer.File
  ) {
    if (reqFile) {
      const uploadResult = await uploadToCloudinary(reqFile.path);

      payload.image = uploadResult.secure_url;
    }
    const newThread = ThreadModel.create({ ...payload, createdBy: user._id });

    return newThread;
  }

  static async getThreads(page = 1, limit = 10, user?: IUserDocument) {
    const options = {
      page,
      limit,
      sort: { createdAt: -1 },
      populate: [
        { path: 'createdBy', select: 'firstName lastName' },
        // { path: 'attachment', select: 'url' },
      ],
      lean: true,
    };
    const result = await ThreadModel.paginate({}, options);

    result.docs = result.docs.map((thread: any) => {
      const likesArr = Array.isArray(thread.likes) ? thread.likes : [];
      const dislikesArr = Array.isArray(thread.dislikes) ? thread.dislikes : [];
      return {
        ...thread,
        likes: likesArr.length,
        dislikes: dislikesArr.length,
        isLiked: user
          ? likesArr.some((id: any) => id.toString() === user._id.toString())
          : false,
        isDisliked: user
          ? dislikesArr.some((id: any) => id.toString() === user._id.toString())
          : false,
      };
    });

    return result;
  }

  static async getThread(threadId: Types.ObjectId, user: IUserDocument) {
    const thread = await ThreadModel.findById(threadId)
      .populate('createdBy', 'firstName lastName')
      .lean();
    if (!thread) throw new ResourceNotFound('Thread not found');

    const likesArr = Array.isArray(thread.likes) ? thread.likes : [];
    const dislikesArr = Array.isArray(thread.dislikes) ? thread.dislikes : [];

    return {
      ...thread,
      likes: likesArr.length,
      dislikes: dislikesArr.length,
      isLiked: user
        ? likesArr.some((id: any) => id.toString() === user._id.toString())
        : false,
      isDisliked: user
        ? dislikesArr.some((id: any) => id.toString() === user._id.toString())
        : false,
    };
  }

  static async updateThread(
    threadId: Types.ObjectId,
    payload: Partial<IThreadDocument>,
    user: IUserDocument
  ) {
    if (!Types.ObjectId.isValid(threadId))
      throw new BadRequest('Invalid Thread ID');

    const thread = await ThreadModel.findById(threadId);
    if (!thread) throw new ResourceNotFound('Thread not found');
    if (String(thread.createdBy) !== String(user._id)) {
      throw new InvalidInput('You are not authorized to update this post');
    }

    Object.assign(thread, payload);
    await thread.save();
    return thread;
  }

  static async commentThread(
    user: IUserDocument,
    threadId: Types.ObjectId,
    comment: string
  ) {
    if (!Types.ObjectId.isValid(threadId))
      throw new BadRequest('Invalid thread ID');
    if (!comment) throw new InvalidInput('Comment is required');

    const thread = await ThreadModel.findById(threadId);
    if (!thread) throw new ResourceNotFound('Thread not found');

    // if (user.isBanned) await this.handleBannedAccount(user);

    const newComment = await ThreadCommentModel.create({
      threadId,
      comment,
      createdBy: user._id,
    });
    return newComment;
  }

  static async getComments(threadId: Types.ObjectId) {
    if (!Types.ObjectId.isValid(threadId))
      throw new BadRequest('Invalid thread ID');

    const comments = await ThreadCommentModel.find({
      threadId,
      deletedAt: null,
    })
      .populate('createdBy', 'firstName lastName email')
      .sort({ createdAt: 1 });

    return comments;
  }

  static async updateComment(
    commentId: Types.ObjectId,
    payload: Partial<IThreadCommentDocument>,
    user: IUserDocument
  ) {
    if (!Types.ObjectId.isValid(commentId))
      throw new BadRequest('Invalid comment ID');

    const comment = await ThreadCommentModel.findById(commentId);
    if (!comment) throw new ResourceNotFound('Comment not found');
    if (String(comment.createdBy) !== String(user._id)) {
      throw new InvalidInput('You are not authorized to update this comment');
    }
    // if (user.isBanned) await this.handleBannedAccount(user);

    Object.assign(comment, payload);
    await comment.save();
    return comment;
  }

  static async deleteComment(commentId: Types.ObjectId) {
    if (!Types.ObjectId.isValid(commentId))
      throw new BadRequest('Invalid comment ID');

    const comment = await ThreadCommentModel.findById(commentId);
    if (!comment) throw new ResourceNotFound('Comment not found');
    // if (String(comment.createdBy) !== String(user._id)) {
    //   throw new InvalidInput('You are not authorized to delete this comment');
    // }

    await ThreadCommentModel.findByIdAndUpdate(commentId, {
      deletedAt: new Date(),
    });
    return;
  }

  static async likethread(threadId: Types.ObjectId, user: IUserDocument) {
    const thread = await ThreadModel.findById(threadId);
    if (!thread) throw new ResourceNotFound('thread not found');

    const userIdStr = String(user._id);

    // Remove from dislikes if present
    thread.dislikes = (thread.dislikes || []).filter(
      (id: Types.ObjectId) => String(id) !== userIdStr
    );

    // Toggle like
    if (
      (thread.likes || []).some(
        (id: Types.ObjectId) => String(id) === userIdStr
      )
    ) {
      thread.likes = thread.likes?.filter(
        (id: Types.ObjectId) => String(id) !== userIdStr
      );
    } else {
      thread.likes = [...(thread.likes || []), user._id];
    }

    await thread.save();
    return thread;
  }

  static async dislikethread(threadId: Types.ObjectId, user: IUserDocument) {
    const thread = await ThreadModel.findById(threadId);
    if (!thread) throw new ResourceNotFound('thread not found');

    const userIdStr = String(user._id);

    // Remove from likes if present
    thread.likes = (thread.likes || []).filter(
      (id: Types.ObjectId) => String(id) !== userIdStr
    );

    // Toggle dislike
    if (
      (thread.dislikes || []).some(
        (id: Types.ObjectId) => String(id) === userIdStr
      )
    ) {
      thread.dislikes = thread.dislikes?.filter(
        (id: Types.ObjectId) => String(id) !== userIdStr
      );
    } else {
      thread.dislikes = [...(thread.dislikes || []), user._id];
    }

    await thread.save();
    return thread;
  }
}
