import { model, Schema, PaginateModel, Types } from 'mongoose';
import paginate from 'mongoose-paginate-v2';
import { IThreadDocument, IThreadCommentDocument } from './thread.type';

const threadSchema = new Schema<IThreadDocument>(
  {
    title: { type: String, required: true },
    description: { type: String },
    image: { type: String },
    link: { type: String },
    likes: [{ type: Types.ObjectId, ref: 'User' }],
    dislikes: [{ type: Types.ObjectId, ref: 'User' }],
    createdBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  },
  { timestamps: true }
);

const threadCommentSchema = new Schema<IThreadCommentDocument>(
  {
    threadId: { type: Schema.Types.ObjectId, ref: 'Thread', required: true },
    comment: { type: String, required: true },
    reaction: { type: Number, default: 0 },
    likes: [{ type: Types.ObjectId, ref: 'User' }],
    dislikes: [{ type: Types.ObjectId, ref: 'User' }],
    createdBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    deletedAt: { type: Date },
  },
  { timestamps: true }
);

threadSchema.methods.toJSON = function () {
  const thread = this.toObject();
  delete thread.__v;
  delete thread.deletedAt;
  return thread;
};

threadCommentSchema.methods.toJSON = function () {
  const threadComment = this.toObject();
  delete threadComment.__v;
  delete threadComment.deletedAt;
  return threadComment;
};

threadSchema.plugin(paginate);
threadCommentSchema.plugin(paginate);

export const ThreadModel = model<
  IThreadDocument,
  PaginateModel<IThreadDocument>
>('Thread', threadSchema);

export const ThreadCommentModel = model<
  IThreadCommentDocument,
  PaginateModel<IThreadCommentDocument>
>('ThreadComment', threadCommentSchema);
