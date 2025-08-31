import { Types } from 'mongoose';

interface IThread {
  title: string;
  description?: string;
  image?: string;
  link?: string;
  likes?: Types.ObjectId[];
  dislikes?: Types.ObjectId[];
  createdBy: Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

interface IThreadComment {
  threadId: Types.ObjectId;
  comment: string;
  reaction?: number;
  likes?: Types.ObjectId[];
  dislikes?: Types.ObjectId[];
  createdBy: Types.ObjectId;
  deletedAt?: Date;
}

export interface IThreadDocument extends IThread {}
export interface IThreadCommentDocument extends IThreadComment {}
