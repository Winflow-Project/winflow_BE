import { Schema } from 'mongoose';
import { IAccount } from './account.types';
import { SettingsSchema } from '@settings/settings.model';

export const AccountSchema = new Schema<IAccount>({
  settings: { type: SettingsSchema, default: {}, _id: false },
});
