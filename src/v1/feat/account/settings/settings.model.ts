import { Schema } from 'mongoose';
import { ISettings } from './settings.types';

export const SettingsSchema = new Schema<ISettings>({
  multifactorAuth: {
    isEnabled: { type: Boolean, default: false },
    methods: [
      {
        type: {
          type: String,
          enum: ['email', 'sms', 'authenticator'],
          required: true,
        },
        isEnabled: { type: Boolean, default: false },
      },
    ],
  },
});
