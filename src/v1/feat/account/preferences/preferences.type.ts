import { Document } from 'mongoose';

export interface IAppearanceSettings {
  theme: Themes;
}

export enum Themes {
  SYSTEM_DEFAULT = 'system default',
  LIGHT = 'light',
  DARK = 'dark',
}

export interface IPreferences {
  appearance: IAppearanceSettings;
  //   notification: INotification;
}
export interface IPreferencesDocument extends IPreferences, Document {
  updatePreferences: (preferences: IPreferences) => Promise<void>;
  resetToDefault: () => Promise<void>;
  getCurrentPreferences: () => Promise<IPreferences>;
  getDefaultPreferences: () => Promise<IPreferences>;
}
