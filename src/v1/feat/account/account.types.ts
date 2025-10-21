import { ISettings } from '@settings/settings.types';
import { IPreferences } from '@preferences/preferences.type';

export interface IAccount {
  settings: ISettings;
  preferences: IPreferences;
  //   privacy: any;
}
