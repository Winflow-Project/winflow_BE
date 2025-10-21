import { Router } from 'express';
import SettingsController from './settings.controller';

const settingsRouter = Router();

settingsRouter
  .route('/change-password')
  .post(SettingsController.changePassword.bind(SettingsController));

export default settingsRouter;
