import { Router } from 'express';
import SettingsRouter from '@settings/settings.route';

const accountRouter = Router();

accountRouter.use('/settings', SettingsRouter);

export default accountRouter;
