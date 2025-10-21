import Joi from 'joi';
import safeString from './safe.string.validations';
import { userPasswordSchema } from './auth.validations';

export const changePasswordValidationSchema = Joi.object({
  currentPassword: Joi.string().required().min(8),
  newPassword: userPasswordSchema,
});

export const updateProfileValidationSchema = Joi.object({
  firstName: safeString.label('First name').allow('', null),
  lastName: safeString.label('Last name').allow('', null),
  email: safeString.label('Email').email().lowercase().allow('', null),
  phone: Joi.object({
    dialCode: safeString.label('Dial code').allow('', null),
    number: Joi.alternatives().conditional('dialCode', {
      switch: [
        { is: '+1', then: Joi.string().length(10) }, // USA, Canada
        { is: '+44', then: Joi.string().length(10) }, // UK
        { is: '+234', then: Joi.string().length(10) }, // Nigeria
      ],
      otherwise: safeString.label('Dial code').min(6).max(15), // fallback for other codes
    }),
  }),
});
