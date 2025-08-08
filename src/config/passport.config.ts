import passport from 'passport';
import {
  Strategy as GoogleStrategy,
  StrategyOptions,
  Profile,
  VerifyCallback,
} from 'passport-google-oauth20';
import DotenvConfig from './dotenv.config';
import { UserModel } from '@user/user.model';
import { AppRoles, IUserDocument } from '@user/user.type';
import { Unauthorized, ResourceNotFound } from '@middlewares/error.middleware';
// import { GoogleProfile } from '@auth/auth.type';

const googleStrategyOptions: StrategyOptions = {
  clientID: DotenvConfig.Google.clientID,
  clientSecret: DotenvConfig.Google.clientSecret,
  callbackURL: DotenvConfig.Google.callbackUrl,
  scope: ['profile', 'email'],
};

passport.use(
  new GoogleStrategy(
    googleStrategyOptions,
    async (
      accessToken: string,
      refreshToken: string,
      profile: Profile,
      done: VerifyCallback
    ) => {
      try {
        const email = profile.emails?.[0]?.value;
        const isEmailVerified = profile.emails?.[0]?.verified || false;

        if (!email)
          return done(new ResourceNotFound('No email found in Google profile'));

        // Check if user already exists
        let existingUser = await UserModel.findOne({ email });

        if (existingUser) {
          // Update Google ID if not present
          if (!existingUser.googleId) {
            existingUser.googleId = profile.id;
            existingUser.isVerified = isEmailVerified;
            await existingUser.save();
          }
          return done(null, existingUser);
        }

        // Create new user
        const newUser = await UserModel.create({
          googleId: profile.id,
          firstName: profile.name?.givenName,
          lastName: profile.name?.familyName,
          email: email,
          isVerified: isEmailVerified,
          isAccountActive: true,
          profilePicture: profile.photos?.[0]?.value || '',
          authProvider: 'google',
          appRole: AppRoles.USER,
        });

        return done(null, newUser);
      } catch (error) {
        return done(error as Error);
      }
    }
  )
);

export default passport;
