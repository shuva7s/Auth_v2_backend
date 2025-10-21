// import { Injectable } from '@nestjs/common';
// import { PassportStrategy } from '@nestjs/passport';
// import { Strategy, Profile } from 'passport-google-oauth20';

// @Injectable()
// export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
//   constructor() {
//     super({
//       clientID: process.env.GOOGLE_CLIENT_ID!,
//       clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
//       callbackURL: process.env.GOOGLE_REDIRECT_URI!,
//       scope: ['openid', 'email', 'profile'],
//       proxy: true,
//     });
//   }

//   async validate(
//     accessToken: string,
//     refreshToken: string,
//     profile: any,
//     done: Function,
//   ): Promise<any> {
//     const { emails, name, photos } = profile;

//     const userData = {
//       email: emails?.[0]?.value,
//       name: `${name?.givenName ?? ''} ${name?.familyName ?? ''}`.trim(),
//       picture: photos?.[0]?.value,
//       accessToken,
//       refreshToken,
//     };

//     done(null, userData);
//   }
// }

import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile } from 'passport-google-oauth20';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor() {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: process.env.GOOGLE_REDIRECT_URI!,
      scope: ['openid', 'email', 'profile'],
      proxy: process.env.NODE_ENV === 'production',
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: Function,
  ): Promise<void> {
    try {
      if (!profile || !profile.emails || profile.emails.length === 0) {
        return done(
          new Error('Google authentication failed: invalid profile'),
          null,
        );
      }

      const { emails, name, photos } = profile;

      const userData = {
        providerId: 'google',
        email: emails?.[0]?.value ?? null,
        name: `${name?.givenName ?? ''} ${name?.familyName ?? ''}`.trim(),
        picture: photos?.[0]?.value ?? null,
        accessToken,
        refreshToken: refreshToken || null,
      };

      // Verify essential fields
      if (!userData.email) {
        return done(
          new Error('Google authentication failed: missing email'),
          null,
        );
      }

      return done(null, userData);
    } catch (error) {
      return done(
        new InternalServerErrorException(
          error.message ||
            'An unexpected error occurred during Google authentication.',
        ),
        null,
      );
    }
  }
}
