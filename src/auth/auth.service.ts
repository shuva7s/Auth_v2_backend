import {
  Injectable,
  BadRequestException,
  NotFoundException,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DeepPartial, Repository } from 'typeorm';
import * as crypto from 'crypto';
import * as bcrypt from 'bcryptjs';
import { SignupDto } from './dtos/signup.dto';
import { User } from 'src/user/entities/user.entity';
import { Request, Response } from 'express';
import { JwtService } from '@nestjs/jwt';
import { TempUser } from 'src/user/entities/temp_users.entity';
import { Account } from './entities/account.entity';
import { Session } from './entities/session.entity';
import { SigninDto } from './dtos/signin.dto';
import { Verification } from './entities/verification.entity';
import { decryptEmail, encryptEmail } from 'src/utils/email.encryption';
import { BrevoMailerService } from 'src/mailer/brevo-mailer.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepo: Repository<User>,
    @InjectRepository(TempUser) private tempUserRepo: Repository<TempUser>,
    @InjectRepository(Account) private accountRepo: Repository<Account>,
    @InjectRepository(Session) private sessionRepo: Repository<Session>,
    @InjectRepository(Verification)
    private verificationRepo: Repository<Verification>,
    private jwtService: JwtService,
    private readonly brevoMailer: BrevoMailerService,
  ) {}
  async signup(data: SignupDto, res: Response) {
    const existing = await this.userRepo.findOne({
      where: { email: data.email },
    });
    if (existing) throw new BadRequestException('Email already registered');

    const otp = crypto.randomInt(100000, 999999).toString();
    const passwordHash = await bcrypt.hash(data.password, 10);

    await this.tempUserRepo.upsert(
      {
        email: data.email,
        name: data.name,
        hashedPassword: passwordHash,
        otp,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000),
      },
      ['email'],
    );

    if (process.env.NODE_ENV !== 'production') console.log('Signup OTP: ', otp);
    else {
      await this.brevoMailer.sendSignupOtp(data.email, otp, data.name);
    }

    const token = this.jwtService.sign({ email: data.email });

    res.cookie('signup_pending', token, {
      httpOnly: false, // Let client js access this cookie to detect a pending signup flow
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 5 * 60 * 1000, // 5 minutes
    });

    return { message: 'OTP sent to email' };
  }

  async verifyOtp({
    otp,
    req,
    res,
  }: {
    otp: string;
    req: Request;
    res: Response;
  }) {
    const token = req.cookies?.signup_pending;
    if (!token) throw new BadRequestException('Signup session not found');

    let email: string;
    try {
      const payload = this.jwtService.verify<{ email: string }>(token);
      email = payload.email;
    } catch {
      res.clearCookie('signup_pending');
      throw new BadRequestException('Invalid or expired signup session');
    }

    const record = await this.tempUserRepo.findOne({ where: { email, otp } });
    if (!record) throw new BadRequestException('Invalid OTP');

    if (record.expiresAt < new Date()) {
      await this.tempUserRepo.delete({ email: record.email });
      res.clearCookie('signup_pending');
      throw new BadRequestException('OTP expired');
    }

    // Create the user (profile only)
    const user = this.userRepo.create({
      email: record.email,
      name: record.name,
    });
    await this.userRepo.save(user);

    // Create the account (credentials-based)
    const account = this.accountRepo.create({
      providerId: 'credential',
      user,
      hashedPassword: record.hashedPassword,
    });
    await this.accountRepo.save(account);

    // Cleanup and finish
    await this.tempUserRepo.delete({ email: record.email });
    res.clearCookie('signup_pending');

    // Check auto sign-in config
    const auto_sign_in_after_sign_up =
      process.env.AUTO_SIGNIN_AFTER_SIGN_UP === 'true';

    if (auto_sign_in_after_sign_up) {
      const sessionToken = crypto.randomUUID();
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
      const ipAddress =
        req.headers['x-forwarded-for']?.toString() ||
        req.socket.remoteAddress ||
        null;
      const userAgent = req.headers['user-agent'] || null;

      const session = this.sessionRepo.create({
        user,
        sessionToken,
        expiresAt,
        ipAddress,
        userAgent,
      } as DeepPartial<Session>);
      await this.sessionRepo.save(session);

      res.cookie('session_token', sessionToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });
      return {
        message: `Welcome ${user.name}!`,
        redirectPath: '/',
      };
    } else {
      return {
        message: `Account created successfully, Signin to ontinue`,
        redirectPath: '/sign-in',
      };
    }
  }

  async signIn({
    dto,
    req,
    res,
  }: {
    dto: SigninDto;
    req: Request;
    res: Response;
  }) {
    const { email, password } = dto;

    if (!email || !password)
      throw new BadRequestException('Invalid credentials');

    // Find user
    const user = await this.userRepo.findOne({ where: { email } });
    if (!user) throw new BadRequestException('Invalid credentials');

    // Find credentials account
    const account = await this.accountRepo.findOne({
      where: { user: { id: user.id }, providerId: 'credential' },
    });

    if (!account || !account.hashedPassword)
      throw new BadRequestException('Invalid credentials');

    // Verify password
    const valid = await bcrypt.compare(password, account.hashedPassword);
    if (!valid) throw new BadRequestException('Invalid credentials');

    // Create a new session
    const sessionToken = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    const ipAddress =
      req.headers['x-forwarded-for']?.toString() ||
      req.socket.remoteAddress ||
      null;
    const userAgent = req.headers['user-agent'] || null;

    const session = this.sessionRepo.create({
      user,
      sessionToken,
      expiresAt,
      ipAddress,
      userAgent,
    } as DeepPartial<Session>);
    await this.sessionRepo.save(session);

    // Set the session token as a cookie
    res.cookie('session_token', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    console.log(`User ${user.email} signed in`);
    return {
      message: `Login successful, welcome back ${user.name}`,
      user: { id: user.id, email: user.email, name: user.name },
    };
  }

  async signOut(req: Request, res: Response) {
    const token = req.cookies?.session_token;
    if (!token) throw new BadRequestException('No active session found');

    const session = await this.sessionRepo.findOne({
      where: { sessionToken: token },
      relations: ['user'],
    });

    if (session) {
      await this.sessionRepo.delete({ id: session.id });
      console.log(`Session for ${session.user.email} terminated`);
    }

    // Clear cookie on client
    res.clearCookie('session_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
    });

    return { message: 'Logged out successfully' };
  }

  async forgotPassword(email: string, res: Response) {
    if (!email) throw new BadRequestException('Invalid email');

    const user = await this.userRepo.findOne({ where: { email } });
    if (!user) throw new NotFoundException('User not found');

    const token = encryptEmail(email);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    const verification = this.verificationRepo.create({
      identifier: email,
      value: token,
      expiresAt,
    });

    await this.verificationRepo.save(verification);

    const resetLink = `${process.env.FRONT_END_URL}/reset-password?token=${encodeURIComponent(token)}`;

    if (process.env.NODE_ENV !== 'production') console.log(resetLink);
    else {
      await this.brevoMailer.sendResetPassword(email, resetLink, user.name);
    }

    await this.brevoMailer.sendResetPassword(email, resetLink, user.name);
    return { message: 'Password reset link has been generated' };
  }

  async validateResetPasswordToken(token: string) {
    if (!token) throw new BadRequestException('Password reset token missing');
    try {
      const decoded = decodeURIComponent(token);
      const email = decryptEmail(decoded);

      const record = await this.verificationRepo.findOne({
        where: { identifier: email, value: decoded },
      });

      if (!record) throw new NotFoundException('Invalid token');

      if (new Date(record.expiresAt) < new Date())
        throw new BadRequestException('Token expired');

      return { message: 'Token is valid' };
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof NotFoundException
      )
        throw error;
      throw new BadRequestException('Invalid token');
    }
  }

  async resetPassword({
    token,
    new_password,
    confirm_new_password,
  }: {
    token: string;
    new_password: string;
    confirm_new_password: string;
  }) {
    if (!token) throw new BadRequestException('Password reset token missing');
    if (new_password !== confirm_new_password)
      throw new BadRequestException('Passwords do not match');
    if (new_password.length < 8)
      throw new BadRequestException(
        'Passwords must be at least 8 characters long',
      );

    try {
      const decoded = decodeURIComponent(token);
      const email = decryptEmail(decoded);

      const record = await this.verificationRepo.findOne({
        where: { identifier: email, value: decoded },
      });

      if (!record) throw new NotFoundException('Invalid token');

      if (new Date(record.expiresAt) < new Date())
        throw new BadRequestException('Token expired');

      const user = await this.userRepo.findOne({ where: { email } });
      if (!user) throw new NotFoundException('User not found');

      const existing_credential_account = await this.accountRepo.findOne({
        where: { user: { id: user.id }, providerId: 'credential' },
      });

      const passwordHash = await bcrypt.hash(new_password, 10);

      if (existing_credential_account) {
        existing_credential_account.hashedPassword = passwordHash;
        await this.accountRepo.save(existing_credential_account);
      } else {
        const new_credential_account = this.accountRepo.create({
          user,
          providerId: 'credential',
          hashedPassword: passwordHash,
        });
        await this.accountRepo.save(new_credential_account);
      }

      await this.verificationRepo.delete({ id: record.id });

      return { message: 'Password has been reset successfully' };
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof NotFoundException
      )
        throw error;
      throw new BadRequestException('Invalid token');
    }
  }

  async handleGoogleCallback(req: Request, res: Response) {
    try {
      return await this.handleGoogleSignIn({ req, res });
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof NotFoundException
      )
        throw error;
      throw new InternalServerErrorException(
        error.message || 'Something went wrong during Google sign-in',
      );
    }
  }

  async handleGoogleSignIn({ req, res }: { req: Request; res: Response }) {
    const googleProfile = req.user as any;

    if (!googleProfile)
      throw new BadRequestException('Google authentication failed');

    const { email, name, accessToken, refreshToken, picture } = googleProfile;

    if (!email) throw new BadRequestException('No email returned from Google');

    let user = await this.userRepo.findOne({ where: { email } });

    if (!user) {
      user = this.userRepo.create({
        name: name || 'Google User',
        email,
        avatarUrl: picture,
      });
      await this.userRepo.save(user);
    }

    let account = await this.accountRepo.findOne({
      where: { providerId: 'google', user: { id: user.id } },
    });

    if (!account) {
      account = this.accountRepo.create({
        user,
        providerId: 'google',
        accessToken,
        refreshToken,
        idToken: googleProfile.idToken ?? null,
        scope: googleProfile.scope ?? null,
      });
      await this.accountRepo.save(account);
    } else {
      // Update tokens if re-login happens
      account.accessToken = accessToken;
      account.refreshToken = refreshToken;
      account.updatedAt = new Date();
      await this.accountRepo.save(account);
    }

    const sessionToken = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    const ipAddress =
      req.headers['x-forwarded-for']?.toString() ||
      req.socket.remoteAddress ||
      null;
    const userAgent = req.headers['user-agent'] || null;

    const session = this.sessionRepo.create({
      user,
      sessionToken,
      expiresAt,
      ipAddress,
      userAgent,
    } as DeepPartial<Session>);
    await this.sessionRepo.save(session);

    res.cookie('session_token', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    console.log(`User ${user.email} signed in via Google`);

    return res.redirect(process.env.FRONT_END_URL!);
  }
}
