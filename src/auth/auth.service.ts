import { Injectable, BadRequestException } from '@nestjs/common';
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

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepo: Repository<User>,
    @InjectRepository(TempUser) private tempUserRepo: Repository<TempUser>,
    @InjectRepository(Account) private accountRepo: Repository<Account>,
    @InjectRepository(Session) private sessionRepo: Repository<Session>,
    private jwtService: JwtService,
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

    console.log(`OTP for ${data.email}: ${otp}`); // TODO: replace with actual mailer

    const token = this.jwtService.sign({ email: data.email });

    res.cookie('signup_pending', token, {
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
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
    console.log(`Verifying OTP ${otp}`);

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

    console.log(`User ${user.email} created`);
    return { message: 'User created successfully' };
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

    // 4️⃣ Create a new session
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

    // 5️⃣ Set the session token as a cookie
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
}
