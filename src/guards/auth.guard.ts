import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Response } from 'express';
import { Session } from 'src/auth/entities/session.entity';

@Injectable()
export class SessionGuard implements CanActivate {
  // Session slide interval - only update if last update was > 1 hour ago
  private readonly SLIDE_INTERVAL_MS = 60 * 60 * 1000; // 1 hour
  private readonly SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

  constructor(
    @InjectRepository(Session)
    private sessionRepo: Repository<Session>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const response: Response = context.switchToHttp().getResponse();
    const sessionToken = request.cookies?.session_token;

    if (!sessionToken) {
      throw new UnauthorizedException('No session token');
    }

    const session = await this.sessionRepo.findOne({
      where: { sessionToken },
      relations: ['user'],
    });

    if (!session) {
      response.clearCookie('session_token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
      });
      throw new UnauthorizedException('Invalid session');
    }

    if (new Date() > session.expiresAt) {
      response.clearCookie('session_token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
      });
      await this.sessionRepo.remove(session);
      throw new UnauthorizedException('Expired token');
    }

    const timeSinceLastUpdate = Date.now() - session.updatedAt.getTime();
    const shouldSlide = timeSinceLastUpdate > this.SLIDE_INTERVAL_MS;

    if (shouldSlide) {
      session.expiresAt = new Date(Date.now() + this.SESSION_DURATION_MS);
      await this.sessionRepo.save(session);

      // Update cookie
      response.cookie('session_token', sessionToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: this.SESSION_DURATION_MS,
      });
    }

    request.user = session.user;
    request.session = session;

    return true;
  }
}
