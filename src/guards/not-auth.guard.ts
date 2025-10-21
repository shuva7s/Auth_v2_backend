import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Session } from 'src/auth/entities/session.entity';

@Injectable()
export class NotAuthGuard implements CanActivate {
  constructor(
    @InjectRepository(Session)
    private readonly sessionRepo: Repository<Session>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const sessionToken = request.cookies?.session_token;

    if (!sessionToken) return true;

    const session = await this.sessionRepo.findOne({
      where: { sessionToken },
      relations: ['user'],
    });

    if (!session || new Date() > session.expiresAt) {
      return true;
    }

    throw new ForbiddenException('You are already logged in');
  }
}
