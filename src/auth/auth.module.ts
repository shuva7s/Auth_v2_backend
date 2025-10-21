import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UserModule } from 'src/user/user.module';
import { Account } from './entities/account.entity';
import { Verification } from './entities/verification.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Session } from './entities/session.entity';
import { JwtModule } from '@nestjs/jwt';
import { TempUser } from 'src/user/entities/temp_users.entity';
import { PassportModule } from '@nestjs/passport';
import { GoogleStrategy } from './strategies/google.strategy';

@Module({
  imports: [
    UserModule,
    TypeOrmModule.forFeature([Account, Session, Verification, TempUser]),
    JwtModule.register({
      secret: process.env.JWT_SECRET, // 👈 keep in .env
      signOptions: { expiresIn: '5m' }, // OTP cookie valid for 5 min
    }),
    PassportModule.register({ session: false }),
  ],
  providers: [AuthService, GoogleStrategy],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
