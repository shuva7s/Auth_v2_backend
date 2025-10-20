import {
  Controller,
  Post,
  Body,
  Res,
  Req,
  Get,
  UseGuards,
} from '@nestjs/common';
import type { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { SignupDto } from './dtos/signup.dto';
import { SigninDto } from './dtos/signin.dto';
import { SessionGuard } from 'src/guards/auth.guard';
import { User } from 'src/user/entities/user.entity';
import { Session } from './entities/session.entity';

export type AuthenticatedRequest = Request & {
  user: User;
  session: Session;
};

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('sign-up')
  signUp(@Body() dto: SignupDto, @Res({ passthrough: true }) res: Response) {
    return this.authService.signup(dto, res);
  }

  @Post('verify-signup-otp')
  verifyOtp(
    @Body('otp') otp: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.verifyOtp({
      otp,
      req,
      res,
    });
  }

  @Post('sign-in')
  signIn(
    @Body() dto: SigninDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.signIn({ dto, req, res });
  }

  @Post('sign-out')
  signOut(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.authService.signOut(req, res);
  }

  @UseGuards(SessionGuard)
  @Get('get-session-data')
  getSessionData(@Req() req: AuthenticatedRequest) {
    return {
      user: {
        id: req.user.id,
        email: req.user.email,
        name: req.user.name,
        role: req.user.role,
        avatarUrl: req.user.avatarUrl,
      },
      session: {
        id: req.session.id,
        expiresAt: req.session.expiresAt,
        createdAt: req.session.createdAt,
      },
    };
  }

  @Post('forgot-password')
  forgotPassword(
    @Body() dto: { email: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    const email = dto.email;
    return this.authService.forgotPassword(email, res);
  }

  @Post('validate-reset-password-token')
  validateResetPasswordToken(@Body('token') token: string) {
    return this.authService.validateResetPasswordToken(token);
  }

  @Post('reset-password')
  resetPassword(
    @Body()
    dto: {
      token: string;
      new_password: string;
      confirm_new_password: string;
    },
  ) {
    const { token, new_password, confirm_new_password } = dto;
    return this.authService.resetPassword({
      token,
      new_password,
      confirm_new_password,
    });
  }
}
