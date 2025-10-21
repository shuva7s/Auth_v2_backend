import { Injectable, InternalServerErrorException } from '@nestjs/common';
import axios from 'axios';
import { resetPasswordEmail } from 'src/email_templates/reset-password.email';
import { signupVerificationEmail } from 'src/email_templates/signup-verification.email';

@Injectable()
export class BrevoMailerService {
  private readonly apiKey = process.env.BREVO_API_KEY!;
  private readonly baseUrl = 'https://api.brevo.com/v3/smtp/email';

  async sendSignupOtp(to: string, otp: string, name?: string) {
    const html = signupVerificationEmail({ name, otp });
    return this.sendEmail(to, 'Your OTP Code', html);
  }

  async sendResetPassword(to: string, resetLink: string, name?: string) {
    const html = resetPasswordEmail({ name, resetLink });
    return this.sendEmail(to, 'Reset your password', html);
  }

  private async sendEmail(to: string, subject: string, html: string) {
    try {
      const payload = {
        sender: { name: 'Authentication', email: 'shuvadeepmandal5@gmail.com' },
        to: [{ email: to }],
        subject,
        htmlContent: html,
      };
      await axios.post(this.baseUrl, payload, {
        headers: {
          accept: 'application/json',
          'content-type': 'application/json',
          'api-key': this.apiKey,
        },
      });
    } catch (error) {
      throw new InternalServerErrorException('Failed to send email');
    }
  }
}
