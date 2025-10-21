export function signupVerificationEmail({
  name,
  otp,
}: {
  name?: string;
  otp: string;
}) {
  return `
    <div style="font-family: Inter, sans-serif; max-width: 480px; margin: auto; padding: 24px; border:1px solid #eee; border-radius:10px;">
      <h2 style="color:#111;">Welcome${name ? `, ${name}` : ''}!</h2>
      <p>Thank you for signing up for <strong>Authentication</strong>.</p>
      <p>Use the one-time password (OTP) below to verify your account:</p>

      <h1 style="color:#2563eb; font-size: 2rem; letter-spacing: 2px; margin: 16px 0;">${otp}</h1>

      <p>This code will expire in <strong>5 minutes</strong>.</p>

      <hr style="margin:24px 0; border:none; border-top:1px solid #eee;" />

      <p style="font-size: 13px; color:#666;">
        <strong>Security Tip:</strong> Never share your OTP with anyone. 
        <strong>Authentication</strong> will never ask for your verification codes or passwords via email.
      </p>

      <p style="font-size: 12px; color: #888; margin-top:16px;">
        — The Authentication Team
      </p>
    </div>
  `;
}
