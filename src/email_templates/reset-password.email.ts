export function resetPasswordEmail({
  name,
  resetLink,
}: {
  name?: string;
  resetLink: string;
}) {
  return `
    <div style="font-family: Inter, sans-serif; max-width: 480px; margin: auto; padding: 24px; border:1px solid #eee; border-radius:10px;">
      <h2 style="color:#111;">Hi${name ? `, ${name}` : ''}</h2>
      <p>You recently requested to reset your password for your <strong>Authentication</strong> account.</p>
      <p>Please click the button below to create a new password:</p>
      
      <a href="${resetLink}"
        style="background:#2563eb; color:white; padding:12px 20px; text-decoration:none; border-radius:6px; display:inline-block; margin-top:16px;">
        Reset Password
      </a>

      <p style="margin-top:20px;">If you didn’t request this password reset, please ignore this email or contact our support team immediately to secure your account.</p>

      <hr style="margin:24px 0; border:none; border-top:1px solid #eee;" />

      <p style="font-size: 13px; color:#666;">
        <strong>Security Tip:</strong> Never share your password or verification links with anyone.
        <strong>Authentication</strong> will never ask you for your password via email.
      </p>

      <p style="font-size: 12px; color: #999; margin-top:16px;">
        This link will expire in <strong>5 minutes</strong> for security reasons.
      </p>

      <p style="font-size: 12px; color: #888; margin-top:16px;">
        — The Authentication Team
      </p>
    </div>
  `;
}
