# Security Review and Testing Checklist

## Authentication and Session

- [ ] Verify `JWT_SECRET` is configured in production and not committed to source control.
- [ ] Confirm cookies are set with `httpOnly`, `secure`, `sameSite=strict`, and `path=/`.
- [ ] Ensure `Login` and `register` endpoints do not leak whether an email exists.
- [ ] Confirm `forgot` endpoint returns a generic success message for all emails.
- [ ] Verify `reset-password` tokens are hashed before storage and marked used after successful reset.
- [ ] Test token expiry behavior (expired tokens rejected).

## Encryption and Recovery

- [ ] Confirm all vault entries are encrypted client-side with AES-GCM before being sent to the server.
- [ ] Confirm the server never receives plaintext master passwords or raw vault keys.
- [ ] Verify recovery code only unwraps the vault key when the correct recovery code is provided.
- [ ] Test the recovery flow end-to-end with a valid recovery code and reset link.
- [ ] Test that password reset without recovery code does not allow vault recovery if no recovery was configured.
- [ ] Verify new recovery code registration updates wrapped recovery blob and auth hash.

## Email and SMTP

- [ ] Confirm SMTP settings are required in production and documented in deployment guides.
- [ ] Verify `sendMail` correctly handles TLS vs. non-TLS SMTP hosts.
- [ ] Test email delivery using the configured SMTP server.
- [ ] Validate error handling when email delivery fails.

## Frontend Behavior

- [ ] Confirm `forgot-password` page renders when the reset link is used.
- [ ] Confirm invalid or expired reset links show an error.
- [ ] Confirm reset page requires both recovery code and new password.
- [ ] Confirm login unlock uses the wrapped vault key returned by the server.
- [ ] Test that register with recovery code stores recovery wrappers successfully.

## Database and Schema

- [ ] Confirm `users` table stores `vault_key_ciphertext` and `vault_key_iv`.
- [ ] Confirm `users` table stores recovery wrapper fields only when recovery code is configured.
- [ ] Confirm `password_reset_tokens` table uses hashed tokens and `used` flags.
- [ ] Verify database indexes on `users.email` and `password_reset_tokens.user_id`.

## Deployment and Environment

- [ ] Ensure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `NEXT_PUBLIC_APP_URL`, and `JWT_SECRET` are set in production.
- [ ] Ensure `DATABASE_URL` or DB credentials are configured securely.
- [ ] Confirm `NODE_ENV=production` enables secure cookie settings.

## Additional Security Tests

- [ ] Review for possible XSS in dynamic UI messages and input fields.
- [ ] Review CORS behavior if the app uses a separate frontend domain.
- [ ] Confirm no sensitive data is logged from password reset or recovery flows.
- [ ] Run static analysis or linting on auth-related files.
- [ ] Confirm the app can be audited using browser dev tools for no plaintext key leaks.
