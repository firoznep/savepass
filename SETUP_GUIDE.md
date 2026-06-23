# Development and Deployment Setup Guide

## ✅ What Works Now

- Zero-knowledge password encryption (client-side PBKDF2 + AES-GCM)
- Vault CRUD with encrypted storage
- Email-based password reset with recovery code unwrapping
- Self-hosted SMTP email delivery
- JWT session management
- TypeScript and build configuration

---

## 🚀 Local Development (`pnpm dev`)

### Prerequisites

1. **PostgreSQL** running locally
   - Default: `localhost:5432`
   - Ensure TCP/IP connections are enabled

2. **Node.js 18+** and `pnpm`

### Setup Steps

#### 1. Create `.env.local`

```bash
# Database (local PostgreSQL)
DB_HOST=127.0.0.1
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=safepass

# JWT Secret (can be anything for dev, but use a strong value in production)
JWT_SECRET=your-dev-secret-key-min-32-chars-long

# SMTP Configuration (for password reset emails)
SMTP_HOST=your-smtp-server.com
SMTP_PORT=587
SMTP_USER=your-email@domain.com
SMTP_PASS=your-smtp-password
SMTP_SECURE=false
SMTP_FROM=noreply@yourdomain.com

# App URL (for password reset link)
NEXT_PUBLIC_APP_URL=http://localhost:3000

# Admin email for SMTP failure notifications
ADMIN_EMAIL=admin@yourdomain.com
```

#### 2. Initialize the Database

```bash
pnpm run db:init
```

This creates the `safepass` database and applies the schema.

#### 3. Start Development Server

```bash
pnpm dev
```

App runs on `http://localhost:3000` (or `0.0.0.0:3000`)

#### 4. Test Locally

- Register a new account with recovery code
- Add vault items
- Test password reset using SMTP
- Test recovery flow with recovery code

---

## 🌐 Vercel Deployment

### Prerequisites

1. **PostgreSQL database** (Neon, AWS RDS, or similar)
2. **Vercel account** connected to GitHub

### Setup Steps

#### 1. Configure Environment Variables in Vercel

In your Vercel project settings, add these environment variables:

```
DATABASE_URL=postgresql://user:password@host:5432/safepass

JWT_SECRET=your-production-secret-key-min-32-chars-long-and-random

SMTP_HOST=your-smtp-server.com
SMTP_PORT=587
SMTP_USER=your-email@domain.com
SMTP_PASS=your-smtp-password
SMTP_SECURE=false
SMTP_FROM=noreply@yourdomain.com

NEXT_PUBLIC_APP_URL=https://your-vercel-app.vercel.app

ADMIN_EMAIL=admin@yourdomain.com
```

#### 2. Important: Vercel Function Timeout

- The current code uses raw SMTP with potential for longer connection times.
- Vercel serverless functions timeout after **10 seconds** by default.
- For email sending, consider:
  - Using a queue (Bull, RabbitMQ) for async email
  - Or setting up a dedicated email service function
  - For now, the SMTP timeout is set to 20 seconds but will fail on Vercel

**Recommended: Use a transactional email provider** (SendGrid, Mailgun, etc.) instead of raw SMTP for production.

#### 3. Deploy

```bash
git push  # Vercel auto-deploys on push
```

#### 4. Verify Database Migration

- Vercel runs `pnpm build` which includes TypeScript check
- **Manual step**: SSH into Vercel or use a migration service to run `db-init` OR add a database migration function
- For now, manually create the schema on Neon or AWS RDS using `db/schema.sql`

---

## ⚠️ Known Issues & Workarounds

### Issue 1: SMTP Timeouts on Vercel

**Problem:** Self-hosted SMTP over `node:net` can timeout (10s Vercel limit).

**Workaround A (Recommended):** Replace SMTP with a transactional email provider:

```typescript
// Use Mailgun, SendGrid, or AWS SES instead
```

**Workaround B:** Implement async email queue:

```typescript
// Add Bull/RabbitMQ queue for email jobs
// Worker processes emails outside the 10s request limit
```

**For now:** Test locally. On Vercel, password reset emails may fail silently.

---

### Issue 2: Database Schema Not Applied

**Problem:** Vercel serverless functions can't run `db-init.js` automatically.

**Solution:**

1. Manually run schema on your database:

   ```bash
   psql -h your-db-host -U user -d safepass < db/schema.sql
   ```

2. Or use a migration tool (Flyway, Liquibase, etc.)

---

### Issue 3: Cold Starts & Connection Pooling

Vercel functions may create many DB connections on cold start.

**Solution:** The code already uses connection pooling:

- Dev: max 10 connections
- Production: max 20 connections
- Idle timeout: 30 seconds

No action needed unless you see connection exhaustion errors.

---

## 🔒 Security Checklist Before Going Live

- [ ] `JWT_SECRET` is **NOT** the default value
- [ ] `DATABASE_URL` uses SSL/TLS (`?sslmode=require`)
- [ ] SMTP credentials are **NOT** committed to git (only in Vercel env vars)
- [ ] `NEXT_PUBLIC_APP_URL` matches your actual domain
- [ ] All auth routes return generic error messages (no email enumeration)
- [ ] Cookies are set with `secure`, `httpOnly`, `sameSite=strict`
- [ ] Review `SECURITY_TESTING_CHECKLIST.md` for additional audit items

---

## 📝 Production Email Recommendation

**Current Setup:** Self-hosted SMTP (works locally, may timeout on Vercel)

**Recommended:** Transactional Email Provider

- **SendGrid**: Free tier, simple API
- **Mailgun**: Excellent docs, free tier
- **AWS SES**: Serverless-friendly, pay-per-email

**Example SendGrid migration:**

```typescript
// Replace sendMail in src/utils/email.ts
import sgMail from "@sendgrid/mail";
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

export async function sendMail({ to, subject, text }: SendMailOptions) {
  await sgMail.send({
    to,
    from: process.env.SMTP_FROM!,
    subject,
    text,
  });
}
```

---

## 🧪 Testing the Complete Flow

### Local Dev Test

1. `pnpm dev` → `http://localhost:3000`
2. Register with recovery code
3. Add a vault item
4. Request password reset (check email)
5. Click reset link → enter recovery code → set new password
6. Log in with new password

### Vercel Pre-Production Test

1. Deploy to staging branch on Vercel
2. Test registration (no recovery initially)
3. Add vault items
4. Test password reset (will likely fail email due to timeout)
5. Verify DB schema is present

---

## ❓ Troubleshooting

**Q: `pnpm dev` fails with "Connection refused"**

- A: PostgreSQL not running. Start it: `sudo systemctl start postgresql`

**Q: Database schema not applied**

- A: Run `pnpm run db:init` manually

**Q: Reset email not sent**

- A: Check `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` are correct
- Check firewall isn't blocking the SMTP port
- For Vercel: expect timeout, use email provider instead

**Q: "Invalid JWT"**

- A: `JWT_SECRET` doesn't match between app instances

---

## 📞 Next Steps

1. Test locally with `pnpm dev` + local PostgreSQL + SMTP
2. Before Vercel deployment: set up PostgreSQL on Neon or AWS RDS
3. Add environment variables to Vercel project
4. Deploy and test registration/login flow
5. For production: migrate to transactional email provider
