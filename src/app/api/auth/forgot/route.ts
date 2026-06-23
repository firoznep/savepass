import { NextResponse } from "next/server";
import crypto from "crypto";
import { query } from "@/utils/db";
import { sendMail } from "@/utils/email";

const APP_URL = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@example.com";

export async function POST(request: Request) {
  try {
    const { email } = await request.json();
    if (!email || typeof email !== "string") {
      return NextResponse.json({ success: true }); // do not reveal missing emails
    }

    const emailLower = email.toLowerCase().trim();
    const res = await query("SELECT id FROM users WHERE email = $1", [
      emailLower,
    ]);
    if (!res.rowCount) {
      return NextResponse.json({ success: true });
    }

    const userId = res.rows[0].id;
    const token = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    const existingToken = await query(
      "SELECT id FROM password_reset_tokens WHERE user_id = $1",
      [userId],
    );

    if ((existingToken.rowCount ?? 0) > 0) {
      await query(
        "UPDATE password_reset_tokens SET token_hash = $1, expires_at = $2, used = false WHERE user_id = $3",
        [tokenHash, expires, userId],
      );
    } else {
      await query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        [userId, tokenHash, expires],
      );
    }

    const resetUrl = `${APP_URL}/reset-password?token=${encodeURIComponent(token)}&email=${encodeURIComponent(emailLower)}`;
    const body = `Hello,

A password reset request was received for your account. If you did not request this, you may safely ignore this email.

Reset your password using the link below:

${resetUrl}

This link expires in 15 minutes.

If you have any questions, reply to this message.
`;

    try {
      await sendMail({
        to: emailLower,
        subject: "Pass Desk password reset",
        text: body,
      });
    } catch (emailError) {
      console.error("SMTP sendMail error:", emailError);
      await sendMail({
        to: ADMIN_EMAIL,
        subject: "Pass Desk SMTP send failure",
        text: `Failed to deliver password reset email to ${emailLower}: ${(emailError as Error).message}`,
      }).catch(() => {
        console.error("Failed to notify admin of SMTP failure.");
      });
      return NextResponse.json({ success: true });
    }

    return NextResponse.json({ success: true });
  } catch (err: any) {
    console.error("Forgot-password API error:", err);
    return NextResponse.json({ success: true });
  }
}
