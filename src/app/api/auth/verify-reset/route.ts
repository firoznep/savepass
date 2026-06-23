import { NextResponse } from "next/server";
import crypto from "crypto";
import { query } from "@/utils/db";

export async function POST(request: Request) {
  try {
    const { email, token } = await request.json();
    if (!email || !token) {
      return NextResponse.json(
        { error: "Email and token required." },
        { status: 400 },
      );
    }

    const emailLower = email.toLowerCase().trim();
    const userRes = await query(
      "SELECT id, recovery_key_ciphertext, recovery_key_iv, recovery_key_derivation_salt FROM users WHERE email = $1",
      [emailLower],
    );
    if (!userRes.rowCount) {
      return NextResponse.json(
        { error: "Invalid token or email." },
        { status: 400 },
      );
    }

    const user = userRes.rows[0];
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const tokenRes = await query(
      "SELECT id FROM password_reset_tokens WHERE user_id = $1 AND token_hash = $2 AND used = false AND expires_at > now()",
      [user.id, tokenHash],
    );

    if (!tokenRes.rowCount) {
      return NextResponse.json(
        { error: "Invalid or expired token." },
        { status: 400 },
      );
    }

    // Optionally, do not mark token used until reset completes. Return wrapped recovery blob.
    const wrapped = {
      recoveryCiphertext: user.recovery_key_ciphertext || null,
      recoveryIv: user.recovery_key_iv || null,
      recoverySalt: user.recovery_key_derivation_salt || null,
    };

    return NextResponse.json({ success: true, wrapped });
  } catch (err: any) {
    console.error("Verify-reset API error:", err);
    return NextResponse.json(
      { error: "Internal server error." },
      { status: 500 },
    );
  }
}
