import { NextResponse } from "next/server";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import { query } from "@/utils/db";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const {
      email,
      token,
      newPasswordHash,
      newKeyDerivationSalt,
      vaultKeyCiphertext,
      vaultKeyIv,
    } = body;

    if (
      !email ||
      !token ||
      !newPasswordHash ||
      !newKeyDerivationSalt ||
      !vaultKeyCiphertext ||
      !vaultKeyIv
    ) {
      return NextResponse.json(
        { error: "Missing parameters." },
        { status: 400 },
      );
    }

    const emailLower = email.toLowerCase().trim();
    const userRes = await query("SELECT id FROM users WHERE email = $1", [
      emailLower,
    ]);
    if (!userRes.rowCount) {
      return NextResponse.json(
        { error: "Invalid email or token." },
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

    const tokenId = tokenRes.rows[0].id;

    // Update password hash and wrap the vault key with the new password.
    const serverHash = await bcrypt.hash(newPasswordHash, 10);

    // Build parameter list in order, push user.id only once at the end
    const updateFields: any[] = [
      serverHash,
      newKeyDerivationSalt,
      vaultKeyCiphertext,
      vaultKeyIv,
    ];

    let updateQuery =
      "UPDATE users SET password_hash = $1, key_derivation_salt = $2, vault_key_ciphertext = $3, vault_key_iv = $4";

    if (
      body.recoveryCiphertext &&
      body.recoveryIv &&
      body.recoverySalt &&
      body.recoveryAuthHash
    ) {
      const recoveryHash = await bcrypt.hash(body.recoveryAuthHash, 10);
      updateQuery +=
        ", recovery_key_ciphertext = $5, recovery_key_iv = $6, recovery_key_derivation_salt = $7, recovery_code_hash = $8";
      updateFields.push(
        body.recoveryCiphertext,
        body.recoveryIv,
        body.recoverySalt,
        recoveryHash,
      );
    }

    // id parameter is always last
    updateQuery += " WHERE id = $" + (updateFields.length + 1);
    updateFields.push(user.id);

    await query(updateQuery, updateFields);

    // Mark token as used
    await query("UPDATE password_reset_tokens SET used = true WHERE id = $1", [
      tokenId,
    ]);

    return NextResponse.json({ success: true });
  } catch (err: any) {
    console.error("Reset-password API error:", err);
    return NextResponse.json(
      { error: "Internal server error." },
      { status: 500 },
    );
  }
}
