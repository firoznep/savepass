import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { query } from "@/utils/db";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const {
      email,
      passwordHash,
      keyDerivationSalt,
      vaultKeyCiphertext,
      vaultKeyIv,
    } = body;

    if (
      !email ||
      !passwordHash ||
      !keyDerivationSalt ||
      !vaultKeyCiphertext ||
      !vaultKeyIv
    ) {
      return NextResponse.json(
        {
          error:
            "Email, password hash, salt, and wrapped vault key are required.",
        },
        { status: 400 },
      );
    }

    // Optional recovery fields (client may provide these to enable recovery)
    const recoveryCiphertext: string | undefined = body.recoveryCiphertext;
    const recoveryIv: string | undefined = body.recoveryIv;
    const recoverySalt: string | undefined = body.recoverySalt;
    const recoveryAuthHash: string | undefined = body.recoveryAuthHash;

    const emailLower = email.toLowerCase().trim();

    // Check if user already exists
    const userCheck = await query("SELECT id FROM users WHERE email = $1", [
      emailLower,
    ]);
    if (userCheck.rowCount && userCheck.rowCount > 0) {
      return NextResponse.json(
        { error: "User with this email already exists." },
        { status: 400 },
      );
    }

    // Hash the password hash server-side
    const serverHash = await bcrypt.hash(passwordHash, 10);

    if (recoveryCiphertext && recoveryIv && recoverySalt && recoveryAuthHash) {
      // Hash the recovery auth hash server-side as well
      const recoveryHash = await bcrypt.hash(recoveryAuthHash, 10);

      // Save user including recovery info and wrapped vault key
      await query(
        "INSERT INTO users (email, password_hash, key_derivation_salt, recovery_key_ciphertext, recovery_key_iv, recovery_code_hash, recovery_key_derivation_salt, vault_key_ciphertext, vault_key_iv) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        [
          emailLower,
          serverHash,
          keyDerivationSalt,
          recoveryCiphertext,
          recoveryIv,
          recoveryHash,
          recoverySalt,
          vaultKeyCiphertext,
          vaultKeyIv,
        ],
      );
    } else {
      // Save user without recovery
      await query(
        "INSERT INTO users (email, password_hash, key_derivation_salt, vault_key_ciphertext, vault_key_iv) VALUES ($1, $2, $3, $4, $5)",
        [
          emailLower,
          serverHash,
          keyDerivationSalt,
          vaultKeyCiphertext,
          vaultKeyIv,
        ],
      );
    }

    return NextResponse.json(
      { success: true, message: "User registered successfully!" },
      { status: 201 },
    );
  } catch (err: any) {
    console.error("Registration API error:", err);
    return NextResponse.json(
      { error: "An internal server error occurred during registration." },
      { status: 500 },
    );
  }
}
