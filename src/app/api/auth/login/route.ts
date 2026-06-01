import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import { query } from "@/utils/db";

export async function POST(request: Request) {
  try {
    const { email, passwordHash } = await request.json();

    if (!email || !passwordHash) {
      return NextResponse.json(
        { error: "Email and password hash are required." },
        { status: 400 },
      );
    }

    const emailLower = email.toLowerCase().trim();

    // Find user in database
    const res = await query(
      "SELECT id, email, password_hash, key_derivation_salt FROM users WHERE email = $1",
      [emailLower],
    );

    const genericError = "Invalid email or master password.";

    if (!res.rowCount || res.rowCount === 0) {
      // Security: Even if user is not found, we delay slightly or run a dummy compare to prevent timing attacks.
      await bcrypt.compare(
        "dummy_hash",
        "$2a$10$dummyhashplaceholderstringtobeprettysecure",
      );
      return NextResponse.json({ error: genericError }, { status: 401 });
    }

    const user = res.rows[0];

    // Verify the authentication hash
    const isValid = await bcrypt.compare(passwordHash, user.password_hash);
    if (!isValid) {
      return NextResponse.json({ error: genericError }, { status: 401 });
    }

    // Generate JWT
    const secret =
      process.env.JWT_SECRET || "safepass_jwt_secret_token_key_9988776655";
    const token = jwt.sign({ userId: user.id, email: user.email }, secret, {
      expiresIn: "24h",
    });

    // Set secure cookie
    const cookieStore = await cookies();
    cookieStore.set({
      name: "safepass_token",
      value: token,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
      maxAge: 60 * 60 * 24, // 24 hours
    });

    return NextResponse.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        keyDerivationSalt: user.key_derivation_salt,
      },
    });
  } catch (err: any) {
    console.error("Login API error:", err);
    return NextResponse.json(
      { error: "An internal server error occurred during login." },
      { status: 500 },
    );
  }
}
