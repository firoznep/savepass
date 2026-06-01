import { NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { query } from '@/utils/db';

export async function POST(request: Request) {
  try {
    const { email, passwordHash, keyDerivationSalt } = await request.json();

    if (!email || !passwordHash || !keyDerivationSalt) {
      return NextResponse.json(
        { error: 'Email, password hash, and salt are required.' },
        { status: 400 }
      );
    }

    const emailLower = email.toLowerCase().trim();

    // Check if user already exists
    const userCheck = await query('SELECT id FROM users WHERE email = $1', [emailLower]);
    if (userCheck.rowCount && userCheck.rowCount > 0) {
      return NextResponse.json(
        { error: 'User with this email already exists.' },
        { status: 400 }
      );
    }

    // Hash the password hash server-side
    const serverHash = await bcrypt.hash(passwordHash, 10);

    // Save user to database
    await query(
      'INSERT INTO users (email, password_hash, key_derivation_salt) VALUES ($1, $2, $3)',
      [emailLower, serverHash, keyDerivationSalt]
    );

    return NextResponse.json({ success: true, message: 'User registered successfully!' }, { status: 201 });
  } catch (err: any) {
    console.error('Registration API error:', err);
    return NextResponse.json(
      { error: 'An internal server error occurred during registration.' },
      { status: 500 }
    );
  }
}
