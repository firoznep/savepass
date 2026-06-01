import { NextResponse } from 'next/server';
import crypto from 'crypto';
import { query } from '@/utils/db';

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const email = searchParams.get('email');

    if (!email) {
      return NextResponse.json({ error: 'Email parameter is required.' }, { status: 400 });
    }

    const emailLower = email.toLowerCase().trim();

    // Query database for the user's salt
    const res = await query('SELECT key_derivation_salt FROM users WHERE email = $1', [emailLower]);
    
    if (res.rowCount && res.rowCount > 0) {
      return NextResponse.json({
        exists: true,
        salt: res.rows[0].key_derivation_salt,
      });
    }

    // Security: If the user doesn't exist, return a deterministic mock salt to prevent email enumeration.
    // The client will still derive a key and try to log in, but will be rejected at the login endpoint.
    const hmac = crypto.createHmac('sha256', process.env.JWT_SECRET || 'safepass_jwt_secret_token_key_9988776655');
    hmac.update(emailLower);
    const mockSalt = `safepass-salt-v1-${hmac.digest('hex').substring(0, 16)}`;

    return NextResponse.json({
      exists: false,
      salt: mockSalt,
    });
  } catch (err: any) {
    console.error('Salt API error:', err);
    return NextResponse.json({ error: 'Internal server error.' }, { status: 500 });
  }
}
