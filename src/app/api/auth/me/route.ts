import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/utils/auth';
import { query } from '@/utils/db';

export async function GET() {
  try {
    const authUser = await getAuthenticatedUser();
    
    if (!authUser) {
      return NextResponse.json({ error: 'Unauthorized.' }, { status: 401 });
    }

    // Retrieve salt so the user can derive the encryption key again if they need it
    const res = await query('SELECT id, email, key_derivation_salt FROM users WHERE id = $1', [authUser.id]);
    
    if (!res.rowCount || res.rowCount === 0) {
      return NextResponse.json({ error: 'User not found.' }, { status: 404 });
    }

    const user = res.rows[0];

    return NextResponse.json({
      authenticated: true,
      user: {
        id: user.id,
        email: user.email,
        keyDerivationSalt: user.key_derivation_salt,
      },
    });
  } catch (err: any) {
    console.error('Me API error:', err);
    return NextResponse.json(
      { error: 'An error occurred fetching user details.' },
      { status: 500 }
    );
  }
}
