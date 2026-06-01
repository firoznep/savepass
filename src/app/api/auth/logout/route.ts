import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';

export async function POST() {
  try {
    const cookieStore = await cookies();
    cookieStore.delete('safepass_token');

    return NextResponse.json({ success: true, message: 'Logged out successfully.' });
  } catch (err: any) {
    console.error('Logout API error:', err);
    return NextResponse.json(
      { error: 'An error occurred during logout.' },
      { status: 500 }
    );
  }
}
