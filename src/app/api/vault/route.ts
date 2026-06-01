import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/utils/auth';
import { query } from '@/utils/db';

// GET: Retrieve all encrypted vault items for the logged-in user
export async function GET() {
  try {
    const authUser = await getAuthenticatedUser();
    if (!authUser) {
      return NextResponse.json({ error: 'Unauthorized.' }, { status: 401 });
    }

    const res = await query(
      'SELECT id, key_ciphertext, key_iv, value_ciphertext, value_iv, notes_ciphertext, notes_iv, created_at, updated_at FROM vault_items WHERE user_id = $1 ORDER BY created_at DESC',
      [authUser.id]
    );

    return NextResponse.json({ items: res.rows });
  } catch (err: any) {
    console.error('GET Vault API error:', err);
    return NextResponse.json(
      { error: 'An error occurred while retrieving vault items.' },
      { status: 500 }
    );
  }
}

// POST: Add a new encrypted vault item
export async function POST(request: Request) {
  try {
    const authUser = await getAuthenticatedUser();
    if (!authUser) {
      return NextResponse.json({ error: 'Unauthorized.' }, { status: 401 });
    }

    const {
      keyCiphertext,
      keyIv,
      valueCiphertext,
      valueIv,
      notesCiphertext,
      notesIv,
    } = await request.json();

    if (!keyCiphertext || !keyIv || !valueCiphertext || !valueIv) {
      return NextResponse.json(
        { error: 'Key and Value ciphertexts with their IVs are required.' },
        { status: 400 }
      );
    }

    const res = await query(
      `INSERT INTO vault_items 
       (user_id, key_ciphertext, key_iv, value_ciphertext, value_iv, notes_ciphertext, notes_iv) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) 
       RETURNING id, key_ciphertext, key_iv, value_ciphertext, value_iv, notes_ciphertext, notes_iv, created_at, updated_at`,
      [
        authUser.id,
        keyCiphertext,
        keyIv,
        valueCiphertext,
        valueIv,
        notesCiphertext || null,
        notesIv || null,
      ]
    );

    return NextResponse.json({ success: true, item: res.rows[0] }, { status: 201 });
  } catch (err: any) {
    console.error('POST Vault API error:', err);
    return NextResponse.json(
      { error: 'An error occurred while creating the vault item.' },
      { status: 500 }
    );
  }
}
