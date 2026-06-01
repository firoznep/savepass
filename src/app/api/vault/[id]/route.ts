import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/utils/auth';
import { query } from '@/utils/db';

type RouteParams = {
  params: Promise<{ id: string }>;
};

// PUT: Update an existing encrypted vault item
export async function PUT(request: Request, { params }: RouteParams) {
  try {
    const authUser = await getAuthenticatedUser();
    if (!authUser) {
      return NextResponse.json({ error: 'Unauthorized.' }, { status: 401 });
    }

    const { id } = await params;

    // Verify ownership of the item before updating
    const itemCheck = await query(
      'SELECT id FROM vault_items WHERE id = $1 AND user_id = $2',
      [id, authUser.id]
    );

    if (!itemCheck.rowCount || itemCheck.rowCount === 0) {
      return NextResponse.json(
        { error: 'Vault item not found or access denied.' },
        { status: 404 }
      );
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
      `UPDATE vault_items 
       SET key_ciphertext = $1, key_iv = $2, 
           value_ciphertext = $3, value_iv = $4, 
           notes_ciphertext = $5, notes_iv = $6, 
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $7 AND user_id = $8
       RETURNING id, key_ciphertext, key_iv, value_ciphertext, value_iv, notes_ciphertext, notes_iv, created_at, updated_at`,
      [
        keyCiphertext,
        keyIv,
        valueCiphertext,
        valueIv,
        notesCiphertext || null,
        notesIv || null,
        id,
        authUser.id,
      ]
    );

    return NextResponse.json({ success: true, item: res.rows[0] });
  } catch (err: any) {
    console.error('PUT Vault Item API error:', err);
    return NextResponse.json(
      { error: 'An error occurred while updating the vault item.' },
      { status: 500 }
    );
  }
}

// DELETE: Remove an encrypted vault item
export async function DELETE(request: Request, { params }: RouteParams) {
  try {
    const authUser = await getAuthenticatedUser();
    if (!authUser) {
      return NextResponse.json({ error: 'Unauthorized.' }, { status: 401 });
    }

    const { id } = await params;

    // Verify ownership and delete
    const res = await query(
      'DELETE FROM vault_items WHERE id = $1 AND user_id = $2 RETURNING id',
      [id, authUser.id]
    );

    if (!res.rowCount || res.rowCount === 0) {
      return NextResponse.json(
        { error: 'Vault item not found or access denied.' },
        { status: 404 }
      );
    }

    return NextResponse.json({ success: true, message: 'Vault item deleted.' });
  } catch (err: any) {
    console.error('DELETE Vault Item API error:', err);
    return NextResponse.json(
      { error: 'An error occurred while deleting the vault item.' },
      { status: 500 }
    );
  }
}
