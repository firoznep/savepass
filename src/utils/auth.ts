import { cookies } from 'next/headers';
import jwt from 'jsonwebtoken';

export interface AuthUser {
  id: string;
  email: string;
}

export async function getAuthenticatedUser(): Promise<AuthUser | null> {
  try {
    const cookieStore = await cookies();
    const token = cookieStore.get('safepass_token')?.value;
    if (!token) return null;

    const secret = process.env.JWT_SECRET || 'safepass_jwt_secret_token_key_9988776655';
    const decoded = jwt.verify(token, secret) as { userId: string; email: string };
    
    if (!decoded || !decoded.userId) return null;
    
    return {
      id: decoded.userId,
      email: decoded.email,
    };
  } catch (err) {
    console.error('Authentication helper error:', err);
    return null;
  }
}
