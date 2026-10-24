import { NextRequest, NextResponse } from 'next/server';
import { requireAuthenticatedUser, AuthError } from '@/lib/auth';
import { createClient } from '@/lib/supabase-server';

export async function GET(req: NextRequest) {
  try {
    const user = await requireAuthenticatedUser();
    const client = createClient();
    const searchParams = req.nextUrl.searchParams;
    const page = parseInt(searchParams.get('page') || '1');
    const pageSize = parseInt(searchParams.get('pageSize') || '50');
    const offset = (page - 1) * pageSize;
    const action = searchParams.get('action');
    const outcome = searchParams.get('outcome');

    let query = client
      .from('audit_events')
      .select('*', { count: 'exact' })
      .order('sequence_number', { ascending: false })
      .range(offset, offset + pageSize - 1);

    if (action) query = query.eq('action', action);
    if (outcome) query = query.eq('outcome', outcome);

    const { data, count } = await query;

    const events = (data || []).filter((e: { actor_id: string | null; target_user_id: string | null }) => {
      if (user.profile.role === 'admin') return true;
      if (e.actor_id === user.id) return true;
      if (e.target_user_id === user.id) return true;
      return false;
    });

    return NextResponse.json({ events, total: count || 0 });
  } catch (err) {
    if (err instanceof AuthError) {
      return NextResponse.json({ error: err.message }, { status: 401 });
    }
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
