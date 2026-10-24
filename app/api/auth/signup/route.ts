import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase-server';
import { signUpSchema } from '@/lib/validation';
import { logAuditEvent } from '@/lib/audit';
import { headers } from 'next/headers';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const parsed = signUpSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json({ error: parsed.error.issues[0]?.message || 'Invalid input' }, { status: 400 });
    }

    const supabase = createClient();
    const { data, error } = await supabase.auth.signUp({
      email: parsed.data.email,
      password: parsed.data.password,
      options: { data: { display_name: parsed.data.display_name, role: parsed.data.role } },
    });

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 400 });
    }

    const correlationId = headers().get('x-request-id') || '';
    await logAuditEvent({
      actor_id: data.user?.id || null,
      action: 'user_signup',
      outcome: 'success',
      request_id: correlationId,
      metadata: { email: parsed.data.email },
    });

    return NextResponse.json({ user: data.user, message: 'Account created successfully' });
  } catch {
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
