// ============================================================
// SUPABASE EDGE FUNCTION — create-user
// ============================================================
// PURPOSE:
// Lets an admin create a new student account WITHOUT logging
// the admin panel out of its own session (which happens if you
// call supabase.auth.signUp() directly from the browser).
//
// WHY THIS HAS TO BE SERVER-SIDE:
// Creating an account "as" another person requires the Supabase
// SERVICE ROLE key, which has full database access and must
// NEVER appear in any HTML/JS file that ships to a browser.
// Edge Functions run on Supabase's servers, so the key stays
// there and is never exposed to whoever opens admin.html.
//
// HOW TO DEPLOY (one-time setup):
// 1. Install the Supabase CLI:  npm install -g supabase
// 2. supabase login
// 3. supabase link --project-ref amicwjhgdemypsiyuumw
// 4. Put this file at:  supabase/functions/create-user/index.ts
// 5. supabase functions deploy create-user
// 6. In the Supabase Dashboard > Edge Functions > create-user
//    > Settings, the SUPABASE_SERVICE_ROLE_KEY is already
//    available automatically as an environment variable —
//    you do NOT need to paste your secret key anywhere yourself.
//
// HOW admin.html WOULD CALL IT (once deployed), replacing the
// disabled adminAddUser() function:
//
//   const { data, error } = await sb.functions.invoke('create-user', {
//     body: { fullName, fatherName, phone, univId, email, password, role }
//   });
//
// The function checks that the CALLER is a real admin (using
// their own access token) before doing anything, so this can't
// be abused even if someone finds the function's URL.
// ============================================================

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

Deno.serve(async (req) => {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  };

  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  try {
    // 1. Identify the caller from their own auth token (sent
    //    automatically by supabase-js when you use functions.invoke).
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'Missing authorization' }), {
        status: 401, headers: corsHeaders,
      });
    }

    // A client scoped to the CALLER's token — used only to verify
    // who is calling, never to perform privileged writes.
    const callerClient = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
      global: { headers: { Authorization: authHeader } },
    });

    const { data: { user: callerUser }, error: callerErr } = await callerClient.auth.getUser();
    if (callerErr || !callerUser) {
      return new Response(JSON.stringify({ error: 'Invalid session' }), {
        status: 401, headers: corsHeaders,
      });
    }

    // 2. Confirm the caller is actually an admin (server-enforced,
    //    not trusting anything the browser claims about itself).
    const adminClient = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);
    const { data: callerProfile } = await adminClient
      .from('users').select('is_admin').eq('id', callerUser.id).single();

    if (!callerProfile || !callerProfile.is_admin) {
      return new Response(JSON.stringify({ error: 'Admin privileges required' }), {
        status: 403, headers: corsHeaders,
      });
    }

    // 3. Parse and validate input.
    const body = await req.json();
    const { fullName, fatherName, phone, univId, email, password, role } = body;

    if (!fullName || !phone || !univId || !email || !password) {
      return new Response(JSON.stringify({ error: 'Missing required fields' }), {
        status: 400, headers: corsHeaders,
      });
    }
    if (!/^(010|011|012|015)\d{8}$/.test(phone)) {
      return new Response(JSON.stringify({ error: 'Invalid phone number' }), {
        status: 400, headers: corsHeaders,
      });
    }
    if (!/^42510\d{3}$/.test(univId)) {
      return new Response(JSON.stringify({ error: 'Invalid university ID' }), {
        status: 400, headers: corsHeaders,
      });
    }

    // 4. Create the auth user using the ADMIN API — this does NOT
    //    touch or replace the caller's session, unlike signUp().
    const { data: newAuthUser, error: createErr } = await adminClient.auth.admin.createUser({
      email, password, email_confirm: true,
    });
    if (createErr) {
      return new Response(JSON.stringify({ error: createErr.message }), {
        status: 400, headers: corsHeaders,
      });
    }

    // 5. Insert the profile row.
    const now = new Date().toISOString();
    const { error: dbErr } = await adminClient.from('users').insert({
      id: newAuthUser.user.id,
      full_name: fullName,
      father_name: fatherName || '',
      phone, university_id: univId, email,
      total_points: 0, study_sessions: 0, achievements: [],
      progress: { networks: 0, architecture: 0, dsa: 0 },
      created_at: now, updated_at: now, last_login: now,
      is_admin: role === 'admin', is_vip: role === 'vip', is_guest: false,
    });
    if (dbErr) {
      // Roll back the auth user if the profile insert failed, so we
      // don't end up with an orphaned auth account with no profile.
      await adminClient.auth.admin.deleteUser(newAuthUser.user.id);
      return new Response(JSON.stringify({ error: dbErr.message }), {
        status: 400, headers: corsHeaders,
      });
    }

    // 6. Log the action.
    await adminClient.from('admin_activity_log').insert({
      admin_id: callerUser.id,
      action: 'User added',
      details: { detail: `Created new user: ${fullName} (${role})`, color: 'green' },
    });

    return new Response(JSON.stringify({ success: true, userId: newAuthUser.user.id }), {
      status: 200, headers: corsHeaders,
    });

  } catch (e) {
    return new Response(JSON.stringify({ error: e.message || 'Unexpected error' }), {
      status: 500, headers: corsHeaders,
    });
  }
});
