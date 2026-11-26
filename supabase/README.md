# Log Sentinel — Supabase Setup & Phase 2 Migration Guide

## 1. Create Your Free Supabase Project
1. Sign in to Supabase and create a new project on the **Free** tier (name it e.g. `log-sentinel`).
2. Save your database password safely (never commit it to Git).
3. Under **Project Settings → API**, note:
   - **Project URL** (`VITE_SUPABASE_URL`)
   - **anon / public key** (`VITE_SUPABASE_ANON_KEY`)
   - **service_role key** (for Edge Function secrets in Phase 5 — never put in `frontend/` or `collector/`).

## 2. Apply Phase 2 Migrations (SQL Editor Method — No Docker Needed)
Open **SQL Editor → New Query** in the Supabase Dashboard and run these files **in order**:
1. `supabase/migrations/202611260001_initial_schema.sql`
2. `supabase/migrations/202611260002_rls_policies.sql`
3. `supabase/migrations/202611260003_functions_views_realtime.sql`

## 3. Verify Schema, RLS & Deduplication
Run `supabase/seed/verify_phase2_rls.sql` in the SQL Editor.
- It executes inside a `BEGIN; ... ROLLBACK;` transaction so it leaves zero test data behind.
- You should see the notice: `ALL PHASE 2 VERIFICATION CHECKS PASSED`.

## 4. Create Your First Admin User
1. Go to **Authentication → Users → Add user → Create new user**.
2. Enter your admin email and a strong password (check **Auto Confirm User**).
3. Verify in **Table Editor → `profiles`** that your admin profile row was created automatically by the `on_auth_user_created` trigger.
