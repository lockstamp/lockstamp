// DEMO MISTAKE: VITE_ variables are bundled into the website, so this "secret" is public.
export const adminKey = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY;
