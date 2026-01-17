import { createClient } from '@supabase/supabase-js';


const supabaseUrl = process.env.REACT_APP_SUPABASE_URL || process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.REACT_APP_SUPABASE_ANON_KEY || process.env.SUPABASE_KEY;

// Security: Don't log sensitive credentials
if (typeof window !== 'undefined' && process.env.NODE_ENV === 'development') {
    // eslint-disable-next-line no-console
    console.log('[DEBUG] Supabase configured:', isSupabaseConfigured);
}

export const isSupabaseConfigured = Boolean(supabaseUrl && supabaseAnonKey);

export const supabase = isSupabaseConfigured
    ? createClient(supabaseUrl, supabaseAnonKey, {
        auth: {
            persistSession: true,
            detectSessionInUrl: true
        }
    })
    : null;

if (!isSupabaseConfigured && typeof window !== 'undefined') {
    // eslint-disable-next-line no-console
    console.warn(
        'Supabase environment variables are not set. Provide REACT_APP_SUPABASE_URL and REACT_APP_SUPABASE_ANON_KEY (or their SUPABASE_URL / SUPABASE_KEY equivalents) to enable authentication.'
    );
}
