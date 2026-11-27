import { createContext, useContext, useEffect, useState } from 'react';
import { isSupabaseConfigured, supabase } from '../services/supabaseClient';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!isSupabaseConfigured || !supabase) {
      setLoading(false);
      return undefined;
    }

    let mounted = true;

    async function loadProfile(userId) {
      const { data } = await supabase
        .from('profiles')
        .select('id, full_name, email')
        .eq('id', userId)
        .maybeSingle();
      if (mounted) {
        setProfile(data || null);
      }
    }

    supabase.auth.getSession().then(({ data }) => {
      if (!mounted) return;
      const sessionUser = data?.session?.user ?? null;
      setUser(sessionUser);
      setLoading(false);
      if (sessionUser) {
        loadProfile(sessionUser.id);
      }
    });

    const { data: listener } = supabase.auth.onAuthStateChange((_event, session) => {
      if (!mounted) return;
      const sessionUser = session?.user ?? null;
      setUser(sessionUser);
      setLoading(false);
      if (sessionUser) {
        loadProfile(sessionUser.id);
      } else {
        setProfile(null);
      }
    });

    return () => {
      mounted = false;
      listener?.subscription?.unsubscribe();
    };
  }, []);

  async function signIn(email, password) {
    if (!supabase) {
      throw new Error('Supabase environment variables are not configured.');
    }
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) {
      throw new Error(error.message || 'Authentication failed');
    }
    return data;
  }

  async function signOut() {
    if (!supabase) return;
    const { error } = await supabase.auth.signOut();
    if (error) {
      throw new Error(error.message || 'Sign out failed');
    }
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        profile,
        loading,
        isConfigured: isSupabaseConfigured,
        signIn,
        signOut,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used inside AuthProvider');
  }
  return ctx;
}
