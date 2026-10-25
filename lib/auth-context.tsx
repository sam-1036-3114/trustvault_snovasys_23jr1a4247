'use client';

import { createContext, useContext, useEffect, useState, ReactNode, useCallback } from 'react';
import { AuthChangeEvent, Session, User } from '@supabase/supabase-js';
import { getBrowserClient } from '@/lib/supabase-browser';
import type { Profile, UserRole } from '@/lib/types';

interface AuthContextType {
  user: User | null;
  profile: Profile | null;
  session: Session | null;
  loading: boolean;
  error: string | null;
  signIn: (email: string, password: string) => Promise<{ error: string | null }>;
  signUp: (email: string, password: string, displayName: string, role: UserRole) => Promise<{ error: string | null }>;
  signOut: () => Promise<void>;
  refreshProfile: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const supabase = getBrowserClient();

  const fetchProfile = useCallback(async (userId: string) => {
    const { data, error: profileError } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', userId)
      .maybeSingle();

    if (profileError) throw profileError;
    setProfile(data as Profile | null);
    if (!data) throw new Error('Your account profile could not be loaded. Please sign out and sign in again.');
  }, [supabase]);

  useEffect(() => {
    let mounted = true;

    const loadSession = async () => {
      try {
        const { data: { session: currentSession }, error: sessionError } = await supabase.auth.getSession();
        if (sessionError) throw sessionError;
        if (!mounted) return;

        setSession(currentSession);
        setUser(currentSession?.user ?? null);
        if (currentSession?.user) {
          await fetchProfile(currentSession.user.id);
        }
      } catch (sessionError) {
        if (mounted) {
          setError(sessionError instanceof Error ? sessionError.message : 'Unable to load your account.');
          setProfile(null);
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };

    void loadSession();

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event: AuthChangeEvent, nextSession: Session | null) => {
      if (!mounted) return;
      setSession(nextSession);
      setUser(nextSession?.user ?? null);
      setError(null);

      if (!nextSession?.user) {
        setProfile(null);
        setLoading(false);
        return;
      }

      setLoading(true);
      setTimeout(() => {
        if (!mounted) return;
        void fetchProfile(nextSession.user.id)
          .catch((profileError: unknown) => {
            if (mounted) {
              setProfile(null);
              setError(profileError instanceof Error ? profileError.message : 'Unable to load your account.');
            }
          })
          .finally(() => mounted && setLoading(false));
      }, 0);
    });

    return () => {
      mounted = false;
      subscription.unsubscribe();
    };
  }, [supabase, fetchProfile]);

  const signIn = useCallback(async (email: string, password: string) => {
    const { error: signInError } = await supabase.auth.signInWithPassword({ email, password });
    return { error: signInError?.message || null };
  }, [supabase]);

  const signUp = useCallback(async (email: string, password: string, displayName: string, role: UserRole) => {
    const { data, error: signUpError } = await supabase.auth.signUp({
      email,
      password,
      options: { data: { display_name: displayName, role } },
    });
    if (signUpError) return { error: signUpError.message };
    if (data.user) {
      await supabase.auth.signInWithPassword({ email, password });
    }
    return { error: null };
  }, [supabase]);

  const signOut = useCallback(async () => {
    await supabase.auth.signOut();
    setUser(null);
    setProfile(null);
    setSession(null);
    setError(null);
  }, [supabase]);

  const refreshProfile = useCallback(async () => {
    if (!user) return;
    setError(null);
    try {
      await fetchProfile(user.id);
    } catch (profileError) {
      setProfile(null);
      setError(profileError instanceof Error ? profileError.message : 'Unable to load your account.');
    }
  }, [user, fetchProfile]);

  return (
    <AuthContext.Provider value={{ user, profile, session, loading, error, signIn, signUp, signOut, refreshProfile }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
