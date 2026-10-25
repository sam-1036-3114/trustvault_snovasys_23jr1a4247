'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';
import { AppShell } from '@/components/sidebar';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { FileText, Download, Shield, Activity, Users, AlertTriangle, CheckCircle2 } from 'lucide-react';
import type { Document, AuditEvent } from '@/lib/types';
import { Skeleton } from '@/components/ui/skeleton';
import { Badge } from '@/components/ui/badge';

export default function DashboardPage() {
  const { user, profile, loading, error: authError } = useAuth();
  const router = useRouter();
  const [stats, setStats] = useState<{
    totalDocuments: number;
    deniedAttempts: number;
    permissionChanges: number;
    recentEvents: AuditEvent[];
    auditIntegrity: { is_valid: boolean; total_events: number } | null;
  } | null>(null);
  const [dataLoading, setDataLoading] = useState(true);

  useEffect(() => {
    if (!loading && !user) router.push('/login');
    if (!loading && user && profile?.status === 'suspended') router.push('/access-denied');
  }, [loading, user, profile, router]);

  useEffect(() => {
    if (user) {
      Promise.all([
        fetch('/api/documents?pageSize=5').then(r => r.json()),
        fetch('/api/audit?pageSize=5').then(r => r.json()),
        fetch('/api/audit/verify').then(r => r.json()),
      ]).then(([docsData, auditData, integrityData]) => {
        setStats({
          totalDocuments: docsData.total || 0,
          deniedAttempts: auditData.events?.filter((e: AuditEvent) => e.outcome === 'denied').length || 0,
          permissionChanges: 0,
          recentEvents: auditData.events || [],
          auditIntegrity: integrityData,
        });
        setDataLoading(false);
      }).catch(() => setDataLoading(false));
    }
  }, [user]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Skeleton className="h-12 w-12 rounded-full" />
      </div>
    );
  }

  if (!user || !profile) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background p-6">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>Unable to load your account</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              {authError || 'Your account details are unavailable right now.'}
            </p>
            <button
              type="button"
              className="mt-6 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
              onClick={() => router.push('/login')}
            >
              Return to sign in
            </button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const cards = [
    { label: 'Total Documents', value: stats?.totalDocuments ?? 0, icon: FileText, color: 'text-primary' },
    { label: 'Recent Denied Access', value: stats?.deniedAttempts ?? 0, icon: AlertTriangle, color: 'text-warning' },
    { label: 'Audit Events', value: stats?.auditIntegrity?.total_events ?? 0, icon: Activity, color: 'text-primary' },
    { label: 'Audit Integrity', value: stats?.auditIntegrity?.is_valid ? 'Verified' : 'Check', icon: Shield, color: stats?.auditIntegrity?.is_valid ? 'text-success' : 'text-destructive' },
  ];

  return (
    <AppShell>
      <div className="mb-8">
        <h1 className="text-2xl font-bold">Welcome back, {profile.display_name}</h1>
        <p className="mt-1 text-muted-foreground">Here&apos;s an overview of your TrustVault activity</p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {cards.map((card) => {
          const Icon = card.icon;
          return (
            <Card key={card.label}>
              <CardContent className="flex items-center gap-4 p-5">
                <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
                  <Icon className={`h-6 w-6 ${card.color}`} />
                </div>
                <div>
                  <p className="text-2xl font-bold">{card.value}</p>
                  <p className="text-sm text-muted-foreground">{card.label}</p>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <div className="mt-8 grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-primary" />
              Recent Activity
            </CardTitle>
          </CardHeader>
          <CardContent>
            {dataLoading ? (
              <div className="space-y-3">
                {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
              </div>
            ) : stats?.recentEvents?.length ? (
              <div className="space-y-3">
                {stats.recentEvents.slice(0, 6).map((event) => (
                  <div key={event.id} className="flex items-center gap-3 border-b pb-2 last:border-0">
                    <div className={`h-2 w-2 rounded-full ${event.outcome === 'denied' ? 'bg-destructive' : event.outcome === 'success' ? 'bg-success' : 'bg-warning'}`} />
                    <div className="flex-1 min-w-0">
                      <p className="truncate text-sm font-medium">{event.action.replace(/_/g, ' ')}</p>
                      <p className="text-xs text-muted-foreground">{new Date(event.event_timestamp).toLocaleString()}</p>
                    </div>
                    <Badge variant={event.outcome === 'denied' ? 'destructive' : event.outcome === 'success' ? 'default' : 'secondary'}>
                      {event.outcome}
                    </Badge>
                  </div>
                ))}
              </div>
            ) : (
              <p className="py-8 text-center text-sm text-muted-foreground">No recent activity</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-primary" />
              Security Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className={`h-5 w-5 ${stats?.auditIntegrity?.is_valid ? 'text-success' : 'text-destructive'}`} />
                  <span className="text-sm">Audit Chain Integrity</span>
                </div>
                <Badge variant={stats?.auditIntegrity?.is_valid ? 'default' : 'destructive'}>
                  {stats?.auditIntegrity?.is_valid ? 'Valid' : 'Tampered'}
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-primary" />
                  <span className="text-sm">Your Role</span>
                </div>
                <Badge variant="secondary">{profile.role}</Badge>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Users className="h-5 w-5 text-primary" />
                  <span className="text-sm">Account Status</span>
                </div>
                <Badge variant={profile.status === 'active' ? 'default' : 'destructive'}>{profile.status}</Badge>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileText className="h-5 w-5 text-primary" />
                  <span className="text-sm">Total Audit Events</span>
                </div>
                <span className="text-sm font-bold">{stats?.auditIntegrity?.total_events ?? 0}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
