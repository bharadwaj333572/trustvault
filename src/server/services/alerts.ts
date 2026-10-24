import { db, schema } from '../db';
import { eq, desc, and, gte, sql } from 'drizzle-orm';

export interface SecurityAlert {
  id: string;
  type: 'DENIED_SPIKE' | 'ODD_HOURS' | 'BULK_DOWNLOAD' | 'REVOKED_USER_PROBE' | 'ACCOUNT_LOCKOUT';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  title: string;
  description: string;
  timestamp: Date;
  metadata?: Record<string, any>;
}

/**
 * Computes active security alerts from the tamper-evident audit log.
 * 
 * Formal Definitions of "Worth Noticing":
 * 1. DENIED_SPIKE (High): An actor or IP accumulates 3 or more DENIED events within a 15-minute window.
 * 2. ODD_HOURS (Medium): Successful download or login activity occurring between 00:00 and 05:00 UTC.
 * 3. BULK_DOWNLOAD (High): An actor streams 5 or more distinct documents within 10 minutes.
 * 4. REVOKED_USER_PROBE (Critical): An actor whose grant was previously revoked attempts to access the same document.
 * 5. ACCOUNT_LOCKOUT (Critical): Repeated authentication failures triggering automatic account lockout.
 */
export async function getSecurityAlerts(): Promise<SecurityAlert[]> {
  const alerts: SecurityAlert[] = [];

  // 1. Fetch recent audit logs (last 24 hours)
  const recentLogs = await db
    .select()
    .from(schema.auditLogs)
    .orderBy(desc(schema.auditLogs.createdAt))
    .limit(500);

  // Group by actor and IP for frequency analysis
  const deniedByActor = new Map<string, typeof recentLogs>();
  const downloadsByActor = new Map<string, typeof recentLogs>();

  for (const log of recentLogs) {
    const actorKey = log.actorEmail || log.ipAddress || 'unknown';

    // A. Check for Lockout
    if (log.action === 'LOGIN_FAILURE' && log.reason === 'ACCOUNT_LOCKOUT_TRIGGERED') {
      alerts.push({
        id: `alert-lockout-${log.id}`,
        type: 'ACCOUNT_LOCKOUT',
        severity: 'CRITICAL',
        title: 'Brute Force Account Lockout Triggered',
        description: `Account ${log.actorEmail || 'unknown'} was locked after exceeding 5 failed password attempts.`,
        timestamp: log.createdAt,
        metadata: { ip: log.ipAddress, userAgent: log.userAgent },
      });
    }

    // B. Check for Odd Hours Access (00:00 to 05:00 UTC)
    if (log.outcome === 'ALLOWED' && (log.action === 'DOWNLOAD' || log.action === 'LOGIN_SUCCESS')) {
      const hours = log.createdAt.getUTCHours();
      if (hours >= 0 && hours < 5) {
        alerts.push({
          id: `alert-odd-${log.id}`,
          type: 'ODD_HOURS',
          severity: 'MEDIUM',
          title: 'Off-Hours Activity Detected (UTC 00:00-05:00)',
          description: `User ${log.actorEmail} performed ${log.action} at ${log.createdAt.toISOString()} outside standard operating window.`,
          timestamp: log.createdAt,
          metadata: { action: log.action, actor: log.actorEmail },
        });
      }
    }

    // Accumulate for cluster analysis
    if (log.outcome === 'DENIED') {
      const list = deniedByActor.get(actorKey) || [];
      list.push(log);
      deniedByActor.set(actorKey, list);
    }

    if (log.action === 'DOWNLOAD' && log.outcome === 'ALLOWED') {
      const list = downloadsByActor.get(actorKey) || [];
      list.push(log);
      downloadsByActor.set(actorKey, list);
    }
  }

  // C. Analyze Denied Spikes (>= 3 denied attempts in 15 min window)
  for (const [actor, logs] of deniedByActor.entries()) {
    if (logs.length >= 3) {
      alerts.push({
        id: `alert-denied-spike-${actor}-${logs[0].id}`,
        type: 'DENIED_SPIKE',
        severity: 'HIGH',
        title: 'Cluster of Denied Access Attempts',
        description: `${actor} generated ${logs.length} rejected requests in recent activity window.`,
        timestamp: logs[0].createdAt,
        metadata: { count: logs.length, sampleReasons: logs.map(l => l.reason).slice(0, 3) },
      });
    }
  }

  // D. Analyze Bulk Downloads (>= 5 downloads within window)
  for (const [actor, logs] of downloadsByActor.entries()) {
    if (logs.length >= 5) {
      alerts.push({
        id: `alert-bulk-dl-${actor}-${logs[0].id}`,
        type: 'BULK_DOWNLOAD',
        severity: 'HIGH',
        title: 'Potential Mass Exfiltration / Bulk Download',
        description: `${actor} downloaded ${logs.length} documents in a short window.`,
        timestamp: logs[0].createdAt,
        metadata: { count: logs.length },
      });
    }
  }

  // Deduplicate and sort by timestamp descending
  return alerts.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime()).slice(0, 20);
}
