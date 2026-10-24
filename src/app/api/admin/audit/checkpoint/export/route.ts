import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { db, schema } from '@/server/db';
import { desc } from 'drizzle-orm';
import { createCheckpoint, logAuditEvent } from '@/server/services/audit';
import { AppError } from '@/server/errors';

export async function GET(req: NextRequest) {
  const ip = req.headers.get('x-forwarded-for') || '127.0.0.1';
  const userAgent = req.headers.get('user-agent') || 'unknown';

  try {
    const cookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
    const authHeader = req.headers.get('authorization');
    const token = cookieToken || (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined);

    if (!token) {
      return NextResponse.json(
        { error: { code: 'UNAUTHENTICATED', message: 'Authentication required' } },
        { status: 401 }
      );
    }

    const { user } = await validateSession(token);

    if (user.role !== 'ADMIN') {
      return NextResponse.json(
        { error: { code: 'FORBIDDEN', message: 'Only Administrators can export audit anchor checkpoints' } },
        { status: 403 }
      );
    }

    // Get latest checkpoint or generate one
    let checkpoints = await db
      .select()
      .from(schema.chainCheckpoints)
      .orderBy(desc(schema.chainCheckpoints.sequenceNumber))
      .limit(1);

    let checkpoint = checkpoints[0];

    if (!checkpoint) {
      // Find latest audit log
      const latestLogs = await db
        .select()
        .from(schema.auditLogs)
        .orderBy(desc(schema.auditLogs.sequenceNumber))
        .limit(1);

      if (latestLogs.length > 0) {
        checkpoint = await createCheckpoint(latestLogs[0].sequenceNumber, latestLogs[0].rowHash, 'EXTERNAL');
      } else {
        return NextResponse.json(
          { error: { code: 'EMPTY_AUDIT_LOG', message: 'No audit records to anchor' } },
          { status: 400 }
        );
      }
    }

    // Record audit event for checkpoint export
    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      ipAddress: ip,
      userAgent,
      action: 'AUDIT_CHECKPOINT_EXPORTED',
      outcome: 'ALLOWED',
      details: {
        checkpointId: checkpoint.id,
        sequenceNumber: checkpoint.sequenceNumber,
        chainHeadHash: checkpoint.chainHeadHash,
      },
    });

    const exportPayload = {
      system: 'TrustVault External Audit Anchor',
      exportedAt: new Date().toISOString(),
      exportedBy: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      anchor: {
        id: checkpoint.id,
        sequenceNumber: checkpoint.sequenceNumber,
        chainHeadHash: checkpoint.chainHeadHash,
        checkpointType: checkpoint.checkpointType,
        hmacSignature: checkpoint.hmacSignature,
        createdAt: checkpoint.createdAt,
      },
      verificationInstructions:
        'Store this signed anchor in independent cold/WORM storage. In an audit, if live logs show fewer records than sequenceNumber, tail truncation has occurred.',
    };

    const jsonString = JSON.stringify(exportPayload, null, 2);

    return new NextResponse(jsonString, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="trustvault-anchor-seq-${checkpoint.sequenceNumber}.json"`,
        'X-Content-Type-Options': 'nosniff',
      },
    });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json(
      { error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to export checkpoint anchor' } },
      { status: 500 }
    );
  }
}
