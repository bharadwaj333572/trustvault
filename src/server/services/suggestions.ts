import { db, schema } from '../db';
import { eq, and, ne, sql, desc, inArray } from 'drizzle-orm';
import { getDocumentWithAuthorization } from './documents';
import { logAuditEvent } from './audit';
import { AuthenticatedUser } from '../auth/session';
import { AppError } from '../errors';

export interface SharingSuggestion {
  userId: string;
  email: string;
  fullName: string;
  suggestedPermission: 'READ' | 'EDIT';
  confidenceScore: number; // 0.0 to 1.0
  reason: string;
}

/**
 * AI Sharing Suggestions Engine.
 * 
 * CORE SECURITY INVARIANTS:
 * 1. NEVER receives or processes document file contents or storage payloads.
 * 2. NEVER creates, modifies, or widens access permissions on its own.
 * 3. Only suggests candidates based on metadata category patterns and historical collaboration.
 * 4. All suggestions MUST be explicitly reviewed and confirmed by a human.
 * 5. Logs 'SUGGESTION_SHOWN' in the tamper-evident audit hash chain.
 */
export async function getSharingSuggestions(
  user: AuthenticatedUser,
  documentId: string,
  clientIp?: string,
  userAgent?: string,
  requestId?: string
): Promise<SharingSuggestion[]> {
  // 1. Verify owner authorization via central policy
  const { document } = await getDocumentWithAuthorization(user, documentId, 'share', clientIp, userAgent, requestId);

  // 2. Fetch existing active grants on this document to exclude people who already have access
  const existingGrants = await db
    .select({ userId: schema.documentGrants.userId })
    .from(schema.documentGrants)
    .where(eq(schema.documentGrants.documentId, documentId));

  const alreadyGrantedUserIds = new Set(existingGrants.map((g) => g.userId));
  alreadyGrantedUserIds.add(user.id); // Exclude owner

  // 3. Analyze previous grants made by this owner on documents within the same category
  const categoryDocs = await db
    .select({ id: schema.documents.id })
    .from(schema.documents)
    .where(
      and(
        eq(schema.documents.ownerId, user.id),
        eq(schema.documents.category, document.category),
        ne(schema.documents.id, documentId)
      )
    );

  const categoryDocIds = categoryDocs.map((d) => d.id);

  const candidateScores = new Map<string, { count: number; preferredPermission: 'READ' | 'EDIT' }>();

  if (categoryDocIds.length > 0) {
    const historicalGrants = await db
      .select({
        userId: schema.documentGrants.userId,
        permission: schema.documentGrants.permission,
      })
      .from(schema.documentGrants)
      .where(inArray(schema.documentGrants.documentId, categoryDocIds));

    for (const hg of historicalGrants) {
      if (!alreadyGrantedUserIds.has(hg.userId)) {
        const current = candidateScores.get(hg.userId) || { count: 0, preferredPermission: 'READ' };
        candidateScores.set(hg.userId, {
          count: current.count + 2, // Higher weight for same category
          preferredPermission: hg.permission as 'READ' | 'EDIT',
        });
      }
    }
  }

  // 4. Also fetch other available active users in system (excluding disabled accounts)
  const availableUsers = await db
    .select({
      id: schema.users.id,
      email: schema.users.email,
      fullName: schema.users.fullName,
      role: schema.users.role,
      isDisabled: schema.users.isDisabled,
    })
    .from(schema.users)
    .where(
      and(
        ne(schema.users.id, user.id),
        eq(schema.users.isDisabled, false)
      )
    );

  const suggestions: SharingSuggestion[] = [];

  for (const u of availableUsers) {
    if (alreadyGrantedUserIds.has(u.id)) continue;

    const historical = candidateScores.get(u.id);

    if (historical) {
      suggestions.push({
        userId: u.id,
        email: u.email,
        fullName: u.fullName,
        suggestedPermission: historical.preferredPermission,
        confidenceScore: Math.min(0.6 + historical.count * 0.1, 0.95),
        reason: `Frequently shared on ${document.category} documents (${historical.count} previous grants)`,
      });
    } else if (u.role === 'VIEWER') {
      // Suggest active viewers as general candidates
      suggestions.push({
        userId: u.id,
        email: u.email,
        fullName: u.fullName,
        suggestedPermission: 'READ',
        confidenceScore: 0.45,
        reason: `Active auditor / viewer in workspace`,
      });
    }
  }

  const sortedSuggestions = suggestions
    .sort((a, b) => b.confidenceScore - a.confidenceScore)
    .slice(0, 3);

  // 5. Audit: Log that suggestions were shown
  await logAuditEvent({
    actorId: user.id,
    actorEmail: user.email,
    actorRole: user.role,
    ipAddress: clientIp,
    userAgent,
    documentId,
    action: 'SUGGESTION_SHOWN',
    outcome: 'ALLOWED',
    reason: 'AI_SHARING_SUGGESTIONS_DISPLAYED',
    details: {
      candidateCount: sortedSuggestions.length,
      candidateEmails: sortedSuggestions.map((s) => s.email),
      category: document.category,
    },
    requestId,
  });

  return sortedSuggestions;
}

/**
 * Records user confirmation or rejection of an AI sharing suggestion.
 */
export async function recordSuggestionFeedback(
  user: AuthenticatedUser,
  documentId: string,
  targetEmail: string,
  accepted: boolean,
  clientIp?: string,
  userAgent?: string,
  requestId?: string
) {
  await logAuditEvent({
    actorId: user.id,
    actorEmail: user.email,
    actorRole: user.role,
    ipAddress: clientIp,
    userAgent,
    documentId,
    action: accepted ? 'SUGGESTION_ACCEPTED' : 'SUGGESTION_REJECTED',
    outcome: 'ALLOWED',
    reason: accepted ? 'USER_ACCEPTED_AI_SUGGESTION' : 'USER_DISMISSED_AI_SUGGESTION',
    details: { targetEmail, accepted },
    requestId,
  });

  return { success: true };
}
