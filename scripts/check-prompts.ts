import fs from 'fs';
import path from 'path';

const PROMPTS_FILE_PATH = path.resolve(__dirname, '../PROMPTS.md');

interface PromptLogEntry {
  rawHeader: string;
  date: string;
  title: string;
  queryTask: string;
  resultOutput: string;
  discrepancyWeakness: string;
  resolution: string;
  commitRef: string;
  isAuthOrAuditRelated: boolean;
}

function verifyPromptsIntegrity(): void {
  console.log('================================================================');
  console.log('        TrustVault PROMPTS.md Verification Enforcement           ');
  console.log('================================================================\n');

  if (!fs.existsSync(PROMPTS_FILE_PATH)) {
    console.error('FAIL: PROMPTS.md file not found at ' + PROMPTS_FILE_PATH);
    process.exit(1);
  }

  const content = fs.readFileSync(PROMPTS_FILE_PATH, 'utf-8');

  // Split on section headers matching "### [YYYY-MM-DD"
  const sections = content.split(/\n###\s+\[/);
  const entries: PromptLogEntry[] = [];
  const errors: string[] = [];

  for (let i = 1; i < sections.length; i++) {
    const rawSection = sections[i];
    const headerEndIndex = rawSection.indexOf('\n');
    if (headerEndIndex === -1) continue;

    const headerLine = rawSection.slice(0, headerEndIndex);
    const dateMatch = headerLine.match(/^(.*?)]\s*-\s*(.*?)$/);
    if (!dateMatch) continue;

    const dateStr = dateMatch[1].trim();
    const titleStr = dateMatch[2].trim();

    // Skip template and TODO placeholders
    if (dateStr.includes('YYYY') || dateStr.includes('TODO')) continue;

    // Check mandatory fields:
    // 1. What I asked (Query / Task)
    const taskMatch = rawSection.match(/-\s*\*\*Query \/ Task\*\*:\s*(.*?)(?=\n-|\n\n|$)/s);
    // 2. What it produced (Result / Model Output)
    const outputMatch = rawSection.match(/-\s*\*\*Result \/ Model Output\*\*:\s*(.*?)(?=\n-|\n\n|$)/s);
    // 3. What was wrong (Discrepancy / Weakness)
    const discrepancyMatch = rawSection.match(/-\s*\*\*Discrepancy \/ Weakness\*\*:\s*(.*?)(?=\n-|\n\n|$)/s);
    // 4. What I did instead (Resolution)
    const resolutionMatch = rawSection.match(/-\s*\*\*Resolution\*\*:\s*(.*?)(?=\n-|\n\n|$)/s);
    // 5. Commit link (Commit Reference)
    const commitMatch = rawSection.match(/-\s*\*\*Commit Reference\*\*:\s*`?(.*?)`?(?=\n|$)/);

    const queryTask = taskMatch ? taskMatch[1].trim() : '';
    const resultOutput = outputMatch ? outputMatch[1].trim() : '';
    const discrepancyWeakness = discrepancyMatch ? discrepancyMatch[1].trim() : '';
    const resolution = resolutionMatch ? resolutionMatch[1].trim() : '';
    const commitRef = commitMatch ? commitMatch[1].trim() : '';

    const missingFields: string[] = [];
    if (!queryTask) missingFields.push('what I asked (Query / Task)');
    if (!resultOutput) missingFields.push('what it produced (Result / Model Output)');
    if (!discrepancyWeakness) missingFields.push('what was wrong (Discrepancy / Weakness)');
    if (!resolution) missingFields.push('what I did instead (Resolution)');
    if (!commitRef) missingFields.push('commit link (Commit Reference)');

    if (missingFields.length > 0) {
      errors.push(`Entry [${dateStr}] "${titleStr}" is missing required fields: ${missingFields.join(', ')}`);
    }

    const fullEntryText = (rawSection + ' ' + titleStr).toLowerCase();
    const isAuthOrAuditRelated =
      fullEntryText.includes('authoriz') ||
      fullEntryText.includes('access control') ||
      fullEntryText.includes('audit') ||
      fullEntryText.includes('revocation') ||
      fullEntryText.includes('permission') ||
      fullEntryText.includes('grant');

    entries.push({
      rawHeader: headerLine,
      date: dateStr,
      title: titleStr,
      queryTask,
      resultOutput,
      discrepancyWeakness,
      resolution,
      commitRef,
      isAuthOrAuditRelated,
    });
  }

  console.log(`Parsed ${entries.length} dated post-mortem entries in PROMPTS.md:\n`);
  for (const e of entries) {
    const tag = e.isAuthOrAuditRelated ? '[AUTH/AUDIT]' : '[ENGINEERING]';
    console.log(`  ✓ [${e.date}] ${tag} ${e.title} (commit: ${e.commitRef})`);
  }
  console.log('');

  // RULE 1: Minimum 5 dated entries
  if (entries.length < 5) {
    errors.push(`PROMPTS.md has only ${entries.length} dated entries. At least 5 dated entries are required.`);
  }

  // RULE 2: Minimum 2 entries about authorization, access control, or audit trail
  const authAuditCount = entries.filter((e) => e.isAuthOrAuditRelated).length;
  if (authAuditCount < 2) {
    errors.push(`PROMPTS.md has only ${authAuditCount} entries related to authorization/audit. At least 2 are required.`);
  }

  if (errors.length > 0) {
    console.error('================================================================');
    console.error('           PROMPTS.md VERIFICATION FAILED:                      ');
    console.error('================================================================');
    for (const err of errors) {
      console.error('  FAIL: ' + err);
    }
    process.exit(1);
  }

  console.log('================================================================');
  console.log(`✓ SUCCESS: ${entries.length} valid dated entries verified.`);
  console.log(`✓ ${authAuditCount} entries verified regarding authorization/audit integrity.`);
  console.log('================================================================\n');
}

verifyPromptsIntegrity();
