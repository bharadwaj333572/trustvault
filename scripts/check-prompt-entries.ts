import fs from 'fs';
import path from 'path';

const PROMPTS_FILE_PATH = path.resolve(__dirname, '../PROMPTS.md');

interface PromptEntry {
  title: string;
  date: string;
  task: string;
  discrepancy: string;
  commitRef: string;
  isComplete: boolean;
  missingFields: string[];
}

function checkPromptEntries() {
  console.log('=====================================================');
  console.log('      TrustVault PROMPTS.md Entry Status Check       ');
  console.log('=====================================================\n');

  if (!fs.existsSync(PROMPTS_FILE_PATH)) {
    console.error('ERROR: PROMPTS.md not found!');
    process.exit(1);
  }

  const content = fs.readFileSync(PROMPTS_FILE_PATH, 'utf-8');
  const sections = content.split(/###\s+\[/);

  const completedEntries: PromptEntry[] = [];
  const missingEntries: PromptEntry[] = [];

  for (let i = 1; i < sections.length; i++) {
    const section = sections[i];
    const headerMatch = section.match(/^(.*?)]\s*-\s*(.*?)\n/);
    if (!headerMatch) continue;

    const rawDate = headerMatch[1].trim();
    const title = headerMatch[2].trim();

    const taskMatch = section.match(/-\s*\*\*Query \/ Task\*\*:\s*(.*?)\n/);
    const discrepancyMatch = section.match(/-\s*\*\*Discrepancy \/ Weakness\*\*:\s*(.*?)\n/);
    const commitMatch = section.match(/-\s*\*\*Commit Reference\*\*:\s*`?(.*?)`?\n/);

    const task = taskMatch ? taskMatch[1].trim() : '';
    const discrepancy = discrepancyMatch ? discrepancyMatch[1].trim() : '';
    const commitRef = commitMatch ? commitMatch[1].trim() : '';

    const missingFields: string[] = [];
    if (!rawDate || rawDate.includes('TODO')) missingFields.push('Date');
    if (!task || task.includes('TODO')) missingFields.push('Query / Task Summary');
    if (!discrepancy || discrepancy.includes('TODO')) missingFields.push('What Was Wrong / Discrepancy');
    if (!commitRef || commitRef.includes('TODO')) missingFields.push('Fix Commit Link / Reference');

    const entry: PromptEntry = {
      title,
      date: rawDate,
      task,
      discrepancy,
      commitRef,
      isComplete: missingFields.length === 0,
      missingFields,
    };

    if (entry.isComplete) {
      completedEntries.push(entry);
    } else {
      missingEntries.push(entry);
    }
  }

  console.log(`[COMPLETED ENTRIES: ${completedEntries.length}]`);
  for (const c of completedEntries) {
    console.log(`  ✓ [${c.date}] ${c.title}`);
    console.log(`    - Task: ${c.task}`);
    console.log(`    - Discrepancy: ${c.discrepancy}`);
    console.log(`    - Commit: ${c.commitRef}\n`);
  }

  console.log(`-----------------------------------------------------`);
  console.log(`[PENDING / MISSING ENTRIES: ${missingEntries.length}]`);
  if (missingEntries.length === 0) {
    console.log('  All human prompt log entries are 100% complete!');
  } else {
    for (const m of missingEntries) {
      console.log(`  ! [${m.date}] ${m.title}`);
      console.log(`    - Missing Fields: ${m.missingFields.join(', ')}`);
      console.log(`    - Current Task: ${m.task || 'NONE'}`);
      console.log(`    - Current Commit: ${m.commitRef || 'NONE'}\n`);
    }
  }

  console.log('=====================================================');
  console.log(`Summary: ${completedEntries.length} verified | ${missingEntries.length} awaiting human review entry.`);
  console.log('=====================================================\n');
}

checkPromptEntries();
