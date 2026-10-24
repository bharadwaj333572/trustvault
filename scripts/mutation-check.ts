import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

const POLICY_FILE_PATH = path.resolve(__dirname, '../src/server/policy/index.ts');

async function runMutationCheck() {
  console.log('=====================================================');
  console.log('  TrustVault Security Mutation Testing Verification  ');
  console.log('=====================================================\n');

  // 1. Read original policy code
  const originalPolicyCode = fs.readFileSync(POLICY_FILE_PATH, 'utf-8');

  // Verify initial state passes
  console.log('[1/4] Running baseline security tests on unmodified code...');
  try {
    execSync('npx vitest run tests/unit/policy.test.ts', { stdio: 'pipe' });
    console.log('✓ Baseline tests PASSED.\n');
  } catch (err) {
    console.error('FAIL: Baseline tests failed before mutation!');
    process.exit(1);
  }

  // 2. Introduce Mutator: Intentionally bypass policy check by allowing ungranted downloads!
  console.log('[2/4] Introducing security mutation: Disabling default DENY rule...');
  const mutatedPolicyCode = originalPolicyCode.replace(
    `  // 8. Default DENY for all ungranted users
  return {
    allowed: false,
    reason: 'NO_ACTIVE_GRANT_FOR_USER',
  };`,
    `  // MUTATION: Insecurely permit ungranted access
  return {
    allowed: true,
    reason: 'MUTATED_INSECURE_BYPASS',
  };`
  );

  fs.writeFileSync(POLICY_FILE_PATH, mutatedPolicyCode, 'utf-8');

  // 3. Run test suite against mutated code (it MUST FAIL!)
  console.log('[3/4] Running tests against mutated policy engine...');
  let mutationDetected = false;
  try {
    execSync('npx vitest run tests/unit/policy.test.ts', { stdio: 'pipe' });
    console.error('CRITICAL VULNERABILITY: Tests PASSED on mutated code! Security checks are toothless!');
  } catch (err: any) {
    mutationDetected = true;
    console.log('✓ SUCCESS: Mutation was immediately caught by the security test suite!');
  } finally {
    // 4. Always restore original policy code
    console.log('\n[4/4] Restoring original policy engine...');
    fs.writeFileSync(POLICY_FILE_PATH, originalPolicyCode, 'utf-8');
    console.log('✓ Policy code cleanly restored.');
  }

  if (mutationDetected) {
    console.log('\n=====================================================');
    console.log('  MUTATION CHECK PASSED: Policy Suite is Defensible  ');
    console.log('=====================================================\n');
    process.exit(0);
  } else {
    process.exit(1);
  }
}

runMutationCheck();
