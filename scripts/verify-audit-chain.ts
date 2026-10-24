import { verifyChain } from '../src/server/services/audit';

async function main() {
  console.log('=====================================================');
  console.log('  TrustVault Tamper-Evident Audit Chain Verifier     ');
  console.log('=====================================================\n');

  try {
    const result = await verifyChain();

    if (result.valid) {
      console.log('STATUS: [ CHAIN VERIFIED ]');
      console.log(`Total verified audit blocks: ${result.totalEntries}`);
      console.log(`Highest verified sequence: #${result.lastVerifiedSequence}`);
      console.log('Cryptographic integrity: 100% Intact. No tampering detected.\n');
      process.exit(0);
    } else {
      console.error('STATUS: [ TAMPERING DETECTED ]');
      console.error(`Broken at sequence: #${result.brokenAtSequence}`);
      console.error(`Compromised row ID: ${result.brokenRowId}`);
      console.error(`Reason: ${result.reason}`);
      console.error(`Expected Hash: ${result.expectedHash}`);
      console.error(`Actual Hash:   ${result.actualHash}\n`);
      process.exit(1);
    }
  } catch (err: any) {
    console.error('Fatal verification error:', err);
    process.exit(1);
  }
}

main();
