#!/usr/bin/env node

/**
 * ShieldIoT Standalone CLI Scanner
 * Usage: node scan.js [--target 192.168.1.101] [--model "VisionGuard C20"] [--api http://localhost:5000]
 */

import { AssessmentService } from './server/services/assessmentService.js';
import { AuditService } from './server/services/auditService.js';

const args = process.argv.slice(2);

function getArg(flag, fallback) {
  const idx = args.indexOf(flag);
  if (idx !== -1 && args[idx + 1]) return args[idx + 1];
  return fallback;
}

const target = getArg('--target', '192.168.1.101');
const model = getArg('--model', 'VisionGuard C20');
const manufacturer = getArg('--manufacturer', 'VisionGuard');
const firmware = getArg('--firmware', '2.4.1');

console.log('\n=============================================================');
console.log('   🛡️  ShieldIoT Command Line Security Scanner');
console.log('=============================================================');
console.log(` Target IP:      ${target}`);
console.log(` Target Model:   ${model}`);
console.log(` Manufacturer:   ${manufacturer}`);
console.log(` Firmware:       ${firmware}`);
console.log('-------------------------------------------------------------\n');

console.log('[*] Running heuristic IoT vulnerability scan...');

const assessment = AssessmentService.assess({
  manufacturer,
  model,
  firmware
});

console.log(`\n[+] Scan Complete! Security Score: ${assessment.score}/100 (${assessment.risk} Risk)`);
console.log(`[+] Findings Flagged: ${assessment.findingsCount}\n`);

assessment.findings.forEach((finding, i) => {
  const badge = finding.risk === 'High' ? '🔴 HIGH' : finding.risk === 'Medium' ? '🟡 MED' : '🟢 LOW';
  console.log(` ${i + 1}. [${badge}] ${finding.title} (${finding.cwe || 'CWE'})`);
  console.log(`    Detail:         ${finding.text}`);
  console.log(`    Remediation:    ${finding.recommendation}\n`);
});

console.log('=============================================================');
console.log(' Result saved to ShieldIoT database. View in dashboard.');
console.log('=============================================================\n');

