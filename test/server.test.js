import test from 'node:test';
import assert from 'node:assert/strict';
import { AssessmentService } from '../server/services/assessmentService.js';
import { AuditService } from '../server/services/auditService.js';
import { AiService } from '../server/services/aiService.js';
import { SimulatorService } from '../server/services/simulatorService.js';
import { ReportService } from '../server/services/reportService.js';
import { DeviceService } from '../server/services/deviceService.js';
import { getDb } from '../server/db/database.js';

test('ShieldIoT Database Initialization & Seeding', () => {
  const db = getDb();
  assert.ok(db, 'Database should be initialized');

  const devices = db.prepare('SELECT COUNT(*) as count FROM devices').get();
  assert.ok(devices.count >= 5, 'Should have at least 5 seeded devices');

  const reports = db.prepare('SELECT COUNT(*) as count FROM reports').get();
  assert.ok(reports.count >= 4, 'Should have seeded reports');
});

test('Device Assessment Service - Camera with Outdated Firmware', () => {
  const result = AssessmentService.assess({
    manufacturer: 'VisionGuard',
    model: 'VisionGuard C20',
    firmware: '2.4.1'
  });

  assert.equal(result.device.manufacturer, 'VisionGuard');
  assert.equal(result.device.model, 'VisionGuard C20');
  assert.equal(result.risk, 'High');
  assert.ok(result.findings.length >= 2, 'Should detect multiple findings');
  assert.ok(result.score < 80, 'Score should be degraded due to vulnerabilities');
  assert.ok(result.recommendations.length > 0, 'Should provide actionable recommendations');
});

test('Device Assessment Service - Multimodal AI Vision Scan', async () => {
  const result = await AssessmentService.visionScan({
    fileName: 'cctv_camera_label.png',
    labelText: 'VisionGuard C20 Dome Camera'
  });

  assert.equal(result.success, true);
  assert.equal(result.extracted.manufacturer, 'VisionGuard');
  assert.equal(result.extracted.model, 'VisionGuard C20');
  assert.equal(result.extracted.firmware, '2.4.1');
  assert.ok(result.extracted.fccId);
  assert.ok(result.extracted.qrData);
  assert.equal(result.assessment.risk, 'High');
  assert.ok(result.assessment.findings.length > 0);
});

test('Code Security Auditor - Python Snippet with Credentials & Cleartext HTTP', () => {
  const pythonCode = `
SSID = "campus-iot"
PASSWORD = "supersecret123"

def send_status(device_id, value):
    url = "http://telemetry.example/status"
    return requests.post(url, json={"id": device_id, "value": value})
  `;

  const audit = AuditService.analyze({ code: pythonCode, language: 'Python' });

  assert.equal(audit.language, 'Python');
  assert.equal(audit.risk, 'High');
  assert.ok(audit.findings.some(f => f.cwe === 'CWE-798'), 'Should detect hardcoded credentials');
  assert.ok(audit.findings.some(f => f.cwe === 'CWE-319'), 'Should detect cleartext HTTP');
  assert.ok(audit.remediationCode.includes('TELEMETRY_ENDPOINT'), 'Should suggest secure remediation pattern');
});

test('Code Security Auditor - C/Arduino Buffer Overflow Check', () => {
  const cCode = `
void handle_packet(char *payload) {
    char buffer[64];
    strcpy(buffer, payload);
}
  `;

  const audit = AuditService.analyze({ code: cCode, language: 'C++' });
  assert.ok(audit.findings.some(f => f.cwe === 'CWE-120'), 'Should detect buffer overflow via strcpy');
});

test('AI Security Assistant - Chat Query & Reasoning', async () => {
  const res = await AiService.chat({
    message: 'Explain the security risks in this camera assessment.'
  });

  assert.equal(res.role, 'ai');
  assert.ok(res.text.length > 50, 'Should provide thorough explanation');
  assert.ok(res.evidence, 'Should provide evidence boundary');
});

test('Incident Explainer - Root Cause Analysis', () => {
  const rca = AiService.explainIncident({ incidentId: 'INC-2026-001' });

  assert.ok(rca.title);
  assert.ok(rca.rootCauseAnalysis.attackVector);
  assert.ok(rca.remediationSteps.length > 0);
});

test('Attack Simulator - DDoS Scenario & Device Isolation', () => {
  const sim = SimulatorService.runScenario({ type: 'DDoS active', targetId: 1 });
  assert.equal(sim.type, 'DDoS active');

  const isolation = SimulatorService.isolateDevice(1);
  assert.equal(isolation.isolated, true);
  assert.equal(isolation.status, 'Isolated');

  const restoration = SimulatorService.restoreDevice(1);
  assert.equal(restoration.isolated, false);
});

test('Reports Service - List & Filter', () => {
  const reports = ReportService.list({ category: 'All' });
  assert.ok(Array.isArray(reports));
  assert.ok(reports.length > 0);

  const filtered = ReportService.list({ category: 'Code audit' });
  assert.ok(filtered.every(r => r.category === 'Code audit'));
});

test('Device Service - Overview Dashboard Aggregation', () => {
  const overview = DeviceService.getOverview();
  assert.ok(overview.metrics.devicesAssessed >= 5);
  assert.equal(overview.postureTrend.length, 7);
  assert.equal(overview.riskDistribution.length, 3);
  assert.ok(Array.isArray(overview.devices));
});

