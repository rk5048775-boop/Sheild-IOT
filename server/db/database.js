import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import { config } from '../config.js';

let dbInstance = null;

export function getDb() {
  if (dbInstance) return dbInstance;

  const dir = path.dirname(config.dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  dbInstance = new DatabaseSync(config.dbPath);
  initSchema(dbInstance);
  seedInitialData(dbInstance);
  return dbInstance;
}

function initSchema(db) {
  db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      kind TEXT NOT NULL,
      model TEXT NOT NULL,
      manufacturer TEXT,
      firmware TEXT,
      risk TEXT NOT NULL DEFAULT 'Low',
      status TEXT NOT NULL DEFAULT 'Protected',
      checked TEXT,
      icon TEXT DEFAULT 'router',
      isolated INTEGER DEFAULT 0,
      ip_address TEXT,
      mac_address TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS assessments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id INTEGER,
      manufacturer TEXT,
      model TEXT,
      firmware TEXT,
      score INTEGER NOT NULL,
      risk TEXT NOT NULL,
      summary TEXT,
      findings_json TEXT NOT NULL,
      recommendations_json TEXT NOT NULL,
      confidence TEXT DEFAULT 'High',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS audits (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      language TEXT NOT NULL,
      code TEXT NOT NULL,
      findings_count INTEGER DEFAULT 0,
      high_risk_count INTEGER DEFAULT 0,
      findings_json TEXT NOT NULL,
      remediation_code TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      target_device TEXT,
      severity TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Active',
      description TEXT,
      timeline_json TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS chat_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      conversation_id TEXT NOT NULL,
      role TEXT NOT NULL,
      content TEXT NOT NULL,
      evidence_level TEXT DEFAULT 'Verified Heuristics',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category TEXT NOT NULL,
      title TEXT NOT NULL,
      risk TEXT NOT NULL,
      summary TEXT,
      details_json TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      tone TEXT DEFAULT 'blue',
      details TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

function seedInitialData(db) {
  const countRow = db.prepare('SELECT COUNT(*) as count FROM devices').get();
  if (countRow.count === 0) {
    const insertDevice = db.prepare(`
      INSERT INTO devices (id, name, kind, model, manufacturer, firmware, risk, status, checked, icon, isolated, ip_address)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertDevice.run(1, 'Campus CCTV Camera', 'Camera', 'VisionGuard C20', 'VisionGuard', '2.4.1', 'High', 'Attention', '18 min ago', 'camera', 0, '192.168.1.101');
    insertDevice.run(2, 'Wi-Fi Router', 'Network', 'NexaLink R500', 'NexaLink', '1.1.8', 'Medium', 'Protected', '42 min ago', 'router', 0, '192.168.1.1');
    insertDevice.run(3, 'Biometric Access Scanner', 'Access control', 'BioEntry S2', 'BioEntry', '3.0.4', 'Low', 'Protected', '1 hr ago', 'scan', 0, '192.168.1.55');
    insertDevice.run(4, 'Smart AC Controller', 'HVAC', 'ClimateCore 4', 'ClimateCore', '1.0.2', 'High', 'Attention', '3 hrs ago', 'ac', 0, '192.168.1.82');
    insertDevice.run(5, 'Smart Lighting Controller', 'Lighting', 'LumaMesh 12', 'LumaMesh', '2.0.0', 'Low', 'Protected', 'Today, 08:30', 'light', 0, '192.168.1.90');
  }

  const reportCount = db.prepare('SELECT COUNT(*) as count FROM reports').get();
  if (reportCount.count === 0) {
    const insertReport = db.prepare(`
      INSERT INTO reports (category, title, risk, summary, details_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    insertReport.run(
      'Device assessment',
      'Campus CCTV Camera assessment',
      'High',
      'Vulnerability scan revealed unauthenticated RTSP stream and outdated firmware 2.4.1.',
      JSON.stringify({ device: 'VisionGuard C20', cves: ['CVE-2021-36260'], score: 62 }),
      'Today, 10:42'
    );
    insertReport.run(
      'Code audit',
      'Telemetry Python review',
      'High',
      'Static analysis flagged hardcoded credentials and unencrypted HTTP POST transport in telemetry script.',
      JSON.stringify({ language: 'Python', issues: 3, lineAffected: [3, 6, 7] }),
      'Today, 09:15'
    );
    insertReport.run(
      'Virtual incident',
      'CCTV DDoS scenario',
      'Medium',
      'Simulated volumetric SYN flood against edge camera node mitigated via VLAN quarantine.',
      JSON.stringify({ attack: 'SYN Flood', duration: '12m', mitigated: true }),
      'Yesterday'
    );
    insertReport.run(
      'Device assessment',
      'Wi-Fi Router assessment',
      'Medium',
      'NexaLink R500 security review: UPnP active on WAN, firmware upgrade recommended to v1.2.0.',
      JSON.stringify({ device: 'NexaLink R500', cves: [], score: 78 }),
      'Oct 21'
    );
  }

  const eventCount = db.prepare('SELECT COUNT(*) as count FROM events').get();
  if (eventCount.count === 0) {
    const insertEvent = db.prepare('INSERT INTO events (title, tone, details) VALUES (?, ?, ?)');
    insertEvent.run('Unencrypted telemetry endpoint detected', 'red', 'Campus CCTV Camera broadcasted plain HTTP on port 80');
    insertEvent.run('Virtual defense verified', 'green', 'Automated rate limiting engaged successfully');
    insertEvent.run('Scheduled assessment completed', 'blue', 'All 5 registered campus IoT nodes scanned');
    insertEvent.run('Firmware review recommended', 'orange', 'Smart AC Controller running superseded firmware build');
  }

  const incidentCount = db.prepare('SELECT COUNT(*) as count FROM incidents').get();
  if (incidentCount.count === 0) {
    const insertIncident = db.prepare(`
      INSERT INTO incidents (id, type, title, target_device, severity, status, description, timeline_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertIncident.run(
      'INC-2026-001',
      'DDoS',
      'Mirai-style Volumetric Flood on CCTV Node',
      'Campus CCTV Camera (VisionGuard C20)',
      'High',
      'Contained',
      'High rate of inbound UDP/SYN packets targeting RTSP port 554 and HTTP port 80. Caused packet drop rate > 65% and telemetry stalling.',
      JSON.stringify([
        { time: '10:14:02', event: 'Sudden spike in inbound traffic (85 Mbps) on 192.168.1.101' },
        { time: '10:15:30', event: 'Anomaly flagged by ShieldIoT Behavioral Inspector' },
        { time: '10:16:10', event: 'Virtual defense engaged: rate limiting and edge port isolation applied' },
        { time: '10:18:00', event: 'Traffic normalized; device restored to monitored quarantine VLAN' }
      ])
    );
  }
}

