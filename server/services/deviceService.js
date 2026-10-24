import { getDb } from '../db/database.js';

export class DeviceService {
  /**
   * Get all registered IoT devices
   */
  static list() {
    const db = getDb();
    const rows = db.prepare('SELECT * FROM devices ORDER BY id ASC').all();
    return rows.map(formatDevice);
  }

  /**
   * Get a single device by ID
   */
  static getById(id) {
    const db = getDb();
    const row = db.prepare('SELECT * FROM devices WHERE id = ?').get(parseInt(id, 10));
    return row ? formatDevice(row) : null;
  }

  /**
   * Create a new device
   */
  static create(payload = {}) {
    const db = getDb();
    const name = payload.name || 'New IoT Device';
    const kind = payload.kind || 'Network';
    const model = payload.model || 'Generic Model';
    const manufacturer = payload.manufacturer || 'Generic';
    const firmware = payload.firmware || '1.0.0';
    const risk = payload.risk || 'Low';
    const status = payload.status || 'Protected';
    const checked = 'Just now';
    const icon = payload.icon || 'router';
    const ip = payload.ip_address || '192.168.1.150';

    const insert = db.prepare(`
      INSERT INTO devices (name, kind, model, manufacturer, firmware, risk, status, checked, icon, ip_address)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const info = insert.run(name, kind, model, manufacturer, firmware, risk, status, checked, icon, ip);
    return DeviceService.getById(info.lastInsertRowid);
  }

  /**
   * Update a device
   */
  static update(id, payload = {}) {
    const db = getDb();
    const existing = DeviceService.getById(id);
    if (!existing) return null;

    const name = payload.name ?? existing.name;
    const kind = payload.kind ?? existing.kind;
    const model = payload.model ?? existing.model;
    const manufacturer = payload.manufacturer ?? existing.manufacturer;
    const firmware = payload.firmware ?? existing.firmware;
    const risk = payload.risk ?? existing.risk;
    const status = payload.status ?? existing.status;
    const checked = payload.checked ?? 'Just now';
    const icon = payload.icon ?? existing.icon;
    const isolated = payload.isolated !== undefined ? (payload.isolated ? 1 : 0) : existing.isolated;

    db.prepare(`
      UPDATE devices
      SET name = ?, kind = ?, model = ?, manufacturer = ?, firmware = ?, risk = ?, status = ?, checked = ?, icon = ?, isolated = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(name, kind, model, manufacturer, firmware, risk, status, checked, icon, isolated, parseInt(id, 10));

    return DeviceService.getById(id);
  }

  /**
   * Get high-level overview metrics, posture trend, risk distribution, and events
   */
  static getOverview() {
    const db = getDb();
    const devices = db.prepare('SELECT * FROM devices').all();
    const events = db.prepare('SELECT * FROM events ORDER BY id DESC LIMIT 5').all();

    const lowCount = devices.filter(d => d.risk === 'Low').length;
    const medCount = devices.filter(d => d.risk === 'Medium').length;
    const highCount = devices.filter(d => d.risk === 'High').length;
    const requireAttention = devices.filter(d => d.status === 'Attention' || d.risk === 'High').length;

    // 7-day posture trend scores
    const postureTrend = [
      { day: 'Mon', score: 69 },
      { day: 'Tue', score: 72 },
      { day: 'Wed', score: 70 },
      { day: 'Thu', score: 77 },
      { day: 'Fri', score: 76 },
      { day: 'Sat', score: 81 },
      { day: 'Sun', score: 84 },
    ];

    return {
      metrics: {
        devicesAssessed: devices.length,
        requireAttention,
        openFindings: 6,
        lastAssessmentTime: '18m',
        lastAssessedDevice: devices[0]?.name || 'Campus CCTV Camera',
        securityScore: 84
      },
      postureTrend,
      riskDistribution: [
        { name: 'Low', value: lowCount, color: '#3ddc97' },
        { name: 'Medium', value: medCount, color: '#e7be67' },
        { name: 'High', value: highCount, color: '#f17b6b' },
      ],
      devices: devices.map(formatDevice),
      recentEvents: events.map(e => ({
        id: e.id,
        title: e.title,
        time: formatRelativeTime(e.created_at),
        tone: e.tone || 'blue',
        details: e.details
      }))
    };
  }
}

function formatDevice(d) {
  return {
    id: d.id,
    name: d.name,
    kind: d.kind,
    model: d.model,
    manufacturer: d.manufacturer,
    firmware: d.firmware,
    risk: d.risk,
    status: d.status,
    checked: d.checked,
    icon: d.icon,
    isolated: Boolean(d.isolated),
    ip_address: d.ip_address,
    mac_address: d.mac_address
  };
}

function formatRelativeTime(timestamp) {
  if (!timestamp) return 'Just now';
  const diff = Date.now() - new Date(timestamp).getTime();
  if (diff < 60000) return 'Just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return 'Recently';
}

