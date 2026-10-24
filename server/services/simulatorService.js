import { getDb } from '../db/database.js';

export class SimulatorService {
  /**
   * Run a simulated attack scenario or defense action
   */
  static runScenario(payload = {}) {
    const type = payload.type || 'DDoS active';
    const targetId = payload.targetId || 1;
    const db = getDb();

    let eventTitle = '';
    let tone = 'red';
    let details = '';

    if (type === 'DDoS active') {
      eventTitle = 'Virtual DDoS flood simulated against CCTV node';
      tone = 'red';
      details = 'Volumetric SYN flood generated at 85 Mbps targeting port 554';

      // Update target device status to Attention / High risk
      db.prepare("UPDATE devices SET status = 'Attention', risk = 'High', checked = 'Just now' WHERE id = ?").run(targetId);
    } else if (type === 'Unknown connection') {
      eventTitle = 'Virtual suspicious connection detected';
      tone = 'orange';
      details = 'Unrecognized MAC address attempted connection to Smart Lighting Controller';

      db.prepare("UPDATE devices SET status = 'Attention', risk = 'Medium', checked = 'Just now' WHERE id = 5").run();
    } else if (type === 'Defense applied') {
      eventTitle = 'Virtual automated defense engaged';
      tone = 'green';
      details = 'Rate limiting rule activated on ingress switch; malicious packets dropped';

      db.prepare("UPDATE devices SET status = 'Protected', checked = 'Just now' WHERE id = ?").run(targetId);
    }

    db.prepare('INSERT INTO events (title, tone, details) VALUES (?, ?, ?)').run(eventTitle, tone, details);

    return {
      type,
      targetId,
      status: 'active',
      eventTitle,
      tone,
      details,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Isolate a device from the virtual network
   */
  static isolateDevice(deviceId) {
    const db = getDb();
    const id = parseInt(deviceId, 10);
    db.prepare("UPDATE devices SET isolated = 1, status = 'Isolated', checked = 'Just now' WHERE id = ?").run(id);

    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(id);

    db.prepare('INSERT INTO events (title, tone, details) VALUES (?, ?, ?)').run(
      `Device quarantined: ${device ? device.name : `Device #${id}`}`,
      'orange',
      'Moved to Quarantine VLAN 999. Ingress and egress traffic blocked.'
    );

    return {
      success: true,
      deviceId: id,
      isolated: true,
      status: 'Isolated',
      message: `${device ? device.name : `Device #${id}`} has been isolated from the virtual network.`
    };
  }

  /**
   * Restore an isolated device back into normal operation
   */
  static restoreDevice(deviceId) {
    const db = getDb();
    const id = parseInt(deviceId, 10);
    db.prepare("UPDATE devices SET isolated = 0, status = 'Protected', checked = 'Just now' WHERE id = ?").run(id);

    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(id);

    db.prepare('INSERT INTO events (title, tone, details) VALUES (?, ?, ?)').run(
      `Device restored: ${device ? device.name : `Device #${id}`}`,
      'green',
      'Restored to production network VLAN. Continuous telemetry resumed.'
    );

    return {
      success: true,
      deviceId: id,
      isolated: false,
      status: 'Protected',
      message: `${device ? device.name : `Device #${id}`} has been restored to normal operation.`
    };
  }
}

