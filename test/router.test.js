import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { handleApiRoute } from '../server/routes/apiRouter.js';
import { handleCors } from '../server/middleware/cors.js';
import { getDb } from '../server/db/database.js';

function createMockReqRes(method, path, body = null, headers = {}) {
  const req = new EventEmitter();
  req.method = method;
  req.url = path;
  req.headers = { host: 'localhost:5000', ...headers };

  let statusCode = 200;
  const resHeaders = {};
  let bodyBuffer = '';

  const res = new EventEmitter();
  res.setHeader = (k, v) => { resHeaders[k.toLowerCase()] = v; };
  res.getHeader = (k) => resHeaders[k.toLowerCase()];
  res.writeHead = (code, h = {}) => {
    statusCode = code;
    for (const [k, v] of Object.entries(h)) {
      resHeaders[k.toLowerCase()] = v;
    }
  };
  res.end = (chunk) => {
    if (chunk) bodyBuffer += chunk;
    res.emit('finish');
  };

  const execute = async () => {
    const parsedUrl = new URL(path, 'http://localhost:5000');
    const routePromise = handleApiRoute(req, res, parsedUrl);

    if (body !== null) {
      const payload = typeof body === 'string' ? body : JSON.stringify(body);
      req.emit('data', Buffer.from(payload));
    }
    req.emit('end');

    await routePromise;
    let json = null;
    try {
      json = JSON.parse(bodyBuffer);
    } catch {
      json = bodyBuffer;
    }
    return { statusCode, headers: resHeaders, body: json };
  };

  return { req, res, execute };
}

test('Mock HTTP GET /health', async () => {
  const { execute } = createMockReqRes('GET', '/health');
  const res = await execute();
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.status, 'ok');
});

test('Mock HTTP GET /health/model', async () => {
  const { execute } = createMockReqRes('GET', '/health/model');
  const res = await execute();
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.status, 'connected');
  assert.equal(res.body.connected, true);
});

test('Mock HTTP POST /assessments/devices', async () => {
  const { execute } = createMockReqRes('POST', '/assessments/devices', {
    manufacturer: 'VisionGuard',
    model: 'C20',
    firmware: '2.4.1'
  });
  const res = await execute();
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.risk, 'High');
  assert.ok(res.body.findings.length > 0);
});

test('Mock HTTP POST /assessments/vision-scan', async () => {
  const { execute } = createMockReqRes('POST', '/assessments/vision-scan', {
    fileName: 'router_nexalink_r500.jpg',
    labelText: 'NexaLink R500'
  });
  const res = await execute();
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.extracted.manufacturer, 'NexaLink');
  assert.equal(res.body.extracted.model, 'NexaLink R500');
  assert.ok(res.body.assessment.findings.length > 0);
});

test('Mock HTTP POST /audits/code', async () => {
  const { execute } = createMockReqRes('POST', '/audits/code', {
    code: 'PASSWORD = "secret"\nrequests.post("http://insecure.api", json={})',
    language: 'Python'
  });
  const res = await execute();
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.risk, 'High');
  assert.ok(res.body.findings.length >= 2);
});

test('Mock HTTP POST /ai/chat', async () => {
  const { execute } = createMockReqRes('POST', '/ai/chat', {
    message: 'How do I secure an IoT camera?'
  });
  const res = await execute();
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.role, 'ai');
  assert.ok(res.body.text.length > 50);
});

test('Mock HTTP POST /incidents/explain', async () => {
  const { execute } = createMockReqRes('POST', '/incidents/explain', {
    incidentId: 'INC-2026-001'
  });
  const res = await execute();
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.incidentId, 'INC-2026-001');
  assert.ok(res.body.rootCauseAnalysis);
});

test('Mock HTTP GET /reports', async () => {
  const { execute } = createMockReqRes('GET', '/reports?category=Code%20audit');
  const res = await execute();
  assert.equal(res.statusCode, 200);
  assert.ok(Array.isArray(res.body));
});

test('Mock HTTP GET /overview', async () => {
  const { execute } = createMockReqRes('GET', '/overview');
  const res = await execute();
  assert.equal(res.statusCode, 200);
  assert.ok(res.body.metrics);
  assert.ok(res.body.postureTrend);
});

test('Mock HTTP POST /simulator/isolate and restore', async () => {
  const isolate = createMockReqRes('POST', '/simulator/isolate', { deviceId: 2 });
  const res1 = await isolate.execute();
  assert.equal(res1.statusCode, 200);
  assert.equal(res1.body.isolated, true);

  const restore = createMockReqRes('POST', '/simulator/restore', { deviceId: 2 });
  const res2 = await restore.execute();
  assert.equal(res2.statusCode, 200);
  assert.equal(res2.body.isolated, false);
});

