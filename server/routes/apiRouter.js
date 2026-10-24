import { AssessmentService } from '../services/assessmentService.js';
import { AuditService } from '../services/auditService.js';
import { AiService } from '../services/aiService.js';
import { SimulatorService } from '../services/simulatorService.js';
import { ReportService } from '../services/reportService.js';
import { DeviceService } from '../services/deviceService.js';
import { sendJson, sendError, parseBody } from '../utils/response.js';
import { config } from '../config.js';

export async function handleApiRoute(req, res, parsedUrl) {
  let pathname = parsedUrl.pathname.replace(/\/+$/, '');
  if (!pathname) pathname = '/';

  // Normalize path by stripping optional /api prefix for unified routing
  const normalized = pathname.startsWith('/api/') ? pathname.slice(4) : pathname === '/api' ? '/' : pathname;
  const method = req.method.toUpperCase();

  try {
    // 1. Health & Status
    if (normalized === '/health' && method === 'GET') {
      return sendJson(res, 200, {
        status: 'ok',
        service: 'ShieldIoT Security Backend',
        version: config.version,
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
      });
    }

    if (normalized === '/health/model' && method === 'GET') {
      const status = AiService.getModelStatus();
      return sendJson(res, 200, status);
    }

    // 2. Device Assessment (/assessments/devices)
    if (normalized === '/assessments/devices' && method === 'POST') {
      const body = await parseBody(req);
      const assessment = AssessmentService.assess(body);
      return sendJson(res, 200, assessment);
    }

    // 2b. Multimodal AI Vision Scan (/assessments/vision-scan)
    if (normalized === '/assessments/vision-scan' && method === 'POST') {
      const body = await parseBody(req);
      const result = await AssessmentService.visionScan(body);
      return sendJson(res, 200, result);
    }

    // 3. Code Security Auditor (/audits/code)
    if (normalized === '/audits/code' && method === 'POST') {
      const body = await parseBody(req);
      const audit = AuditService.analyze(body);
      return sendJson(res, 200, audit);
    }

    // 4. AI Security Assistant (/ai/chat)
    if (normalized === '/ai/chat' && method === 'POST') {
      const body = await parseBody(req);
      const response = await AiService.chat(body);
      return sendJson(res, 200, response);
    }

    // 5. Incident Explanation (/incidents/explain)
    if (normalized === '/incidents/explain' && method === 'POST') {
      const body = await parseBody(req);
      const explanation = AiService.explainIncident(body);
      return sendJson(res, 200, explanation);
    }

    // 6. Security Reports (/reports)
    if (normalized === '/reports' && method === 'GET') {
      const query = Object.fromEntries(parsedUrl.searchParams);
      const reports = ReportService.list(query);
      return sendJson(res, 200, reports);
    }

    if (normalized === '/reports' && method === 'POST') {
      const body = await parseBody(req);
      const created = ReportService.create(body);
      return sendJson(res, 201, created);
    }

    // 7. Device Inventory (/devices)
    if (normalized === '/devices' && method === 'GET') {
      const devices = DeviceService.list();
      return sendJson(res, 200, devices);
    }

    if (normalized === '/devices' && method === 'POST') {
      const body = await parseBody(req);
      const created = DeviceService.create(body);
      return sendJson(res, 201, created);
    }

    const deviceMatch = normalized.match(/^\/devices\/(\d+)$/);
    if (deviceMatch) {
      const deviceId = parseInt(deviceMatch[1], 10);
      if (method === 'GET') {
        const device = DeviceService.getById(deviceId);
        if (!device) return sendError(res, 404, 'Device not found');
        return sendJson(res, 200, device);
      }
      if (method === 'PUT') {
        const body = await parseBody(req);
        const updated = DeviceService.update(deviceId, body);
        if (!updated) return sendError(res, 404, 'Device not found');
        return sendJson(res, 200, updated);
      }
    }

    // 8. Overview Stats (/overview)
    if (normalized === '/overview' && method === 'GET') {
      const overview = DeviceService.getOverview();
      return sendJson(res, 200, overview);
    }

    // 9. Attack Simulator Endpoints
    if ((normalized === '/simulator/scenario' || normalized === '/simulator/attack') && method === 'POST') {
      const body = await parseBody(req);
      const sim = SimulatorService.runScenario(body);
      return sendJson(res, 200, sim);
    }

    if (normalized === '/simulator/isolate' && method === 'POST') {
      const body = await parseBody(req);
      const result = SimulatorService.isolateDevice(body.deviceId || body.id);
      return sendJson(res, 200, result);
    }

    if (normalized === '/simulator/restore' && method === 'POST') {
      const body = await parseBody(req);
      const result = SimulatorService.restoreDevice(body.deviceId || body.id);
      return sendJson(res, 200, result);
    }

    // 10. API Documentation Manifest
    if ((normalized === '/docs' || normalized === '/') && method === 'GET') {
      return sendJson(res, 200, {
        name: 'ShieldIoT API Server',
        version: config.version,
        description: 'Comprehensive IoT security assessment, code audit, virtual attack simulation, and AI analysis backend.',
        endpoints: [
          { method: 'GET', path: '/health', description: 'Server health status' },
          { method: 'GET', path: '/health/model', description: 'AI model and security engine connection status' },
          { method: 'POST', path: '/assessments/devices', description: 'Analyze IoT device model, firmware, and label' },
          { method: 'POST', path: '/assessments/vision-scan', description: 'Multimodal AI vision scan of device label photo or QR code' },
          { method: 'POST', path: '/audits/code', description: 'Perform static code security audit on IoT source code' },
          { method: 'POST', path: '/ai/chat', description: 'Interactive AI assistant queries' },
          { method: 'POST', path: '/incidents/explain', description: 'Incident explanation and root cause analysis' },
          { method: 'GET', path: '/reports', description: 'Retrieve security reports with filtering' },
          { method: 'POST', path: '/reports', description: 'Save a security report' },
          { method: 'GET', path: '/devices', description: 'List monitored IoT devices' },
          { method: 'POST', path: '/devices', description: 'Add new device to inventory' },
          { method: 'GET', path: '/overview', description: 'Dashboard metrics, posture trend, risk distribution' },
          { method: 'POST', path: '/simulator/attack', description: 'Simulate network attack scenario' },
          { method: 'POST', path: '/simulator/isolate', description: 'Isolate compromised IoT device' },
          { method: 'POST', path: '/simulator/restore', description: 'Restore quarantined device' }
        ]
      });
    }

    // Route not matched
    return sendError(res, 404, `Endpoint ${method} ${pathname} not found`);

  } catch (err) {
    console.error(`[API Error] ${method} ${pathname}:`, err);
    return sendError(res, 500, 'Internal Server Error', err.message);
  }
}

