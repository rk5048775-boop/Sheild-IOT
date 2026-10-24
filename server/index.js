import http from 'node:http';
import { URL } from 'node:url';
import { config } from './config.js';
import { getDb } from './db/database.js';
import { handleCors } from './middleware/cors.js';
import { handleApiRoute } from './routes/apiRouter.js';

// Initialize Database
console.log('[ShieldIoT Backend] Initializing SQLite database...');
const db = getDb();
console.log(`[ShieldIoT Backend] Database loaded from: ${config.dbPath}`);

const server = http.createServer(async (req, res) => {
  const start = Date.now();

  // Handle CORS
  if (handleCors(req, res)) {
    return;
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  // Log incoming request
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${parsedUrl.pathname} -> ${res.statusCode} (${duration}ms)`);
  });

  try {
    await handleApiRoute(req, res, parsedUrl);
  } catch (err) {
    console.error('[Unhandled Request Error]', err);
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: true, message: 'Internal Server Error' }));
    }
  }
});

server.listen(config.port, () => {
  console.log(`\n======================================================`);
  console.log(`  🛡️  ShieldIoT Security Backend is running!`);
  console.log(`  🌐  Local URL:   http://localhost:${config.port} (or http://127.0.0.1:${config.port})`);
  console.log(`  🔍  API Docs:    http://localhost:${config.port}/api/docs`);
  console.log(`  ❤️   Health Check: http://localhost:${config.port}/api/health`);
  console.log(`  🤖  AI Engine:   ${config.geminiApiKey ? 'Gemini Cloud Hybrid' : 'Gemma 4 Security Core (Local)'}`);
  console.log(`  💾  Database:    ${config.dbPath}`);
  console.log(`======================================================\n`);
});

function shutdown() {
  console.log('\n[ShieldIoT Backend] Gracefully shutting down...');
  server.close(() => {
    console.log('[ShieldIoT Backend] HTTP server closed.');
    try {
      db.close();
      console.log('[ShieldIoT Backend] SQLite database closed.');
    } catch (e) {
      // Ignore if already closed
    }
    process.exit(0);
  });

  // Force close after 5 seconds if hanging
  setTimeout(() => {
    console.error('[ShieldIoT Backend] Forcing shutdown.');
    process.exit(1);
  }, 5000);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

