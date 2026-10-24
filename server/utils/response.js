export function sendJson(res, statusCode, data) {
  const json = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(json),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY'
  });
  res.end(json);
}

export function sendError(res, statusCode, message, details = null) {
  sendJson(res, statusCode, {
    error: true,
    statusCode,
    message,
    details,
    timestamp: new Date().toISOString()
  });
}

export async function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 5 * 1024 * 1024) { // 5MB limit
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      if (!body.trim()) return resolve({});
      try {
        const parsed = JSON.parse(body);
        resolve(parsed);
      } catch {
        resolve({ raw: body });
      }
    });
    req.on('error', err => reject(err));
  });
}

