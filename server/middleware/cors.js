import { config } from '../config.js';

export function handleCors(req, res) {
  res.setHeader('Access-Control-Allow-Origin', config.corsOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.setHeader('Access-Control-Max-Age', '86400');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return true; // request handled
  }
  return false;
}

