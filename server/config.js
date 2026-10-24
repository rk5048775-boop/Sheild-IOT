import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const config = {
  port: parseInt(process.env.PORT || '5000', 10),
  host: process.env.HOST || '0.0.0.0',
  corsOrigin: process.env.CORS_ORIGIN || '*',
  geminiApiKey: process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || '',
  geminiModel: process.env.GEMINI_MODEL || 'gemini-2.5-flash',
  dbPath: process.env.DB_PATH || path.join(__dirname, 'data', 'shieldiot.db'),
  env: process.env.NODE_ENV || 'development',
  version: '1.0.0',
};

