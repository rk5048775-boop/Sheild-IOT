import { getDb } from '../db/database.js';

export class ReportService {
  /**
   * Retrieve list of reports with optional category filtering and search query
   */
  static list(query = {}) {
    const db = getDb();
    const category = query.category || query.filter;
    const search = (query.search || '').trim().toLowerCase();

    let sql = 'SELECT * FROM reports ORDER BY id DESC';
    let reports = db.prepare(sql).all();

    if (category && category !== 'All') {
      reports = reports.filter(r => r.category.toLowerCase() === category.toLowerCase());
    }

    if (search) {
      reports = reports.filter(r =>
        r.title.toLowerCase().includes(search) ||
        r.category.toLowerCase().includes(search) ||
        (r.summary && r.summary.toLowerCase().includes(search))
      );
    }

    return reports.map(r => ({
      id: r.id,
      category: r.category,
      title: r.title,
      risk: r.risk,
      summary: r.summary,
      date: r.created_at,
      details: safeParse(r.details_json)
    }));
  }

  /**
   * Create a new security report
   */
  static create(payload = {}) {
    const db = getDb();
    const category = payload.category || 'Device assessment';
    const title = payload.title || 'Untitled Assessment';
    const risk = payload.risk || 'Low';
    const summary = payload.summary || '';
    const details = payload.details ? JSON.stringify(payload.details) : '{}';
    const date = payload.date || 'Just now';

    const insert = db.prepare(`
      INSERT INTO reports (category, title, risk, summary, details_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    const info = insert.run(category, title, risk, summary, details, date);
    return {
      id: Number(info.lastInsertRowid),
      category,
      title,
      risk,
      summary,
      date
    };
  }
}

function safeParse(str) {
  try {
    return JSON.parse(str || '{}');
  } catch {
    return {};
  }
}

