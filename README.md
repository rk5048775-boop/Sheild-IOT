# 🛡️ ShieldIoT — Connected Device Security Workspace

**ShieldIoT** is a unified security workspace and monitoring platform engineered for operational technology (OT), campus IoT networks, firmware security review, and automated vulnerability management.

---

## 🌟 Features

- **📊 Security Overview & Posture Analytics**: Live tracking of assessed devices, risk distributions (Low/Medium/High), 7-day posture trend score, and security event log.
- **🏷️ Device Passport**: Deep heuristic and CVE-based device assessment analyzing manufacturer, model number, firmware versions, and QR labels.
- **💻 Code Security Auditor**: Static code analyzer detecting hardcoded credentials (CWE-798), cleartext HTTP telemetry (CWE-319), buffer overflows in C/C++ (CWE-120), disabled TLS verification (CWE-295), and automated secure code remediation.
- **⚡ Attack Simulator**: Virtual closed-network sandbox allowing simulated volumetric DDoS attacks, suspicious rogue connection detection, and one-click VLAN device isolation.
- **🤖 Gemma 4 / AI Security Assistant**: Interactive intelligence agent providing vulnerability explanations, root-cause incident analysis, and remediation commands with explicit evidence boundaries.
- **📑 Security Reports**: Categorized audit archives with search, filtering, and JSON export.
- **🔍 Standalone CLI Scanner (`scan.js`)**: Terminal-based scanning tool for automated IoT audits in CI/CD pipelines.

---

## 🏗️ Architecture

```
Sheild-IOT/
├── server/                       # Node.js 24 Native Backend (Zero External Dependencies)
│   ├── index.js                  # HTTP Server entry point & graceful shutdown
│   ├── config.js                 # Configuration & environment variables
│   ├── db/
│   │   └── database.js           # Embedded SQLite database (node:sqlite DatabaseSync)
│   ├── services/
│   │   ├── assessmentService.js  # Heuristic & CVE device analyzer
│   │   ├── auditService.js       # Static code security auditor (Python, C/C++, Arduino)
│   │   ├── aiService.js          # Gemma 4 / Gemini AI engine with local reasoning fallback
│   │   ├── simulatorService.js   # Virtual attack scenario and device quarantine engine
│   │   ├── reportService.js      # Reports repository and filtering
│   │   └── deviceService.js      # Inventory management and metric aggregation
│   ├── routes/
│   │   └── apiRouter.js          # REST API router (handles both / and /api/ prefixes)
│   ├── middleware/
│   │   └── cors.js               # Cross-Origin Resource Sharing (CORS) handler
│   └── utils/
│       └── response.js           # JSON response formatting & body parsing
├── src/                          # React 19 + TypeScript + Vite Frontend
│   ├── services/
│   │   └── shieldiot.ts          # Typed API client for backend communication
│   ├── App.tsx                   # Main SPA dashboard and routing
│   └── App.css                   # Theme styles & responsive layout
├── test/                         # Node.js Native Test Suites
│   ├── server.test.js            # Unit tests for services & database
│   └── router.test.js            # Mock HTTP route integration tests
├── scan.js                       # Standalone CLI Scanner tool
├── .env.example                  # Environment configuration template
└── package.json                  # Scripts and dependencies
```

---

## 🚀 Quick Start

### 1. Start the Backend Server

The backend requires Node.js (v22+ or v24+ recommended). It uses built-in Node modules and requires **zero external npm installs**!

```bash
# Start backend server on port 5000
npm run server
# or directly:
node server/index.js
```

The server will automatically initialize the embedded SQLite database (`server/data/shieldiot.db`) and seed initial device and report records.

### 2. Start the Frontend (Vite)

```bash
npm install
npm run dev
```

Open `http://localhost:5173` in your browser. The sidebar model indicator will show `Gemma 4: Connected` when the backend is active.

### 3. Run Standalone CLI Scanner

Scan any IoT device target from your terminal:

```bash
node scan.js --target 192.168.1.101 --model "VisionGuard C20" --firmware "2.4.1"
```

### 4. Run Automated Test Suite

```bash
npm test
# or
node --test test/server.test.js test/router.test.js
```

---

## 📡 REST API Reference

All endpoints accept and return JSON. They can be queried with or without the `/api` prefix (e.g., `/health/model` or `/api/health/model`).

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Server status and uptime |
| `GET` | `/health/model` | Gemma 4 / AI Engine connection state |
| `POST` | `/assessments/devices` | Evaluate device model, manufacturer, and firmware |
| `POST` | `/audits/code` | Static analysis for Python, C/C++, and Arduino code |
| `POST` | `/ai/chat` | Interactive AI security assistant queries |
| `POST` | `/incidents/explain` | Deep incident root cause analysis (RCA) |
| `GET` | `/reports` | Retrieve list of reports (supports `?category=...&search=...`) |
| `POST` | `/reports` | Save new security report |
| `GET` | `/devices` | List monitored IoT devices |
| `GET` | `/overview` | Metrics, 7-day posture score, and risk distribution |
| `POST` | `/simulator/attack` | Simulate DDoS or suspicious connection |
| `POST` | `/simulator/isolate` | Quarantine compromised device |
| `POST` | `/simulator/restore` | Restore device to production VLAN |

### Sample Device Assessment Request

```bash
curl -X POST http://localhost:5000/api/assessments/devices \
  -H "Content-Type: application/json" \
  -d '{
    "manufacturer": "VisionGuard",
    "model": "VisionGuard C20",
    "firmware": "2.4.1"
  }'
```

### Sample Response

```json
{
  "device": {
    "manufacturer": "VisionGuard",
    "model": "VisionGuard C20",
    "firmware": "2.4.1"
  },
  "score": 38,
  "risk": "High",
  "findingsCount": 3,
  "highRiskCount": 2,
  "findings": [
    {
      "risk": "High",
      "cwe": "CWE-319",
      "title": "Review exposed telemetry and RTSP stream configuration",
      "text": "Unencrypted RTSP video transport (port 554) and HTTP telemetry endpoint detected without mandatory TLS encryption.",
      "recommendation": "Enforce RTSPS (TLS over port 322) and disable plain HTTP configuration APIs in favor of HTTPS."
    }
  ],
  "confidence": "High (Verified Knowledge Base)",
  "timestamp": "2026-10-24T08:00:00.000Z"
}
```

---

## 🔒 Security & AI Configuration

Create a `.env` file in the project root:

```env
PORT=5000
HOST=0.0.0.0
VITE_API_BASE_URL=http://localhost:5000/api

# Optional: Add your Gemini API key to enable cloud LLM reasoning
# If left blank, ShieldIoT automatically runs on its built-in Gemma 4 local security engine!
GEMINI_API_KEY=
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
