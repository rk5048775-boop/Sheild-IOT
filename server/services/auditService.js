import { getDb } from '../db/database.js';

export class AuditService {
  /**
   * Static code security auditor for embedded IoT snippets (Python, C/C++, Arduino)
   */
  static analyze(payload = {}) {
    const code = String(payload.code || '');
    const language = String(payload.language || 'Python').toLowerCase();

    const lines = code.split('\n');
    const findings = [];

    // Line-by-line inspection
    lines.forEach((lineText, idx) => {
      const lineNum = idx + 1;
      const trimmed = lineText.trim();
      if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#')) {
        // Skip comment lines, but check if comments reveal secrets
        if (/(password|secret|key|token)\s*[:=]/i.test(trimmed) && !trimmed.toLowerCase().includes('demo only')) {
          findings.push({
            risk: 'Medium',
            line: lineNum,
            cwe: 'CWE-546',
            title: 'Suspicious credential or sensitive comment',
            text: 'Comments containing credential references should not be committed into firmware images or public repositories.',
            remediation: 'Remove internal credentials or sensitive comments prior to production compile.'
          });
        }
        return;
      }

      // 1. Hardcoded Credentials / Secrets
      if (/(password|passwd|secret|api_key|token|auth_token|client_secret|private_key|ssid)\s*=\s*["'][^"']+["']/i.test(lineText)) {
        findings.push({
          risk: 'High',
          line: lineNum,
          cwe: 'CWE-798',
          title: 'Hardcoded credential in source code',
          text: 'Secrets in firmware source code can be extracted via firmware dump, JTAG interface, or source code repositories.',
          remediation: 'Load secrets dynamically from secure hardware elements (e.g. ATECC608A) or environment variables via os.environ / secure NVS.'
        });
      }

      // 2. Unencrypted HTTP / Cleartext Telemetry
      if (/http:\/\/[^\s"']+/i.test(lineText) || /ws:\/\/[^\s"']+/i.test(lineText)) {
        findings.push({
          risk: 'Medium',
          line: lineNum,
          cwe: 'CWE-319',
          title: 'Unencrypted HTTP / Cleartext transport',
          text: 'Telemetry transmitted over plain HTTP or unencrypted WebSockets is observable and modifiable in transit by network adversaries.',
          remediation: 'Migrate endpoint URL to https:// or wss:// and enforce valid TLS certificate pinning.'
        });
      }

      // 3. Insecure C/C++ Buffer Operations (strcpy, sprintf, gets)
      if (/\b(strcpy|strcat|sprintf|gets|scanf)\b\s*\(/i.test(lineText)) {
        const funcMatch = lineText.match(/\b(strcpy|strcat|sprintf|gets|scanf)\b/i);
        const funcName = funcMatch ? funcMatch[0] : 'buffer function';
        findings.push({
          risk: 'High',
          line: lineNum,
          cwe: 'CWE-120',
          title: `Unbounded buffer operation: ${funcName}`,
          text: `Use of ${funcName}() without bounds checking is a primary root cause of IoT remote code execution (RCE) via stack buffer overflows.`,
          remediation: `Replace ${funcName}() with bounded alternatives such as strncpy(), snprintf(), or C++ std::string with strict bounds checks.`
        });
      }

      // 4. Disabled TLS / SSL Verification
      if (/verify\s*=\s*False/i.test(lineText) || /setInsecure\s*\(\s*\)/i.test(lineText) || /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/i.test(lineText)) {
        findings.push({
          risk: 'High',
          line: lineNum,
          cwe: 'CWE-295',
          title: 'Disabled TLS/SSL certificate verification',
          text: 'Disabling certificate verification renders all encrypted communications vulnerable to Man-in-the-Middle (MITM) interception.',
          remediation: 'Bundle trusted CA roots (e.g. certifi or SPIFFS CA bundle) and verify server certificates.'
        });
      }

      // 5. Command Execution / Injection
      if (/\b(system|popen|exec|eval)\s*\(/i.test(lineText) && !lineText.includes('console.log')) {
        findings.push({
          risk: 'High',
          line: lineNum,
          cwe: 'CWE-78',
          title: 'Potential OS command injection vulnerability',
          text: 'Executing system-level shell commands from application code can allow attackers to hijack the underlying operating system.',
          remediation: 'Avoid invoking OS shells. Use parameterized process spawning (e.g. subprocess.run([args], shell=False)).'
        });
      }

      // 6. Missing Request Timeout (Denial of Service risk)
      if (/requests\.(get|post|put|delete)\s*\([^)]+\)/i.test(lineText) && !lineText.includes('timeout=')) {
        findings.push({
          risk: 'Medium',
          line: lineNum,
          cwe: 'CWE-400',
          title: 'Missing network socket timeout',
          text: 'HTTP requests without explicit timeouts can hang indefinitely if the server stalls, causing watchdog resets or device thread exhaustion.',
          remediation: 'Always specify a bounded timeout: requests.post(url, json=data, timeout=5).'
        });
      }

      // 7. Input validation heuristic (e.g. json={"id": device_id, "value": value})
      if (/def\s+\w+\s*\([^)]*\):/i.test(lineText) && !code.includes('isinstance') && !code.includes('typeof') && !code.includes('assert')) {
        findings.push({
          risk: 'Low',
          line: lineNum,
          cwe: 'CWE-20',
          title: 'Input validation and boundary review',
          text: 'Telemetry function parameters are received without explicit type or boundary validation.',
          remediation: 'Enforce type annotations and validate device_id and value ranges before processing.'
        });
      }
    });

    // Deduplicate findings on the same line with same CWE
    const seen = new Set();
    const uniqueFindings = findings.filter(f => {
      const key = `${f.line}-${f.cwe}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // If clean code provided
    if (uniqueFindings.length === 0) {
      uniqueFindings.push({
        risk: 'Low',
        line: 1,
        cwe: 'CWE-710',
        title: 'No high-severity vulnerabilities flagged',
        text: 'The submitted snippet complies with foundational IoT secure coding rules.',
        remediation: 'Maintain continuous integration fuzz testing and static analysis in your build pipeline.'
      });
    }

    // Generate secure pattern remediation
    const remediationCode = generateSecurePattern(language, code);

    const highRiskCount = uniqueFindings.filter(f => f.risk === 'High').length;
    const overallRisk = highRiskCount > 0 ? 'High' : uniqueFindings.some(f => f.risk === 'Medium') ? 'Medium' : 'Low';

    const result = {
      language: payload.language || 'Python',
      findingsCount: uniqueFindings.length,
      highRiskCount,
      risk: overallRisk,
      findings: uniqueFindings,
      remediationCode,
      timestamp: new Date().toISOString()
    };

    // Save to database
    try {
      const db = getDb();
      const insert = db.prepare(`
        INSERT INTO audits (language, code, findings_count, high_risk_count, findings_json, remediation_code)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      const info = insert.run(
        result.language,
        code.slice(0, 4000),
        result.findingsCount,
        result.highRiskCount,
        JSON.stringify(uniqueFindings),
        remediationCode
      );
      result.id = Number(info.lastInsertRowid);

      db.prepare('INSERT INTO events (title, tone, details) VALUES (?, ?, ?)').run(
        `Code audit performed: ${result.language} (${result.findingsCount} findings)`,
        overallRisk === 'High' ? 'red' : 'orange',
        `Flagged ${highRiskCount} high priority issues`
      );

      db.prepare(`
        INSERT INTO reports (category, title, risk, summary, details_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(
        'Code audit',
        `${result.language} security review`,
        overallRisk,
        `Audited ${lines.length} lines of code with ${uniqueFindings.length} security findings.`,
        JSON.stringify(result),
        'Just now'
      );
    } catch (err) {
      console.error('[AuditService] Database save error:', err.message);
    }

    return result;
  }
}

function generateSecurePattern(language, originalCode) {
  if (language.includes('python')) {
    return `# Hardened IoT Telemetry Pattern
import os
import requests

# Load credentials securely from environment / hardware vault
ENDPOINT = os.environ.get("TELEMETRY_ENDPOINT", "https://telemetry.example.org/api/v1/status")
AUTH_TOKEN = os.environ.get("DEVICE_AUTH_BEARER_TOKEN")

def send_status(device_id: str, value: float) -> bool:
    """Sends authenticated, encrypted telemetry with strict timeout and validation."""
    if not isinstance(device_id, str) or not device_id.isalnum():
        raise ValueError("Invalid device_id format")

    headers = {
        "Authorization": f"Bearer {AUTH_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {"id": device_id, "value": float(value)}

    try:
        response = requests.post(ENDPOINT, json=payload, headers=headers, timeout=5.0, verify=True)
        response.raise_for_status()
        return True
    except requests.RequestException as err:
        # Avoid leaking full tokens in logs
        return False`;
  }

  if (language.includes('arduino') || language.includes('c++') || language.includes('c')) {
    return `// Hardened C/C++ IoT Pattern
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>

const char* server = "telemetry.example.org";
const int port = 443;
const char* rootCA = "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----";

void sendTelemetrySecurely(const char* deviceId, float sensorVal) {
    WiFiClientSecure client;
    client.setCACert(rootCA); // Enforce TLS certificate validation
    client.setTimeout(5000);   // Enforce 5s timeout

    if (!client.connect(server, port)) {
        return; // Connection failed safely
    }

    // Use bounded JSON serialization instead of unsafe sprintf/strcpy
    StaticJsonDocument<256> doc;
    doc["id"] = deviceId;
    doc["value"] = sensorVal;

    client.println("POST /api/v1/status HTTP/1.1");
    client.println("Host: telemetry.example.org");
    client.println("Content-Type: application/json");
    client.println("Connection: close");
    client.println();
    serializeJson(doc, client);
}`;
  }

  return `// Secure Implementation Pattern
const endpoint = process.env.SECURE_TELEMETRY_URL;
const response = await fetch(endpoint, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': \`Bearer \${process.env.DEVICE_KEY}\`
  },
  body: JSON.stringify(payload),
  signal: AbortSignal.timeout(5000)
});`;
}

