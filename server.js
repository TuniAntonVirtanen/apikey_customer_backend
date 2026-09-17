// CUSTOMER BACKEND

import express from "express";
import session from "express-session";
import crypto from "crypto";
import jwt from "jsonwebtoken";

const app = express();

app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Global Request Logger
app.use((req, res, next) => {
  console.log(`[BACKEND REQ] ${req.method} ${req.url}`);
  next();
});

app.use(
  session({
    secret: "mock-customer-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 3600000,
      secure: true,
      sameSite: "none"
    }
  })
);

const MOCK_USER = {
  username: "user",
  password: "password"
};

// ===========================================================================
// SINGLE SOURCE OF TRUTH (DATA)
// ===========================================================================
const MOCK_DATA = {
  workspace1: { completedTasks: 12, inProgressTasks: 3 },
  workspace2: { A: 5, B: 7, C: 3 },
  workspace3: [["D", "A"], ["A", "C"], ["B", "C"], ["D", "C"]]
};

// ===========================================================================
// API KEY STORE (PROTOTYPE SIMULATION)
// Only one API key is ever active at a time. Generating a new one silently
// overwrites/invalidates the previous one. Only a hash of the key is kept
// server-side; the raw key is returned to the caller exactly once, at
// generation time, and can never be retrieved again after that.
// This is now the ONLY credential that can mint an access token — the old
// authorization-code/redirect flow has been removed entirely.
// PROD NOTE: Replace with a persisted, indexed store (DB) if multiple
// concurrent keys / multiple users are ever needed.
// ===========================================================================
let activeApiKey = null;
// shape when set: { hash: string, username: string, issuedAt: number, expiresAt: number }

const API_KEY_MIN_MINUTES = 1;
const API_KEY_MAX_MINUTES = 1440; // 24h ceiling — keeps the UI from minting a de-facto permanent key

function hashApiKey(rawKey) {
  return crypto.createHash("sha256").update(rawKey).digest("hex");
}

function generateAndStoreApiKey(username, minutes) {
  const rawKey = "sk_" + crypto.randomBytes(32).toString("base64url");
  const now = Date.now();
  const expiresAt = now + minutes * 60 * 1000;

  activeApiKey = {
    hash: hashApiKey(rawKey),
    username,
    issuedAt: now,
    expiresAt
  };

  return { rawKey, issuedAt: now, expiresAt };
}

// Freshness + identity check for a presented API key. Constant-time
// comparison is used so that checking an invalid key can't leak timing
// information about the stored hash.
function checkApiKey(providedKey) {
  if (!activeApiKey) return { valid: false, reason: "no_active_key" };
  if (Date.now() > activeApiKey.expiresAt) return { valid: false, reason: "expired" };
  if (typeof providedKey !== "string" || providedKey.length === 0) {
    return { valid: false, reason: "malformed" };
  }

  const providedHash = hashApiKey(providedKey);
  const a = Buffer.from(providedHash, "hex");
  const b = Buffer.from(activeApiKey.hash, "hex");

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { valid: false, reason: "mismatch" };
  }

  return { valid: true, username: activeApiKey.username, expiresAt: activeApiKey.expiresAt };
}

// ===========================================================================
// CRYPTOGRAPHIC KEYS (RS256)
// PROD NOTE: Load persistent RSA keys from environment secrets or AWS KMS.
// ===========================================================================
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" }
});

const keyObject = crypto.createPublicKey(publicKey);
const jwk = keyObject.export({ format: "jwk" });
jwk.use = "sig";
jwk.alg = "RS256";
jwk.kid = "prototype-key-1";

// ===========================================================================
// 1. WEB APP ROUTES & DISCOVERY
// ===========================================================================

// Still needed: mcp-backend (and, in principle, anyone else who receives one
// of our tokens) fetches this to verify signatures.
app.get("/.well-known/jwks.json", (req, res) => {
  res.json({ keys: [jwk] });
});

// Require an active session (same convention as the rest of the frontend routes)
function requireSession(req, res, next) {
  if (!req.session?.isLoggedIn) {
    return res.status(401).json({ error: "unauthorized", message: "Log in first." });
  }
  next();
}

app.get("/", (req, res) => {
  console.log(`[BACKEND ROOT] Session ID: ${req.sessionID}, LoggedIn: ${!!req.session?.isLoggedIn}`);

  if (req.session.isLoggedIn) {
    const ws1Text = `Active Sprint: ${MOCK_DATA.workspace1.completedTasks} completed tasks, ${MOCK_DATA.workspace1.inProgressTasks} in progress`;
    const ws2Chart = Object.entries(MOCK_DATA.workspace2)
      .map(([k, v]) => `<div><strong>${k}:</strong> ${"█".repeat(v)} (${v})</div>`)
      .join("");
    const ws3Text = MOCK_DATA.workspace3
      .map(([from, to]) => `${from} -> ${to}`)
      .join(", ");

    return res.send(`
      <div style="font-family: sans-serif; padding: 20px;">
        <h2>Welcome to Mock Customer Dashboard 🎉</h2>
        <p>Logged in as: <strong>${req.session.username}</strong></p>

        <hr style="margin: 20px 0;">

        <div style="border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; border-radius: 4px;">
          <h3>Workspace 1</h3>
          <p>${ws1Text}</p>
        </div>

        <div style="border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; border-radius: 4px;">
          <h3>Workspace 2</h3>
          ${ws2Chart}
        </div>

        <div style="border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; border-radius: 4px;">
          <h3>Workspace 3</h3>
          <p>${ws3Text}</p>
        </div>

        <div style="border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; border-radius: 4px;">
          <h3>API Key (for MCP / external tools)</h3>
          <div>
            <label>Valid for (minutes):</label><br>
            <input type="number" id="apiKeyMinutes" value="15" min="${API_KEY_MIN_MINUTES}" max="${API_KEY_MAX_MINUTES}" style="padding: 5px; width: 100px;" />
            <button type="button" id="genApiKeyBtn" style="padding: 8px 16px;">Generate API Key</button>
          </div>
          <div id="apiKeyResult" style="margin-top: 10px; display: none;">
            <input type="text" id="apiKeyValue" readonly style="width: 70%; padding: 5px; font-family: monospace;" />
            <button type="button" id="copyApiKeyBtn" style="padding: 8px 12px;">Copy</button>
            <p id="apiKeyExpiry" style="font-size: 12px; color: #555;"></p>
            <p style="font-size: 12px; color: #b00;">This key is shown once. Generating a new one invalidates this one.</p>
          </div>
        </div>

        <br>
        <form action="/logout" method="POST">
          <button type="submit" style="padding: 8px 16px;">Log Out</button>
        </form>

        <script>
          document.getElementById("genApiKeyBtn").addEventListener("click", async () => {
            const minutes = document.getElementById("apiKeyMinutes").value;
            const res = await fetch("/account/api-key/generate", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ minutes: Number(minutes) })
            });
            const data = await res.json();
            if (!res.ok) {
              alert(data.message || "Failed to generate API key.");
              return;
            }
            document.getElementById("apiKeyValue").value = data.api_key;
            document.getElementById("apiKeyExpiry").textContent =
              "Expires at " + new Date(data.expires_at).toLocaleString();
            document.getElementById("apiKeyResult").style.display = "block";
          });

          document.getElementById("copyApiKeyBtn").addEventListener("click", () => {
            const input = document.getElementById("apiKeyValue");
            input.select();
            navigator.clipboard.writeText(input.value);
          });
        </script>
      </div>
    `);
  }

  res.send(`
    <div style="font-family: sans-serif; padding: 20px;">
      <h2>Mock Customer Login</h2>
      <form action="/login" method="POST" style="display: inline-block; text-align: left;">
        <div>
          <label>Username:</label><br>
          <input type="text" name="username" required style="padding: 5px;" />
        </div><br>
        <div>
          <label>Password:</label><br>
          <input type="password" name="password" required style="padding: 5px;" />
        </div><br>
        <button type="submit" style="padding: 8px 16px;">Log In</button>
      </form>
      <p><small>Use <code>user</code> / <code>password</code> to log in.</small></p>
    </div>
  `);
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === MOCK_USER.username && password === MOCK_USER.password) {
    req.session.isLoggedIn = true;
    req.session.username = username;

    const redirectTo = req.session.returnTo || "/";
    delete req.session.returnTo;

    return req.session.save((err) => {
      if (err) console.error(`[BACKEND LOGIN ERROR] Session save failed:`, err);
      res.redirect(redirectTo);
    });
  }

  res.status(401).send(`
    <h3>Invalid Credentials ❌</h3>
    <a href="/">Try Again</a>
  `);
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// ===========================================================================
// 1b. API KEY ROUTES
// ===========================================================================

app.post("/account/api-key/generate", requireSession, (req, res) => {
  const minutesRaw = Number(req.body.minutes);

  if (!Number.isFinite(minutesRaw) || minutesRaw < API_KEY_MIN_MINUTES || minutesRaw > API_KEY_MAX_MINUTES) {
    return res.status(400).json({
      error: "invalid_request",
      message: `minutes must be a number between ${API_KEY_MIN_MINUTES} and ${API_KEY_MAX_MINUTES}.`
    });
  }

  const minutes = Math.floor(minutesRaw);
  const { rawKey, issuedAt, expiresAt } = generateAndStoreApiKey(req.session.username, minutes);

  console.log(`[API-KEY] Generated for ${req.session.username}, valid ${minutes}m (expires ${new Date(expiresAt).toISOString()})`);

  res.json({
    api_key: rawKey, // shown once — server only retains a hash from here on
    issued_at: issuedAt,
    expires_at: expiresAt,
    expires_in_minutes: minutes
  });
});

// Lets the dashboard (or anything else with a session) check key status
// without ever re-exposing the raw key or the stored hash.
app.get("/account/api-key/status", requireSession, (req, res) => {
  if (!activeApiKey || Date.now() > activeApiKey.expiresAt) {
    return res.json({ active: false });
  }
  res.json({
    active: true,
    expires_at: activeApiKey.expiresAt,
    issued_for: activeApiKey.username
  });
});

// Standalone freshness/validity check for a presented API key. No session
// required — kept around as a debug/manual-testing endpoint independent of
// the token-exchange flow below.
app.post("/account/api-key/validate", (req, res) => {
  const { api_key } = req.body;
  if (!api_key) {
    return res.status(400).json({ error: "invalid_request", message: "api_key is required." });
  }

  const result = checkApiKey(api_key);
  if (!result.valid) {
    return res.status(401).json({ valid: false, reason: result.reason });
  }

  res.json({ valid: true, username: result.username, expires_at: result.expiresAt });
});

// ===========================================================================
// 2. DATA API (FOR MCP BACKEND CONSUMPTION)
// ===========================================================================

app.get("/api/data", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  try {
    // NOTE: This endpoint is only ever called internally by mcp-backend, which
    // forwards a token whose `aud` is the mcp-app resource (see /oauth/token
    // below — tokens are now minted via the api_key grant instead of an
    // authorization code, but the aud-binding discipline is unchanged). This
    // route intentionally does not re-check `aud` itself, since that binding
    // is enforced at mcp-backend (the actual protected-resource gatekeeper).
    jwt.verify(token, publicKey, { algorithms: ["RS256"] });
    res.json(MOCK_DATA);
  } catch (err) {
    return res.status(403).json({ error: "invalid_token", message: err.message });
  }
});

// Visual widget route
app.get("/widget/bar-chart", (req, res) => {
  const chartData = MOCK_DATA.workspace2;
  const maxVal = Math.max(...Object.values(chartData));

  const bars = Object.entries(chartData).map(([label, val]) => {
    const heightPercent = (val / maxVal) * 100;
    return `
      <div style="display: flex; flex-direction: column; align-items: center; width: 40px;">
        <div style="font-size: 12px; margin-bottom: 4px;">${val}</div>
        <div style="width: 100%; height: ${heightPercent}%; background-color: #4A90E2; border-radius: 4px 4px 0 0;"></div>
        <div style="font-weight: bold; margin-top: 8px;">${label}</div>
      </div>
    `;
  }).join("");

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f9f9f9; }
        .chart-container { display: flex; align-items: flex-end; gap: 20px; height: 150px; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
      </style>
    </head>
    <body>
      <div class="chart-container">
        ${bars}
      </div>
    </body>
    </html>
  `);
});

// ===========================================================================
// 3. TOKEN ENDPOINT (API-KEY GRANT ONLY)
// The authorization-code/redirect flow (registration, /oauth/authorize, AS
// discovery metadata) has been removed entirely: the only way to obtain an
// access token in this prototype is by presenting a currently valid API key,
// generated via the dashboard's "API Key" panel above.
// ===========================================================================

app.post("/oauth/token", (req, res) => {
  const { grant_type, api_key, resource } = req.body;

  if (grant_type !== "api_key") {
    return res.status(400).json({
      error: "unsupported_grant_type",
      error_description: "Only grant_type=api_key is supported by this prototype."
    });
  }

  if (!api_key) {
    return res.status(400).json({ error: "invalid_request", error_description: "api_key is required." });
  }

  // Resource Indicator (RFC 8707 flavor, informal here): the caller must
  // state which protected resource it intends to use the token with. That
  // value is embedded as the JWT `aud` claim so resource servers (mcp-backend)
  // can verify a token was actually issued for them, not just signed by us
  // for some unrelated purpose.
  if (!resource) {
    return res.status(400).json({
      error: "invalid_target",
      error_description: "resource is required to bind the issued token to a specific protected resource."
    });
  }
  try {
    new URL(resource);
  } catch {
    return res.status(400).json({ error: "invalid_target", error_description: "resource must be a valid absolute URI." });
  }

  const result = checkApiKey(api_key);
  if (!result.valid) {
    return res.status(401).json({ error: "invalid_grant", error_description: `API key ${result.reason}.` });
  }

  // The access token can never outlive the API key that authorized it, and
  // is additionally capped at 1h so a long-lived API key doesn't translate
  // into an equally long-lived bearer token sitting in mcp-app's memory.
  const msRemainingOnKey = result.expiresAt - Date.now();
  const expiresInSeconds = Math.max(1, Math.min(3600, Math.floor(msRemainingOnKey / 1000)));

  const hostUrl = `${req.protocol}://${req.get("host")}`;
  const accessToken = jwt.sign(
    {
      sub: result.username,
      scope: "read write"
    },
    privateKey,
    {
      algorithm: "RS256",
      expiresIn: expiresInSeconds,
      issuer: hostUrl,
      audience: resource,
      keyid: "prototype-key-1"
    }
  );

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: expiresInSeconds
  });
});

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  next();
});

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`Mock Customer Server running on http://localhost:${port}`);
});