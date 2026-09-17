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
// IN-MEMORY STORES
// ===========================================================================
const registeredClients = new Map(); // client_id -> client metadata
const authorizationCodes = new Map(); // code -> auth state

// Single active API key state (as requested)
let activeApiKey = null; // { key: string, username: string, expiresAt: number }

// ===========================================================================
// CRYPTOGRAPHIC KEYS (RS256)
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

app.get("/.well-known/jwks.json", (req, res) => {
  res.json({ keys: [jwk] });
});

app.get("/.well-known/oauth-authorization-server", (req, res) => {
  const hostUrl = `${req.protocol}://${req.get("host")}`;
  res.json({
    issuer: hostUrl,
    authorization_endpoint: `${hostUrl}/oauth/authorize`,
    token_endpoint: `${hostUrl}/oauth/token`,
    registration_endpoint: `${hostUrl}/oauth/register`,
    jwks_uri: `${hostUrl}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["read", "write"]
  });
});

app.get("/.well-known/openid-configuration", (req, res) => {
  res.redirect("/.well-known/oauth-authorization-server");
});

// Primary Customer Frontend UI
app.get("/", (req, res) => {
  if (req.session.isLoggedIn) {
    const ws1Text = `Active Sprint: ${MOCK_DATA.workspace1.completedTasks} completed tasks, ${MOCK_DATA.workspace1.inProgressTasks} in progress`;
    const ws2Chart = Object.entries(MOCK_DATA.workspace2)
      .map(([k, v]) => `<div><strong>${k}:</strong> ${"█".repeat(v)} (${v})</div>`)
      .join("");
    const ws3Text = MOCK_DATA.workspace3
      .map(([from, to]) => `${from} -> ${to}`)
      .join(", ");

    // Check existing API Key status for rendering
    let apiKeyStatusHtml = "<p>No active API key generated.</p>";
    if (activeApiKey) {
      const isExpired = Date.now() > activeApiKey.expiresAt;
      if (isExpired) {
        apiKeyStatusHtml = `<p style="color: red;"><strong>Active API Key Expired!</strong> Generate a new key below.</p>`;
      } else {
        const remainingSec = Math.round((activeApiKey.expiresAt - Date.now()) / 1000);
        apiKeyStatusHtml = `
          <div style="background: #eef; padding: 10px; border-radius: 4px;">
            <p style="margin: 0 0 5px 0;">Active Key: <code style="font-size: 1.1em; background: #fff; padding: 2px 6px;">${activeApiKey.key}</code></p>
            <small style="color: #555;">Expires in: ${remainingSec} seconds</small>
          </div>
        `;
      }
    }

    return res.send(`
      <div style="font-family: sans-serif; padding: 20px; max-width: 600px;">
        <h2>Welcome to Mock Customer Dashboard 🎉</h2>
        <p>Logged in as: <strong>${req.session.username}</strong></p>

        <hr style="margin: 20px 0;">

        <!-- API KEY GENERATOR SECTION -->
        <div style="border: 2px solid #4A90E2; padding: 15px; margin-bottom: 20px; border-radius: 6px; background-color: #f4f8ff;">
          <h3>MCP API Key Generator</h3>
          ${apiKeyStatusHtml}
          <form action="/generate-api-key" method="POST" style="margin-top: 15px;">
            <label>Duration (Minutes):</label><br>
            <input type="number" name="minutes" min="1" max="1440" value="15" required style="padding: 5px; width: 80px; margin-top: 5px;" />
            <button type="submit" style="padding: 6px 12px; margin-left: 10px; cursor: pointer;">Generate API Key</button>
          </form>
        </div>

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

        <br>
        <form action="/logout" method="POST">
          <button type="submit" style="padding: 8px 16px;">Log Out</button>
        </form>
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

// API Key Generation Handler
app.post("/generate-api-key", (req, res) => {
  if (!req.session || !req.session.isLoggedIn) {
    return res.status(401).send("Unauthorized");
  }

  const minutes = parseInt(req.body.minutes, 10) || 15;
  const key = "mcp_key_" + crypto.randomBytes(16).toString("hex");
  const expiresAt = Date.now() + minutes * 60 * 1000;

  // Overwrites existing single API key state
  activeApiKey = {
    key,
    username: req.session.username,
    expiresAt
  };

  console.log(`[API KEY GENERATED] Key: ${key}, Expires in: ${minutes} mins`);
  res.redirect("/");
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === MOCK_USER.username && password === MOCK_USER.password) {
    req.session.isLoggedIn = true;
    req.session.username = username;

    return req.session.save((err) => {
      if (err) console.error(`[BACKEND LOGIN ERROR] Session save failed:`, err);
      res.redirect("/");
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
// 2. DATA API
// ===========================================================================

app.get("/api/data", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  try {
    jwt.verify(token, publicKey, { algorithms: ["RS256"] });
    res.json(MOCK_DATA);
  } catch (err) {
    return res.status(403).json({ error: "invalid_token", message: err.message });
  }
});

// ===========================================================================
// 3. OAUTH / API KEY VERIFICATION BRIDGE ENDPOINTS
// ===========================================================================

app.post("/oauth/register", (req, res) => {
  const { redirect_uris } = req.body;
  const clientId = "client_" + crypto.randomBytes(8).toString("hex");

  const clientMetadata = {
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris: redirect_uris || ["https://chatgpt.com/connector/oauth"],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none"
  };

  registeredClients.set(clientId, clientMetadata);
  res.status(201).json(clientMetadata);
});

// GET /oauth/authorize: Render API Key Input Form Directly
app.get("/oauth/authorize", (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, resource } = req.query;

  console.log("[OAUTH AUTHORIZE GET]", { client_id, redirect_uri, resource });

  // 1. Validate Client ID
  const client = registeredClients.get(client_id);
  if (!client) {
    console.error("[OAUTH ERROR] Unknown client_id:", client_id);
    return res.status(400).send("OAuth Error: Unknown client_id. Please re-connect in ChatGPT.");
  }

  // 2. Flexible Redirect URI Validation (Match Origin + Path)
  if (!redirect_uri) {
    return res.status(400).send("OAuth Error: Missing redirect_uri.");
  }

  const cleanRedirect = (uri) => {
    try {
      const parsed = new URL(uri);
      return parsed.origin + parsed.pathname.replace(/\/$/, "");
    } catch (e) {
      return uri;
    }
  };

  const isRedirectAllowed = client.redirect_uris.some(
    (allowed) => cleanRedirect(allowed) === cleanRedirect(redirect_uri)
  );

  if (!isRedirectAllowed) {
    console.error("[OAUTH ERROR] redirect_uri mismatch. Received:", redirect_uri, "Registered:", client.redirect_uris);
    return res.status(400).send(`OAuth Error: Invalid redirect_uri.`);
  }

  // 3. Render ONLY the API Key Form (Do not check sessions or redirect to /)
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Authorize MCP Access</title>
      <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f9f9f9; }
        .card { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
        input[type="text"] { width: 100%; padding: 10px; margin: 10px 0 20px 0; box-sizing: border-box; font-size: 14px; }
        button { width: 100%; padding: 12px; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; font-weight: bold; }
        button:hover { background: #0052a3; }
      </style>
    </head>
    <body>
      <div class="card">
        <h2 style="margin-top: 0;">MCP Authorization</h2>
        <p style="color: #555;">Paste the API key generated from your Customer Dashboard below to connect.</p>
        
        <form action="/oauth/authorize" method="POST">
          <input type="hidden" name="client_id" value="${client_id}" />
          <input type="hidden" name="redirect_uri" value="${redirect_uri}" />
          <input type="hidden" name="state" value="${state || ""}" />
          <input type="hidden" name="code_challenge" value="${code_challenge || ""}" />
          <input type="hidden" name="resource" value="${resource || ""}" />

          <label><strong>API Key:</strong></label>
          <input type="text" name="api_key" placeholder="mcp_key_..." required autofocus />

          <button type="submit">Authenticate & Connect</button>
        </form>
      </div>
    </body>
    </html>
  `);
});

// POST /oauth/authorize: Validate API Key & Exchange for Authorization Code
// POST /oauth/authorize: Validate API Key & Exchange for Authorization Code
app.post("/oauth/authorize", express.urlencoded({ extended: true }), (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, resource, api_key } = req.body;

  // 1. Verify API key presence and match
  if (!activeApiKey || !api_key || activeApiKey.key !== api_key.trim()) {
    return res.status(401).send(`
      <div style="font-family: sans-serif; padding: 20px; color: red;">
        <h3>Authentication Failed ❌</h3>
        <p>Invalid API Key provided.</p>
        <a href="javascript:history.back()">Try Again</a>
      </div>
    `);
  }

  // 2. Verify freshness/expiration timestamp
  if (Date.now() > activeApiKey.expiresAt) {
    return res.status(401).send(`
      <div style="font-family: sans-serif; padding: 20px; color: red;">
        <h3>Authentication Failed ❌</h3>
        <p>This API Key has expired. Please generate a new key from your dashboard.</p>
        <a href="javascript:history.back()">Try Again</a>
      </div>
    `);
  }

  // 3. Issue Authorization Code bound to the key owner
  const mockAuthCode = "auth_code_" + crypto.randomBytes(12).toString("hex");
  authorizationCodes.set(mockAuthCode, {
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: code_challenge,
    resource,
    username: activeApiKey.username,
    expiresAt: Date.now() + 10 * 60 * 1000
  });

  // 4. Build redirect safely preserving pre-existing query parameters on redirect_uri
  try {
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set("code", mockAuthCode);
    
    // Only set state if a valid non-empty state was supplied by ChatGPT
    if (state && state !== "undefined" && state !== "null") {
      redirectUrl.searchParams.set("state", state);
    }

    const hostUrl = `${req.protocol}://${req.get("host")}`;
    redirectUrl.searchParams.set("iss", hostUrl);

    return res.redirect(redirectUrl.toString());
  } catch (err) {
    console.error("[OAUTH REDIRECT ERROR]", err.message);
    return res.status(400).send("Invalid redirect_uri supplied during authorization.");
  }
});

app.post("/oauth/token", express.urlencoded({ extended: true }), (req, res) => {
  const { code, grant_type, code_verifier, client_id, resource } = req.body;

  if (grant_type !== "authorization_code" || !code || !code_verifier) {
    return res.status(400).json({ error: "invalid_request", error_description: "Missing code or code_verifier" });
  }

  const authData = authorizationCodes.get(code);
  if (!authData || Date.now() > authData.expiresAt) {
    authorizationCodes.delete(code);
    return res.status(400).json({ error: "invalid_grant", error_description: "Code invalid or expired" });
  }

  authorizationCodes.delete(code);

  if (client_id && client_id !== authData.clientId) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "client_id does not match."
    });
  }

  if (resource && resource !== authData.resource) {
    return res.status(400).json({
      error: "invalid_target",
      error_description: "resource does not match."
    });
  }

  // PKCE Check
  const calculatedChallenge = crypto
    .createHash("sha256")
    .update(code_verifier)
    .digest("base64url");

  if (calculatedChallenge !== authData.codeChallenge) {
    return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
  }

  const hostUrl = `${req.protocol}://${req.get("host")}`;
  const accessToken = jwt.sign(
    {
      sub: authData.username,
      client_id: authData.clientId,
      scope: "read write"
    },
    privateKey,
    {
      algorithm: "RS256",
      expiresIn: "1h",
      issuer: hostUrl,
      audience: authData.resource,
      keyid: "prototype-key-1"
    }
  );

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600
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