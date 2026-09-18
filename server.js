// Customer backend
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
// OAUTH IN-MEMORY STORES (PROTOTYPE SIMULATION)
// PROD NOTE: Replace these Map() instances with PostgreSQL/Redis.
// ===========================================================================
const registeredClients = new Map(); // client_id -> client metadata
const authorizationCodes = new Map(); // code -> auth state (code_challenge, userId, resource, etc.)

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
// 2. DATA API (FOR MCP BACKEND CONSUMPTION)
// ===========================================================================

app.get("/api/data", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  try {
    // PROD NOTE: Verify signed RS256 JWT
    // NOTE: This endpoint is only ever called internally by mcp-backend, which
    // forwards a token whose `aud` is the mcp-app resource (see /oauth/token below).
    // It intentionally does not re-check `aud` here, since that binding is enforced
    // at mcp-app (the actual protected resource) and again at mcp-backend.
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
// 3. OAUTH / MCP BRIDGE ENDPOINTS
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

app.get("/oauth/authorize", (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, resource } = req.query;

  // ---------------------------------------------------------------------
  // Enforce dynamic client registration: previously any client_id/redirect_uri
  // was accepted regardless of what /oauth/register had stored. Now the
  // authorize request must reference a client that actually registered, and
  // the redirect_uri must be one that client registered.
  // ---------------------------------------------------------------------
  const client = registeredClients.get(client_id);
  if (!client) {
    return res.status(400).json({
      error: "invalid_client",
      error_description: "Unknown client_id. Register via /oauth/register first."
    });
  }
  if (!redirect_uri || !client.redirect_uris.includes(redirect_uri)) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "redirect_uri does not match a redirect_uri registered for this client."
    });
  }

  // ---------------------------------------------------------------------
  // Resource Indicator (RFC 8707): the client must state which protected
  // resource it intends to use the token with. This value is carried
  // through to /oauth/token and embedded as the JWT `aud` claim, so that
  // resource servers can verify a token was actually issued for them
  // instead of accepting any token signed by this AS.
  // ---------------------------------------------------------------------
  if (!resource) {
    return res.status(400).json({
      error: "invalid_target",
      error_description: "resource parameter is required to bind the issued token to a specific protected resource."
    });
  }
  try {
    new URL(resource);
  } catch {
    return res.status(400).json({
      error: "invalid_target",
      error_description: "resource must be a valid absolute URI."
    });
  }

  if (!req.session || !req.session.isLoggedIn) {
    req.session.returnTo = req.originalUrl;
    return req.session.save((err) => {
      if (err) console.error(`[BACKEND AUTHORIZE ERROR] Session save failed:`, err);
      res.redirect("/");
    });
  }

  // PKCE Check
  if (!code_challenge || code_challenge_method !== "S256") {
    return res.status(400).send("OAuth 2.1 requires PKCE with S256 code_challenge_method.");
  }

  const mockAuthCode = "auth_code_" + crypto.randomBytes(12).toString("hex");
  authorizationCodes.set(mockAuthCode, {
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: code_challenge,
    resource,
    username: req.session.username,
    expiresAt: Date.now() + 10 * 60 * 1000
  });

  if (redirect_uri) {
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set("code", mockAuthCode);
    if (state) redirectUrl.searchParams.set("state", state);

    const hostUrl = `${req.protocol}://${req.get("host")}`;
    redirectUrl.searchParams.set("iss", hostUrl);

    return res.redirect(redirectUrl.toString());
  }

  res.send(`Authorization Granted! Code: ${mockAuthCode}`);
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

  // ---------------------------------------------------------------------
  // If a client_id is supplied in the token request, it must match the
  // client the code was actually issued to at /oauth/authorize. Previously
  // a client-supplied client_id would silently override the bound one when
  // signing the token, breaking the binding between code and client.
  // ---------------------------------------------------------------------
  if (client_id && client_id !== authData.clientId) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "client_id does not match the client this authorization code was issued to."
    });
  }

  // If a resource is supplied here, it must match what was requested at
  // /oauth/authorize (RFC 8707 §2) — a client can't authorize for one
  // resource and redeem the code for a token scoped to a different one.
  if (resource && resource !== authData.resource) {
    return res.status(400).json({
      error: "invalid_target",
      error_description: "resource does not match the resource requested during authorization."
    });
  }

  // PKCE Validation
  const calculatedChallenge = crypto
    .createHash("sha256")
    .update(code_verifier)
    .digest("base64url");

  if (calculatedChallenge !== authData.codeChallenge) {
    return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
  }

  // Issue Signed RS256 JWT, bound to the client and resource captured at
  // authorize-time (never from request-body input at this point).
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