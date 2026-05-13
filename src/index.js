#!/usr/bin/env node

import * as p from "@clack/prompts";
import { execa } from "execa";
import pc from "picocolors";

// ============================================================================
// CLI Flag Parsing
// ============================================================================

function getFlag(name) {
  const prefix = `--${name}=`;
  const arg = process.argv.find((a) => a.startsWith(prefix));
  if (arg) return arg.slice(prefix.length);
  return undefined;
}

function getBoolFlag(name) {
  if (process.argv.includes(`--${name}`)) return true;
  if (process.argv.includes(`--no-${name}`)) return false;
  return undefined;
}

const DEBUG = process.env.DEBUG === "true" || process.argv.includes("--debug");
const FLAGS = {
  login: getBoolFlag("login"),
  reauth: getBoolFlag("reauth"),
  appSetup: getFlag("app-setup"), // "new" or "existing"
  appName: getFlag("app-name"),
  appType: getFlag("app-type"), // "regular" or "m2m"
  callbackUrls: getFlag("callback-urls"),
  logoutUrls: getFlag("logout-urls"),
  appId: getFlag("app-id"), // client ID for existing app
  flavor: getFlag("flavor"), // "connected_accounts", "refresh_token_exchange", "access_token_exchange", "privileged_worker"
  connections: getFlag("connections"), // comma-separated connection names or "none"
  createApiClient: getBoolFlag("create-api-client"),
  apiIdentifier: getFlag("api-identifier"),
  apiClientName: getFlag("api-client-name"),
  configurePrivateKeyJwt: getBoolFlag("configure-private-key-jwt"),
};

if (process.argv.includes("--help") || process.argv.includes("-h")) {
  console.log(`
Auth0 Token Vault Setup

Usage: configure-auth0-token-vault [options]

Options:
  --debug                         Enable debug logging
  --login / --no-login            Auto-answer the login prompt
  --reauth / --no-reauth          Auto-answer the reauthentication prompt
  --app-setup=<new|existing>      Skip app setup question ("new" or "existing")
  --app-name=<name>               Application name (default: "Token Vault App")
  --app-type=<regular|m2m>        Application type (default: "regular")
  --callback-urls=<urls>          Comma-separated callback URLs
  --logout-urls=<urls>            Comma-separated logout URLs
  --app-id=<client_id>            Use an existing application by client ID
  --flavor=<flavor>               Token Vault flavor:
                                    connected_accounts, refresh_token_exchange,
                                    access_token_exchange, privileged_worker
  --connections=<names|none>      Comma-separated connection names, or "none"
  --create-api-client /           Create a Custom API Client
    --no-create-api-client
  --api-identifier=<url>          Backend API identifier (audience)
  --api-client-name=<name>        Custom API Client name
  --configure-private-key-jwt /   Configure Private Key JWT authentication
    --no-configure-private-key-jwt
  -h, --help                      Show this help message

Examples:
  # Fully non-interactive: create a new regular web app
  configure-auth0-token-vault \\
    --login --app-setup=new --app-name="My App" --app-type=regular \\
    --callback-urls=http://localhost:3000/callback \\
    --logout-urls=http://localhost:3000 \\
    --connections=google-oauth2 \\
    --flavor=connected_accounts

  # Use an existing app with access token exchange
  configure-auth0-token-vault \\
    --app-id=abc123 --flavor=access_token_exchange \\
    --connections=none --create-api-client \\
    --api-identifier=https://api.example.com
`);
  process.exit(0);
}

function log(message) {
  if (DEBUG) {
    console.log(pc.dim(`[debug] ${message}`));
  }
}

async function checkScopesChanged(text) {
  if (!text) return;

  const lowerText = text.toLowerCase();
  if (
    lowerText.includes("required scopes have changed") ||
    lowerText.includes("required scopes") ||
    lowerText.includes("insufficient scopes")
  ) {
    log(`Detected scopes issue in: ${text.substring(0, 200)}`);
    p.log.error(
      "The Auth0 CLI requires additional scopes to complete this operation.",
    );
    const shouldReauth =
      FLAGS.reauth ??
      (await p.confirm({
        message: "Would you like to reauthenticate with the required scopes?",
        initialValue: true,
      }));

    if (p.isCancel(shouldReauth) || !shouldReauth) {
      p.cancel("Please run 'auth0 login' manually with the required scopes.");
      process.exit(1);
    }

    p.log.info("Reauthenticating...");
    await execa("auth0", ["login"], { stdio: "inherit" });
    p.log.success("Reauthentication successful! Please run this script again.");
    process.exit(0);
  }
}

async function runAuth0Command(args, options = {}) {
  log(`Running: auth0 ${args.join(" ")}`);

  const result = await execa("auth0", args, {
    ...options,
    reject: false,
    timeout: 30000,
  });

  log(`exitCode: ${result.exitCode}`);
  log(`stdout: ${result.stdout?.substring(0, 500)}`);
  log(`stderr: ${result.stderr?.substring(0, 500)}`);

  const allText = [result.stdout, result.stderr].filter(Boolean).join(" ");
  await checkScopesChanged(allText);

  if (result.exitCode !== 0) {
    const error = new Error(`Command failed: auth0 ${args.join(" ")}`);
    error.stdout = result.stdout;
    error.stderr = result.stderr;
    error.exitCode = result.exitCode;
    throw error;
  }

  return result;
}

async function runAuth0Api(method, path, data = null) {
  const args = ["api", method, path, "--no-input"];
  const options = {};

  if (data) {
    const jsonData = JSON.stringify(data);
    log(
      `Running: auth0 api ${method} ${path} (with data: ${jsonData.substring(0, 100)}...)`,
    );
    options.input = jsonData;
  } else {
    log(`Running: auth0 api ${method} ${path}`);
  }

  const result = await execa("auth0", args, {
    ...options,
    reject: false,
    timeout: 30000,
  });

  log(`exitCode: ${result.exitCode}`);
  log(`stdout: ${result.stdout?.substring(0, 500)}`);
  log(`stderr: ${result.stderr?.substring(0, 500)}`);

  const allText = [result.stdout, result.stderr].filter(Boolean).join(" ");
  await checkScopesChanged(allText);

  if (result.exitCode !== 0) {
    const error = new Error(`Command failed: auth0 api ${method} ${path}`);
    error.stdout = result.stdout;
    error.stderr = result.stderr;
    error.exitCode = result.exitCode;
    throw error;
  }

  return result;
}

// Constants
const TOKEN_VAULT_GRANT_TYPE =
  "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token";

const CONNECTED_ACCOUNTS_SCOPES = [
  "create:me:connected_accounts",
  "read:me:connected_accounts",
  "delete:me:connected_accounts",
];

const MY_ACCOUNT_API_SCOPES = [
  { value: "read:me", description: "Read user profile" },
  { value: "update:me", description: "Update user profile" },
  { value: "delete:me", description: "Delete user account" },
  {
    value: "create:me:connected_accounts",
    description: "Link external accounts",
  },
  {
    value: "read:me:connected_accounts",
    description: "Read linked accounts",
  },
  {
    value: "delete:me:connected_accounts",
    description: "Unlink external accounts",
  },
];

const TOKEN_VAULT_FLAVORS = {
  connected_accounts: {
    label: "Connected Accounts",
    hint: "User-managed linked accounts via My Account API",
    description:
      "Allows users to link multiple external accounts to their Auth0 profile and manage them via the My Account API.",
  },
  refresh_token_exchange: {
    label: "Refresh Token Exchange",
    hint: "Connected Accounts + Exchange Auth0 refresh tokens for external tokens",
    description:
      "Connected Accounts + Backend services exchange Auth0 refresh tokens to retrieve external provider tokens without user interaction.",
  },
  access_token_exchange: {
    label: "Access Token Exchange",
    hint: "Connected Accounts + Exchange Auth0 access tokens for external tokens",
    description:
      "Connected Accounts + Backend APIs exchange Auth0 access tokens to retrieve external provider tokens on behalf of users.",
  },
  privileged_worker: {
    label: "Privileged Worker Token Exchange",
    hint: "Connected Accounts + M2M apps exchange signed JWTs for external tokens",
    description:
      "Connected Accounts + Machine-to-machine applications use signed JWT bearer tokens to retrieve external provider tokens without active user sessions.",
  },
};

// ============================================================================
// Main Function
// ============================================================================

async function main() {
  console.clear();

  p.intro(pc.bgCyan(pc.black(" Auth0 Token Vault Setup ")));

  // Check Auth0 CLI installation
  const cliInstalled = await checkAuth0CLI();
  if (!cliInstalled) {
    p.log.error("Auth0 CLI is not installed.");
    p.note(
      `Install via Homebrew:\n${pc.cyan("brew tap auth0/auth0-cli && brew install auth0")}\n\nOr visit: ${pc.cyan("https://github.com/auth0/auth0-cli")}`,
      "Installation Required",
    );
    p.outro(pc.red("Setup cancelled."));
    process.exit(1);
  }

  p.log.success("Auth0 CLI detected");

  // Check if logged in
  const loggedIn = await checkAuth0Login();
  if (!loggedIn) {
    const shouldLogin =
      FLAGS.login ??
      (await p.confirm({
        message: "You need to log in to Auth0 CLI. Log in now?",
        initialValue: true,
      }));

    if (p.isCancel(shouldLogin) || !shouldLogin) {
      p.cancel("Login required to continue.");
      process.exit(1);
    }

    await runAuth0Login();
  }

  // Get tenant info
  const tenantInfo = await getTenantInfo();
  p.log.success(`Connected to tenant: ${pc.cyan(tenantInfo.domain)}`);

  // Ask about application setup
  const appChoice =
    FLAGS.appSetup ??
    (FLAGS.appId ? "existing" : undefined) ??
    (await p.select({
      message: "How would you like to configure the application?",
      options: [
        { value: "new", label: "Create a new application" },
        { value: "existing", label: "Use an existing application" },
      ],
    }));

  if (p.isCancel(appChoice)) {
    p.cancel("Setup cancelled.");
    process.exit(0);
  }

  let app;

  if (appChoice === "new") {
    app = await createNewApplication();
  } else {
    app = await selectExistingApplication();
  }

  if (!app) {
    p.cancel("No application selected.");
    process.exit(1);
  }

  p.log.info(`Using application: ${pc.cyan(app.name)} (${pc.dim(app.id)})`);

  // Configure basic Token Vault settings (always required)
  await configureApplicationForTokenVault(app.id);

  // Configure connections for Token Vault
  await configureConnections(app.id);

  // Ask which Token Vault flavor to configure
  const flavor =
    FLAGS.flavor ??
    (await p.select({
      message: "Which Token Vault configuration do you need?",
      options: Object.entries(TOKEN_VAULT_FLAVORS).map(([value, config]) => ({
        value,
        label: config.label,
        hint: config.hint,
      })),
    }));

  if (p.isCancel(flavor)) {
    p.cancel("Setup cancelled.");
    process.exit(0);
  }

  // Set up Connected Accounts (foundation for all Token Vault flavors)
  await setupConnectedAccounts(app.id, tenantInfo.domain);

  // Apply flavor-specific configuration
  switch (flavor) {
    case "connected_accounts":
      // Base Connected Accounts setup is complete
      break;

    case "refresh_token_exchange":
      await setupRefreshTokenExchange(app.id, tenantInfo.domain);
      break;

    case "access_token_exchange":
      await setupAccessTokenExchange(app.id, tenantInfo.domain);
      break;

    case "privileged_worker":
      await setupPrivilegedWorker(app.id, tenantInfo.domain);
      break;
  }

  // Show completion summary
  showCompletionSummary(app, tenantInfo.domain, flavor);

  p.outro(pc.green("All done!"));
}

// ============================================================================
// Auth0 CLI Helpers
// ============================================================================

async function checkAuth0CLI() {
  try {
    await runAuth0Command(["--version"]);
    return true;
  } catch {
    return false;
  }
}

async function checkAuth0Login() {
  try {
    const { stdout } = await runAuth0Command([
      "tenants",
      "list",
      "--json",
      "--no-input",
    ]);
    const tenants = JSON.parse(stdout || "[]");
    return tenants.length > 0;
  } catch {
    return false;
  }
}

async function runAuth0Login() {
  p.log.info("Opening browser for Auth0 login...");
  try {
    // auth0 CLI default login does not include this scope. We need it for the client grant creation step, so we request it upfront.
    await runAuth0Command(["login", "--scopes", "create:client_grants"], {
      stdio: "inherit",
    });
    p.log.success("Login successful!");
  } catch (error) {
    p.log.error("Login failed");
    throw error;
  }
}

async function getTenantInfo() {
  const { stdout } = await runAuth0Command([
    "tenants",
    "list",
    "--json",
    "--no-input",
  ]);
  const tenants = JSON.parse(stdout || "[]");

  if (tenants.length === 0) {
    throw new Error("No tenants found. Please log in first.");
  }

  const activeTenant = tenants.find((t) => t.active) || tenants[0];
  return { domain: activeTenant.name };
}

// ============================================================================
// Application Management
// ============================================================================

async function createNewApplication() {
  const onCancel = () => {
    p.cancel("Setup cancelled.");
    process.exit(0);
  };

  // Prompt only for fields that weren't provided via flags. Previously
  // setting either --app-name OR --app-type short-circuited both prompts
  // and silently defaulted the other one, so `--app-type=regular` alone
  // would silently create an app named "Token Vault App".
  let name = FLAGS.appName;
  let type = FLAGS.appType;
  if (name == null || type == null) {
    const appPrompts = {};
    if (name == null) {
      appPrompts.name = () =>
        p.text({
          message: "Enter application name:",
          placeholder: "Token Vault App",
          defaultValue: "Token Vault App",
        });
    }
    if (type == null) {
      appPrompts.type = () =>
        p.select({
          message: "Select application type:",
          options: [
            {
              value: "regular",
              label: "Regular Web Application",
              hint: "Web apps with a secure backend",
            },
            {
              value: "m2m",
              label: "Machine to Machine",
              hint: "Backend services and workers",
            },
          ],
        });
    }
    const answered = await p.group(appPrompts, { onCancel });
    name ??= answered.name;
    type ??= answered.type;
  }

  const details = { name, type };

  let callbackUrls = [];
  let logoutUrls = [];

  if (details.type === "regular") {
    // Same decoupling for URLs: ask for whichever list wasn't provided.
    let callbackRaw = FLAGS.callbackUrls;
    let logoutRaw = FLAGS.logoutUrls;
    if (callbackRaw == null || logoutRaw == null) {
      const urlPrompts = {};
      if (callbackRaw == null) {
        urlPrompts.callbackUrls = () =>
          p.text({
            message: "Enter callback URLs (comma-separated, optional):",
            placeholder: "http://localhost:3000/callback",
          });
      }
      if (logoutRaw == null) {
        urlPrompts.logoutUrls = () =>
          p.text({
            message: "Enter logout URLs (comma-separated, optional):",
            placeholder: "http://localhost:3000",
          });
      }
      const urlAnswered = await p.group(urlPrompts, { onCancel });
      callbackRaw ??= urlAnswered.callbackUrls;
      logoutRaw ??= urlAnswered.logoutUrls;
    }

    callbackUrls = parseUrlList(callbackRaw);
    logoutUrls = parseUrlList(logoutRaw);
  }

  const s = p.spinner();
  s.start("Creating application...");

  try {
    const sanitizedName = details.name.replace(/\+/g, "").trim();
    log(`Creating app: name="${sanitizedName}", type="${details.type}"`);

    const createArgs = [
      "apps",
      "create",
      "--name",
      `${sanitizedName}`,
      "--type",
      details.type,
      "--json",
      "--no-input",
    ];

    if (details.type === "regular") {
      if (callbackUrls.length) {
        createArgs.push("--callbacks", callbackUrls.join(","));
      }
      if (logoutUrls.length) {
        createArgs.push("--logout-urls", logoutUrls.join(","));
      }
    }

    log(`Full command: auth0 ${createArgs.join(" ")}`);
    const { stdout } = await runAuth0Command(createArgs);

    log(`Response: ${stdout}`);
    const app = JSON.parse(stdout);

    s.stop(`Application created: ${pc.cyan(app.name)}`);
    return { id: app.client_id, name: app.name };
  } catch (error) {
    s.stop("Failed to create application");
    p.log.error(`Command failed: ${error.message}`);
    if (error.stdout) {
      p.log.error(`stdout: ${error.stdout}`);
    }
    if (error.stderr) {
      p.log.error(`stderr: ${error.stderr}`);
    }
    throw error;
  }
}

function parseUrlList(rawValue) {
  if (!rawValue) {
    return [];
  }

  return rawValue
    .split(",")
    .map((url) => url.trim())
    .filter(Boolean);
}

async function selectExistingApplication() {
  if (FLAGS.appId) {
    const s = p.spinner();
    s.start("Fetching application details...");
    try {
      const { stdout } = await runAuth0Command([
        "apps",
        "show",
        FLAGS.appId,
        "--json",
        "--no-input",
      ]);
      const app = JSON.parse(stdout);
      s.stop("Application loaded");
      return { id: app.client_id, name: app.name };
    } catch (error) {
      s.stop("Failed to fetch application");
      throw error;
    }
  }

  const s = p.spinner();
  s.start("Fetching applications...");

  try {
    const { stdout } = await runAuth0Command([
      "apps",
      "list",
      "--json",
      "--no-input",
    ]);
    const apps = JSON.parse(stdout);
    s.stop("Applications loaded");

    const filteredApps = apps.filter((app) => app.name !== "All Applications");

    if (filteredApps.length === 0) {
      p.log.warning("No applications found. Creating a new one.");
      return createNewApplication();
    }

    const selected = await p.select({
      message: "Select an application:",
      options: filteredApps.map((app) => ({
        value: { id: app.client_id, name: app.name },
        label: app.name,
        hint: app.client_id,
      })),
    });

    if (p.isCancel(selected)) {
      p.cancel("Setup cancelled.");
      process.exit(0);
    }

    return selected;
  } catch (error) {
    s.stop("Failed to fetch applications");
    throw error;
  }
}

// ============================================================================
// Basic Token Vault Configuration (always applied)
// ============================================================================

async function configureApplicationForTokenVault(appId) {
  const s = p.spinner();
  s.start("Configuring application for Token Vault...");

  try {
    const { stdout } = await runAuth0Command([
      "apps",
      "show",
      appId,
      "--json",
      "--no-input",
    ]);
    const app = JSON.parse(stdout);

    let grantTypes = app.grant_types || ["authorization_code", "refresh_token"];
    if (!grantTypes.includes(TOKEN_VAULT_GRANT_TYPE)) {
      grantTypes.push(TOKEN_VAULT_GRANT_TYPE);
    }
    if (!grantTypes.includes("refresh_token")) {
      grantTypes.push("refresh_token");
    }
    if (!grantTypes.includes("authorization_code")) {
      grantTypes.push("authorization_code");
    }

    const updatePayload = {
      is_first_party: true,
      oidc_conformant: true,
      grant_types: grantTypes,
    };

    // Ensure confidential client (required for Token Vault)
    if (app.token_endpoint_auth_method === "none") {
      updatePayload.token_endpoint_auth_method = "client_secret_post";
    }

    await runAuth0Api("patch", `clients/${appId}`, updatePayload);

    s.stop("Application configured for Token Vault");
  } catch (error) {
    s.stop("Failed to configure application");
    p.log.error(error.message);
    throw error;
  }
}

async function configureConnections(appId) {
  const s = p.spinner();
  s.start("Fetching connections...");

  try {
    const { stdout } = await runAuth0Api("get", "connections");
    const connections = JSON.parse(stdout);

    const supportedStrategies = [
      "google-oauth2",
      "github",
      "linkedin",
      "microsoft",
      "facebook",
      "twitter",
      "dropbox",
      "box",
      "salesforce",
      "fitbit",
      "slack",
      "spotify",
      "stripe-connect",
      "oauth2",
      "oidc",
    ];

    const eligibleConnections = connections.filter(
      (conn) =>
        supportedStrategies.includes(conn.strategy) ||
        conn.strategy?.startsWith("oauth") ||
        conn.strategy?.startsWith("oidc"),
    );

    s.stop("Connections loaded");

    if (eligibleConnections.length === 0) {
      p.log.warning("No eligible social/enterprise connections found.");
      p.note(
        "Create a social connection first in the Auth0 Dashboard.",
        "No Connections",
      );
      return;
    }

    let selectedConnections;

    if (FLAGS.connections != null) {
      if (FLAGS.connections === "none") {
        p.log.warning("No connections selected.");
        return;
      }
      const connectionNames = FLAGS.connections.split(",").map((n) => n.trim());
      selectedConnections = eligibleConnections.filter((conn) =>
        connectionNames.includes(conn.name),
      );
      if (selectedConnections.length === 0) {
        p.log.warning(
          "No matching connections found for the provided names.",
        );
        return;
      }
    } else {
      selectedConnections = await p.multiselect({
        message: "Select connections to enable for Token Vault:",
        options: eligibleConnections.map((conn) => ({
          value: conn,
          label: conn.name,
          hint: conn.strategy,
        })),
        required: false,
      });

      if (p.isCancel(selectedConnections)) {
        p.cancel("Setup cancelled.");
        process.exit(0);
      }

      if (!selectedConnections || selectedConnections.length === 0) {
        p.log.warning("No connections selected.");
        return;
      }
    }

    for (const conn of selectedConnections) {
      const connSpinner = p.spinner();
      connSpinner.start(`Configuring ${conn.name}...`);

      try {
        // Enable Connected Accounts for the connection
        await runAuth0Api("patch", `connections/${conn.id}`, {
          options: {
            ...conn.options,
            connected_accounts: { active: true },
          },
        });

        // Enable the connection for this application
        await runAuth0Api("patch", `connections/${conn.id}`, {
          enabled_clients: [
            ...new Set([...(conn.enabled_clients || []), appId]),
          ],
        });

        connSpinner.stop(`${pc.cyan(conn.name)} configured for Token Vault`);
      } catch {
        connSpinner.stop(`Could not fully configure ${conn.name}`);
        p.log.warning(
          `Please enable Connected Accounts manually in the Dashboard for ${conn.name}`,
        );
      }
    }
  } catch {
    s.stop("Could not fetch connections");
    p.log.warning("Please configure connections manually in the Dashboard.");
  }
}

// ============================================================================
// Connected Accounts Setup
// ============================================================================

async function setupConnectedAccounts(appId, domain) {
  p.log.step("Setting up Connected Accounts...");

  // Enable My Account API
  await enableMyAccountAPI(domain);

  // Create client grant for My Account API
  await createClientGrant(appId, domain);

  // Configure MRRT
  await configureMRRT(appId, domain);
}

async function enableMyAccountAPI(domain) {
  const s = p.spinner();
  s.start("Enabling My Account API...");

  const myAccountIdentifier = `https://${domain}/me/`;

  try {
    const { stdout } = await runAuth0Api(
      "get",
      `resource-servers?identifier=${encodeURIComponent(myAccountIdentifier)}`,
    );
    const apis = JSON.parse(stdout);

    if (apis && apis.length > 0) {
      const existingApi = apis[0];
      const existingScopes = existingApi.scopes || [];
      const existingScopeValues = existingScopes.map((scope) => scope.value);

      const missingScopes = MY_ACCOUNT_API_SCOPES.filter(
        (scope) => !existingScopeValues.includes(scope.value),
      );

      const updatePayload = {};

      if (missingScopes.length > 0) {
        log(
          `Adding missing scopes: ${missingScopes.map((sc) => sc.value).join(", ")}`,
        );
        updatePayload.scopes = [...existingScopes, ...missingScopes];
      }

      const currentUserPolicy =
        existingApi.subject_type_authorization?.user?.policy;
      if (currentUserPolicy !== "require_client_grant") {
        log(
          `Setting user access policy to require_client_grant (current: ${currentUserPolicy})`,
        );
        updatePayload.subject_type_authorization = {
          user: {
            policy: "require_client_grant",
          },
        };
      }

      if (Object.keys(updatePayload).length > 0) {
        await runAuth0Api(
          "patch",
          `resource-servers/${existingApi.id}`,
          updatePayload,
        );
        s.stop("My Account API configured with access policy and scopes");
      } else {
        s.stop("My Account API is already enabled");
      }

      return { identifier: myAccountIdentifier, id: existingApi.id };
    }

    // API doesn't exist, try to create it
    log("My Account API not found, attempting to create it");
    try {
      const { stdout: createOutput } = await runAuth0Api(
        "post",
        "resource-servers",
        {
          identifier: myAccountIdentifier,
          name: "My Account",
          scopes: MY_ACCOUNT_API_SCOPES,
          signing_alg: "RS256",
          allow_offline_access: true,
          token_lifetime: 86400,
          token_lifetime_for_web: 7200,
          skip_consent_for_verifiable_first_party_clients: true,
          subject_type_authorization: {
            user: {
              policy: "require_client_grant",
            },
          },
        },
      );
      const createdApi = JSON.parse(createOutput);
      s.stop("My Account API created and enabled");
      return { identifier: myAccountIdentifier, id: createdApi.id };
    } catch (createError) {
      log(`Creation failed: ${createError.message}`);
      if (createError.stdout) log(`stdout: ${createError.stdout}`);
      if (createError.stderr) log(`stderr: ${createError.stderr}`);

      const dashboardUrl = buildDashboardUrl(domain, "apis");

      s.stop("My Account API needs manual activation");
      p.note(
        `The My Account API requires manual activation:\n\n` +
          `1. Go to the Auth0 Dashboard:\n` +
          `   ${pc.cyan(dashboardUrl)}\n\n` +
          `2. Look for the ${pc.bold("My Account API")} banner\n\n` +
          `3. Click ${pc.bold("Activate")}\n\n` +
          `Once activated, run this script again to complete the setup.`,
        "Action Required",
      );
      return { identifier: myAccountIdentifier, id: null };
    }
  } catch (error) {
    s.stop("Could not verify My Account API status");
    log(`My Account API error: ${error.message}`);
    if (error.stdout) log(`stdout: ${error.stdout}`);
    if (error.stderr) log(`stderr: ${error.stderr}`);

    p.log.warning(
      "Please ensure My Account API is enabled in your Auth0 Dashboard.",
    );
    return { identifier: myAccountIdentifier, id: null };
  }
}

async function createClientGrant(appId, domain) {
  const s = p.spinner();
  s.start("Creating client grant for My Account API...");
  const myAccountIdentifier = `https://${domain}/me/`;

  try {
    const { stdout: grantsOutput } = await runAuth0Api(
      "get",
      `client-grants?client_id=${appId}&audience=${encodeURIComponent(myAccountIdentifier)}`,
    );

    const grants = JSON.parse(grantsOutput);
    const userGrant = grants.find((g) => g.subject_type === "user");

    if (userGrant) {
      const existingScopes = userGrant.scope || [];
      const newScopes = [
        ...new Set([...existingScopes, ...CONNECTED_ACCOUNTS_SCOPES]),
      ];

      await runAuth0Api("patch", `client-grants/${userGrant.id}`, {
        scope: newScopes,
      });

      s.stop("Client grant updated with Connected Accounts scopes");
      return;
    }
  } catch {
    // Grant doesn't exist, create it
  }

  try {
    await runAuth0Api("post", "client-grants", {
      client_id: appId,
      audience: myAccountIdentifier,
      scope: CONNECTED_ACCOUNTS_SCOPES,
      subject_type: "user",
    });

    s.stop("Client grant created for My Account API (user access)");
  } catch (error) {
    if (error.message?.includes("already exists")) {
      s.stop("Client grant already exists");
    } else {
      s.stop("Could not create client grant automatically");
      log(`Client grant error: ${error.message}`);
      if (error.stdout) log(`stdout: ${error.stdout}`);
      if (error.stderr) log(`stderr: ${error.stderr}`);

      p.note(
        `Create a client grant in the Auth0 Dashboard:\n\n` +
          `1. Go to Applications -> APIs -> My Account\n` +
          `2. Click the "Application Access" tab\n` +
          `3. Find your application and click "Edit"\n` +
          `4. Select the User Access tab and authorize below scopes:\n` +
          `   - create:me:connected_accounts\n` +
          `   - read:me:connected_accounts\n` +
          `   - delete:me:connected_accounts`,
        "Action Required",
      );
    }
  }
}

async function configureMRRT(appId, domain) {
  const s = p.spinner();
  s.start("Configuring Multi-Resource Refresh Token (MRRT)...");
  const myAccountIdentifier = `https://${domain}/me/`;

  try {
    const { stdout } = await runAuth0Command([
      "apps",
      "show",
      appId,
      "--json",
      "--no-input",
    ]);
    const app = JSON.parse(stdout);

    const refreshTokenConfig = app.refresh_token || {};
    const existingPolicies = refreshTokenConfig.policies || [];

    const hasMyAccountInMRRT = existingPolicies.some(
      (policy) => policy.audience === myAccountIdentifier,
    );

    if (!hasMyAccountInMRRT) {
      const newPolicies = [
        ...existingPolicies,
        {
          audience: myAccountIdentifier,
          scope: CONNECTED_ACCOUNTS_SCOPES,
        },
      ];

      await runAuth0Api("patch", `clients/${appId}`, {
        refresh_token: {
          ...refreshTokenConfig,
          policies: newPolicies,
        },
      });

      s.stop("MRRT configured with My Account API");
    } else {
      s.stop("MRRT already includes My Account API");
    }
  } catch (error) {
    s.stop("Could not configure MRRT automatically");
    log(`MRRT error: ${error.message}`);
    if (error.stdout) log(`stdout: ${error.stdout}`);
    if (error.stderr) log(`stderr: ${error.stderr}`);

    const settingsUrl = buildDashboardUrl(
      domain,
      `applications/${appId}/settings`,
    );

    p.note(
      `Configure MRRT manually in the Auth0 Dashboard:\n\n` +
        `1. Go to your application settings:\n` +
        `   ${pc.cyan(settingsUrl)}\n\n` +
        `2. Scroll to ${pc.bold("Multi-Resource Refresh Token")}\n\n` +
        `3. Click ${pc.bold("Edit Configuration")} and enable the My Account API`,
      "Action Required: Configure MRRT",
    );
  }
}

// ============================================================================
// Refresh Token Exchange Setup
// ============================================================================

async function setupRefreshTokenExchange(appId, domain) {
  // Show usage instructions
  p.note(
    `${pc.bold("Refresh Token Exchange Usage:")}\n\n` +
      `To exchange an Auth0 refresh token for an external provider token:\n\n` +
      `POST ${pc.cyan(`https://${domain}/oauth/token`)}\n\n` +
      `${pc.bold("Parameters:")}\n` +
      `  grant_type: ${pc.dim(TOKEN_VAULT_GRANT_TYPE)}\n` +
      `  subject_token: ${pc.dim("<auth0_refresh_token>")}\n` +
      `  subject_token_type: ${pc.dim("urn:ietf:params:oauth:token-type:refresh_token")}\n` +
      `  requested_token_type: ${pc.dim("http://auth0.com/oauth/token-type/federated-connection-access-token")}\n` +
      `  connection: ${pc.dim("<connection_name>")}\n` +
      `  client_id: ${pc.dim("<your_client_id>")}\n` +
      `  client_secret: ${pc.dim("<your_client_secret>")}`,
    "Token Exchange Endpoint",
  );
}

// ============================================================================
// Access Token Exchange Setup
// ============================================================================

async function setupAccessTokenExchange(appId, domain) {
  // Ask if user wants to create a Custom API Client
  const createCustomApiClient =
    FLAGS.createApiClient ??
    (await p.confirm({
      message:
        "Do you want to create a Custom API Client for your backend API? (Required for Access Token Exchange)",
      initialValue: true,
    }));

  if (p.isCancel(createCustomApiClient)) {
    p.cancel("Setup cancelled.");
    process.exit(0);
  }

  if (createCustomApiClient) {
    await createCustomAPIClient(domain);
  }

  // Show usage instructions
  p.note(
    `${pc.bold("Access Token Exchange Usage:")}\n\n` +
      `Your backend API exchanges Auth0 access tokens for external provider tokens:\n\n` +
      `POST ${pc.cyan(`https://${domain}/oauth/token`)}\n\n` +
      `${pc.bold("Parameters:")}\n` +
      `  grant_type: ${pc.dim(TOKEN_VAULT_GRANT_TYPE)}\n` +
      `  subject_token: ${pc.dim("<auth0_access_token>")}\n` +
      `  subject_token_type: ${pc.dim("urn:ietf:params:oauth:token-type:access_token")}\n` +
      `  requested_token_type: ${pc.dim("http://auth0.com/oauth/token-type/federated-connection-access-token")}\n` +
      `  connection: ${pc.dim("<connection_name>")}\n` +
      `  client_id: ${pc.dim("<custom_api_client_id>")}\n` +
      `  client_secret: ${pc.dim("<custom_api_client_secret>")}`,
    "Token Exchange Endpoint",
  );
}

async function createCustomAPIClient(domain) {
  let details;

  if (FLAGS.apiIdentifier != null) {
    details = {
      apiIdentifier: FLAGS.apiIdentifier,
      name: FLAGS.apiClientName ?? "Backend API Token Vault Client",
    };
  } else {
    details = await p.group(
      {
        apiIdentifier: () =>
          p.text({
            message: "Enter your backend API identifier (audience):",
            placeholder: "https://api.example.com",
            validate: (value) => {
              if (!value) return "API identifier is required";
              if (!value.startsWith("http"))
                return "API identifier should be a URL";
            },
          }),
        name: () =>
          p.text({
            message: "Enter a name for the Custom API Client:",
            placeholder: "Backend API Token Vault Client",
            defaultValue: "Backend API Token Vault Client",
          }),
      },
      {
        onCancel: () => {
          p.cancel("Setup cancelled.");
          process.exit(0);
        },
      },
    );
  }

  const s = p.spinner();
  s.start("Creating Custom API Client...");

  try {
    // First, check if the API (resource server) exists
    const { stdout: apisOutput } = await runAuth0Api(
      "get",
      `resource-servers?identifier=${encodeURIComponent(details.apiIdentifier)}`,
    );
    const apis = JSON.parse(apisOutput);

    let apiId;
    if (apis && apis.length > 0) {
      apiId = apis[0].id;
      log(`Found existing API: ${apiId}`);
    } else {
      // Create the API
      const { stdout: newApiOutput } = await runAuth0Api(
        "post",
        "resource-servers",
        {
          identifier: details.apiIdentifier,
          name: details.name.replace("Client", "").trim(),
          signing_alg: "RS256",
          allow_offline_access: true,
        },
      );
      const newApi = JSON.parse(newApiOutput);
      apiId = newApi.id;
      log(`Created new API: ${apiId}`);
    }

    // Create the Custom API Client (M2M application linked to the API)
    const { stdout: clientOutput } = await runAuth0Command([
      "apps",
      "create",
      "--name",
      details.name,
      "--type",
      "m2m",
      "--json",
      "--no-input",
    ]);
    const client = JSON.parse(clientOutput);

    // Enable Token Vault grant type for the Custom API Client
    let clientGrantTypes = client.grant_types || ["client_credentials"];
    if (!clientGrantTypes.includes(TOKEN_VAULT_GRANT_TYPE)) {
      clientGrantTypes.push(TOKEN_VAULT_GRANT_TYPE);
    }

    await runAuth0Api("patch", `clients/${client.client_id}`, {
      is_first_party: true,
      oidc_conformant: true,
      grant_types: clientGrantTypes,
    });

    s.stop("Custom API Client created");

    p.note(
      `${pc.bold("Custom API Client Details:")}\n\n` +
        `  Name:          ${pc.cyan(client.name)}\n` +
        `  Client ID:     ${pc.dim(client.client_id)}\n` +
        `  Client Secret: ${pc.dim(client.client_secret)}\n` +
        `  API Audience:  ${pc.dim(details.apiIdentifier)}\n\n` +
        `${pc.yellow("Save these credentials securely!")}`,
      "Custom API Client",
    );

    return { clientId: client.client_id, apiIdentifier: details.apiIdentifier };
  } catch (error) {
    s.stop("Failed to create Custom API Client");
    log(`Error: ${error.message}`);
    if (error.stdout) log(`stdout: ${error.stdout}`);
    if (error.stderr) log(`stderr: ${error.stderr}`);

    p.log.warning(
      "Please create the Custom API Client manually in the Auth0 Dashboard.",
    );
    return null;
  }
}

// ============================================================================
// Privileged Worker Token Exchange Setup
// ============================================================================

async function setupPrivilegedWorker(appId, domain) {
  // Configure the application for Private Key JWT authentication
  const configurePrivateKeyJwt =
    FLAGS.configurePrivateKeyJwt ??
    (await p.confirm({
      message:
        "Do you want to configure Private Key JWT authentication for the worker application?",
      initialValue: true,
    }));

  if (p.isCancel(configurePrivateKeyJwt)) {
    p.cancel("Setup cancelled.");
    process.exit(0);
  }

  if (configurePrivateKeyJwt) {
    await configurePrivateKeyJwtAuth(appId, domain);
  }

  // Show usage instructions
  p.note(
    `${pc.bold("Privileged Worker Token Exchange:")}\n\n` +
      `Worker applications use signed JWT bearer tokens to exchange for external provider tokens.\n\n` +
      `${pc.bold("JWT Requirements:")}\n` +
      `  Header:\n` +
      `    typ: "token-vault-req+jwt"\n` +
      `    alg: "RS256" (or your signing algorithm)\n` +
      `    kid: "<key_id>" (optional)\n\n` +
      `  Payload:\n` +
      `    sub: "<user_id>" (Auth0 user_id)\n` +
      `    aud: "https://${domain}/"\n` +
      `    iss: "<client_id>"\n` +
      `    iat: <issued_at_timestamp>\n` +
      `    exp: <expiration_timestamp>\n\n` +
      `${pc.bold("Token Exchange Request:")}\n` +
      `POST ${pc.cyan(`https://${domain}/oauth/token`)}\n\n` +
      `  grant_type: ${pc.dim(TOKEN_VAULT_GRANT_TYPE)}\n` +
      `  subject_token: ${pc.dim("<signed_jwt>")}\n` +
      `  subject_token_type: ${pc.dim("urn:ietf:params:oauth:token-type:jwt")}\n` +
      `  requested_token_type: ${pc.dim("http://auth0.com/oauth/token-type/federated-connection-access-token")}\n` +
      `  connection: ${pc.dim("<connection_name>")}\n` +
      `  client_id: ${pc.dim("<worker_client_id>")}\n` +
      `  client_assertion_type: ${pc.dim("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")}\n` +
      `  client_assertion: ${pc.dim("<client_jwt>")}`,
    "Privileged Worker Configuration",
  );
}

async function configurePrivateKeyJwtAuth(appId, domain) {
  const s = p.spinner();
  s.start("Configuring Private Key JWT authentication...");

  try {
    // Update the application to use Private Key JWT
    await runAuth0Api("patch", `clients/${appId}`, {
      token_endpoint_auth_method: "private_key_jwt",
    });

    s.stop("Application configured for Private Key JWT");

    const settingsUrl = buildDashboardUrl(
      domain,
      `applications/${appId}/credentials`,
    );

    p.note(
      `${pc.bold("Next Steps:")}\n\n` +
        `1. Generate an RSA key pair for signing JWTs\n\n` +
        `2. Add the public key to your application:\n` +
        `   ${pc.cyan(settingsUrl)}\n\n` +
        `3. Go to the ${pc.bold("Credentials")} tab\n\n` +
        `4. Under ${pc.bold("Public Key")}, upload your public key (PEM or JWKS format)\n\n` +
        `${pc.bold("Generate keys with OpenSSL:")}\n` +
        `  ${pc.dim("openssl genrsa -out private.pem 2048")}\n` +
        `  ${pc.dim("openssl rsa -in private.pem -pubout -out public.pem")}`,
      "Configure Public Key",
    );
  } catch (error) {
    s.stop("Could not configure Private Key JWT automatically");
    log(`Error: ${error.message}`);

    p.log.warning(
      "Please configure Private Key JWT authentication manually in the Dashboard.",
    );
  }
}

// ============================================================================
// Helpers
// ============================================================================

function buildDashboardUrl(domain, path) {
  const domainParts = domain.split(".");
  if (domainParts.length === 4) {
    const [tenant, region] = domainParts;
    return `https://manage.auth0.com/dashboard/${region}/${tenant}/${path}`;
  } else {
    const [tenant] = domainParts;
    return `https://manage.auth0.com/dashboard/us/${tenant}/${path}`;
  }
}

function showCompletionSummary(app, domain, flavor) {
  const flavorConfig = TOKEN_VAULT_FLAVORS[flavor];
  const settingsUrl = buildDashboardUrl(
    domain,
    `applications/${app.id}/settings`,
  );

  const docsUrls = {
    connected_accounts:
      "https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault/connected-accounts-for-token-vault",
    refresh_token_exchange:
      "https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault/refresh-token-exchange-with-token-vault",
    access_token_exchange:
      "https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault/access-token-exchange-with-token-vault",
    privileged_worker:
      "https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault/privileged-worker-token-exchange-with-token-vault",
  };

  p.note(
    `${pc.bold("Application Details:")}\n` +
      `  Name:      ${pc.cyan(app.name)}\n` +
      `  Client ID: ${pc.dim(app.id)}\n\n` +
      `${pc.bold("Configuration:")}\n` +
      `  Type: ${pc.cyan(flavorConfig.label)}\n\n` +
      `${pc.bold("Settings:")}\n` +
      `  ${pc.cyan(settingsUrl)}\n\n` +
      `${pc.bold("Documentation:")}\n` +
      `  ${pc.cyan(docsUrls[flavor])}`,
    "Setup Complete",
  );
}

// ============================================================================
// Entry Point
// ============================================================================

main().catch((error) => {
  p.log.error(error.message);
  process.exit(1);
});
