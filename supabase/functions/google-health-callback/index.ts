import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const STATE_MAX_AGE_MS = 10 * 60 * 1000;
const SITE_URL = Deno.env.get("SITE_URL") || "https://cynergists.ai";

function bytesToHex(bytes: Uint8Array) { return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join(""); }
function hexToBytes(hex: string) { const out = new Uint8Array(hex.length / 2); for (let i=0;i<hex.length;i+=2) out[i/2]=parseInt(hex.slice(i,i+2),16); return out; }
function ab(bytes: Uint8Array): ArrayBuffer { return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer; }

async function sign(value: string, secret: string) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const bytes = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return bytesToHex(new Uint8Array(bytes));
}

async function encrypt(value: string, secret: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret.trim()));
  const key = await crypto.subtle.importKey("raw", digest, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(value));
  const combined = new Uint8Array(iv.length + cipher.byteLength);
  combined.set(iv); combined.set(new Uint8Array(cipher), iv.length);
  return bytesToHex(combined);
}

function redirect(status: string, message: string) {
  const q = new URLSearchParams({ google_health: status, message });
  return Response.redirect(`${SITE_URL}/app?${q.toString()}`, 302);
}

Deno.serve(async (req) => {
  const requestId = crypto.randomUUID();
  let userId: string | null = null;
  try {
    const url = new URL(req.url);
    if (url.searchParams.get("error")) return redirect("error", "Google Health authorization was denied");
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    if (!code || !state) return redirect("error", "Missing Google Health authorization response");

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const serviceKey = Deno.env.get("APP_SERVICE_ROLE_KEY") || Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
    const stateSecret = Deno.env.get("GOOGLE_HEALTH_STATE_SECRET") || serviceKey;
    const encryptionKey = Deno.env.get("TOKEN_ENCRYPTION_KEY");
    const clientId = Deno.env.get("GOOGLE_HEALTH_CLIENT_ID");
    const clientSecret = Deno.env.get("GOOGLE_HEALTH_CLIENT_SECRET");
    if (!serviceKey || !stateSecret || !encryptionKey || !clientId || !clientSecret) {
      console.error("[google-health-callback] missing required server configuration", requestId);
      return redirect("error", "Google Health is not fully configured");
    }

    const decoded = JSON.parse(atob(state));
    if (!decoded?.payload || !decoded?.sig || await sign(decoded.payload, stateSecret) !== decoded.sig) return redirect("error", "Invalid authorization state");
    const parsed = JSON.parse(decoded.payload);
    if (!parsed.userId || !parsed.ts || Date.now() - parsed.ts > STATE_MAX_AGE_MS) return redirect("error", "Authorization link expired");
    userId = parsed.userId;

    const redirectUri = `${supabaseUrl}/functions/v1/google-health-callback`;
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, grant_type: "authorization_code" }),
    });
    const token = await tokenRes.json() as Record<string, any>;
    if (!tokenRes.ok || !token.access_token) throw new Error(`token_exchange_failed:${token.error || tokenRes.status}`);

    const infoRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", { headers: { Authorization: `Bearer ${token.access_token}` } });
    const info = infoRes.ok ? await infoRes.json() as Record<string, any> : {};
    const email = typeof info.email === "string" ? info.email : null;
    const now = Date.now();
    const accessToken = await encrypt(token.access_token, encryptionKey);
    const refreshToken = token.refresh_token ? await encrypt(token.refresh_token, encryptionKey) : null;
    const scopes = typeof token.scope === "string" ? token.scope.split(" ").filter(Boolean) : [];
    const service = createClient(supabaseUrl, serviceKey);

    const { data: existing } = await service.from("health_connections")
      .select("id,refresh_token").eq("user_id", userId).eq("provider", "google_health")
      .filter("google_account_email", email ? "eq" : "is", email).maybeSingle();

    const record: Record<string, unknown> = {
      user_id: userId, provider: "google_health", google_account_email: email,
      access_token: accessToken,
      token_expires_at: token.expires_in ? new Date(now + Number(token.expires_in) * 1000).toISOString() : null,
      refresh_token_expires_at: token.refresh_token_expires_in ? new Date(now + Number(token.refresh_token_expires_in) * 1000).toISOString() : null,
      scopes, status: "connected", last_error: null,
      metadata: { encrypted: true, token_type: token.token_type || "Bearer" },
      updated_at: new Date().toISOString(),
    };
    if (refreshToken) record.refresh_token = refreshToken;

    let connectionId = existing?.id;
    if (existing) {
      if (!refreshToken) delete record.refresh_token;
      delete record.user_id; delete record.provider;
      const { error } = await service.from("health_connections").update(record).eq("id", existing.id);
      if (error) throw error;
    } else {
      if (!refreshToken) throw new Error("missing_refresh_token_on_initial_connect");
      const { data, error } = await service.from("health_connections").insert(record).select("id").single();
      if (error) throw error; connectionId = data.id;
    }

    await service.from("health_audit_logs").insert({ user_id: userId, connection_id: connectionId, action: "oauth_connect", status: "success", request_id: requestId, metadata: { scopes, email_present: !!email } });
    return redirect("success", "Google Health connected");
  } catch (error) {
    console.error("[google-health-callback]", requestId, error);
    try {
      const supabaseUrl = Deno.env.get("SUPABASE_URL");
      const serviceKey = Deno.env.get("APP_SERVICE_ROLE_KEY") || Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
      if (supabaseUrl && serviceKey) await createClient(supabaseUrl, serviceKey).from("health_audit_logs").insert({ user_id: userId, action: "oauth_connect", status: "failure", request_id: requestId, metadata: { reason: error instanceof Error ? error.message : "unknown" } });
    } catch { /* audit must never mask callback failure */ }
    return redirect("error", "Unable to connect Google Health");
  }
});
