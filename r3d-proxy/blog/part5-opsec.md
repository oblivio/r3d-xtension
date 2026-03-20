# Part 5: Operational Security -- Stealth, Rotation, and Monitoring

*This is Part 5 of a 6-part series on building R3D. [Start from Part 1](part1-architecture.md) for the full architecture overview.*

---

## The Problem with Red Team Tools

Red team tools have a detection problem. Blue teams are getting better at identifying automated tooling through:

1. **TLS fingerprinting (JA3/JA4)** -- every HTTP client library has a unique cipher suite ordering that identifies it on the wire
2. **Header ordering analysis** -- Python's `httpx` and `requests` order HTTP headers differently than Chrome or Firefox
3. **API key exposure** -- if the master key is transmitted to extensions or browsers, any local process can steal it
4. **Static secrets** -- a JWT signing key that never rotates means a compromised token provides permanent access
5. **Container escape** -- root containers with full capabilities give attackers everything if they break out

R3D addresses each of these with a layered OPSEC stack.

---

## TLS Fingerprint Randomization

### The JA3/JA4 Problem

JA3 and JA4 are TLS fingerprinting techniques that identify HTTP clients by their TLS Client Hello message -- specifically the cipher suite list, extension list, and elliptic curve parameters. Python's `httpx` (and `requests`, `urllib3`, etc.) all have distinctive fingerprints that scream "automated tool" to any blue team running JA3 monitoring.

### The Solution: Browser Impersonation

The stealth module (`core/stealth.py`) randomizes the TLS fingerprint to match real browser patterns. It maintains cipher suite lists for Chrome, Firefox, and Safari:

```python
_BROWSER_CIPHER_SUITES = [
    # Chrome 120+ pattern
    [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
    ],
    # Firefox 121+ pattern
    [
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_256_GCM_SHA384",
        # ...
    ],
    # Safari 17+ pattern
    # ...
]
```

Each outbound request creates an SSL context with a randomly selected browser profile:

```python
def create_stealth_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    cipher_suite = random.choice(_BROWSER_CIPHER_SUITES)
    ctx.set_ciphers(":".join(cipher_suite))
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx
```

### Header Ordering Normalization

TLS fingerprints aren't the only signal. HTTP header ordering varies by browser. Chrome sends `Host` first, then `Connection`, then `Sec-Ch-Ua`. Firefox sends `Host`, then `User-Agent`, then `Accept`.

The stealth module reorders headers to match the selected browser profile:

```python
_CHROME_HEADER_ORDER = [
    "Host", "Connection", "Cache-Control", "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile",
    "Sec-Ch-Ua-Platform", "Upgrade-Insecure-Requests", "User-Agent", "Accept",
    "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest",
    "Accept-Encoding", "Accept-Language", "Cookie"
]

def normalize_headers(headers: dict, profile: str = "random") -> dict:
    if profile == "random":
        profile = random.choice(["chrome", "firefox", "safari"])
    order_template = {"chrome": _CHROME_HEADER_ORDER, ...}[profile]
    normalized = {}
    for canonical_name in order_template:
        if canonical_name.lower() in headers_lower:
            normalized[canonical_name] = headers_lower.pop(canonical_name.lower())
    # Remaining headers appended last
    for name, value in headers_lower.values():
        normalized[name] = value
    return normalized
```

Python 3.7+ preserves dictionary insertion order, so rebuilding the dict in browser order produces correctly ordered HTTP headers on the wire.

### The Stealth Client Factory

All of this is wrapped in a factory that returns an httpx client ready to impersonate a browser:

```python
def create_stealth_client(profile="random", timeout=30, follow_redirects=True, **kwargs):
    ssl_context = create_stealth_ssl_context()
    limits = httpx.Limits(
        max_keepalive_connections=10,
        max_connections=100,
        keepalive_expiry=30.0,
    )
    client = httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        limits=limits,
        http2=True,
        verify=ssl_context,
        **kwargs
    )
    return client
```

Connection pooling limits are set to avoid the "too many connections from one source" pattern that automated tools typically exhibit.

The replay module (`core/replay.py`) makes stealth the default:

```python
def get_http_client(stealth: bool = True, **kwargs):
    if stealth:
        from core.stealth import create_stealth_client
        return create_stealth_client(**kwargs)
    return httpx.AsyncClient(**kwargs)
```

Every outbound request from every router uses the stealth client unless explicitly opted out.

### Human-Like Timing Jitter

Automated tools have consistent request timing. Humans don't. The stealth module includes a jitter function:

```python
def add_human_delay(min_ms=50, max_ms=300) -> float:
    delay_ms = random.uniform(min_ms, max_ms)
    return delay_ms / 1000.0
```

Combined with the OPSEC `throttle()` function called by all routers, this adds randomized delays between server-side requests to avoid rate-based detection patterns.

---

## Handshake Hardening

### The Old Way

The original handshake was a `GET` request that returned the raw master API key:

```bash
# Any local process could do this
curl http://localhost:4000/r3d/handshake
# {"apiKey": "sk-...", ...}
```

Any process on the machine -- malware, a rogue browser extension, a compromised npm package -- could steal the master key.

### The New Way

The hardened handshake (`routers/dashboard.py`) implements six security measures:

**1. POST-only** -- prevents CSRF attacks and accidental discovery via browser navigation.

**2. Extension ID validation** -- the extension sends its `chrome.runtime.id`, which the proxy validates against an allowlist:

```bash
R3D_ALLOWED_EXTENSION_IDS=chrome-extension://abc123...  # Production
R3D_ALLOWED_EXTENSION_IDS=*                              # Development
```

**3. Rate limiting** -- a sliding window of 5 attempts per minute per IP. The sixth attempt gets `429 Too Many Requests`:

```bash
for i in {1..6}; do
  curl -X POST http://localhost:4000/r3d/handshake \
    -d '{"extensionId":"test-id"}'
done
# 6th attempt: 429 Too Many Requests
```

**4. Audit logging** -- every handshake attempt (success and failure) is logged to the `r3d_audit_log` collection with IP, extension ID, and timestamp.

**5. JWT minting** -- instead of returning the master API key, the proxy mints a 24-hour JWT:

```bash
curl -X POST http://localhost:4000/r3d/handshake \
  -d '{"extensionId":"chrome-extension://abc123"}'
# {"ok": true, "token": "eyJ...", ...}
```

The master key stays server-side. The extension receives a scoped, time-limited token.

**6. Localhost-only** -- the endpoint rejects connections from non-localhost IPs.

### Dashboard Session Tokens

The dashboard login also changed. Previously, visiting `/` set a cookie containing the raw API key. Now it mints a 1-hour JWT with `role=operator`. The master key never reaches the browser.

---

## JWT Rotation

### Why Rotate

A static JWT signing secret means a compromised token (or a compromised secret) provides permanent access. Rotation limits the blast radius -- compromised tokens expire, and even a leaked signing secret becomes useless after the next rotation.

### Implementation

The rotation module (`core/rotation.py`) stores secrets as files in `/tmp/r3d/`:

```python
ROTATION_INTERVAL_HOURS = int(os.environ.get("JWT_ROTATION_HOURS", "168"))  # 7 days

def _load_or_generate_secret(key_name: str) -> str:
    secret_file = Path(f"/tmp/r3d/{key_name}.key")
    secret_file.parent.mkdir(parents=True, exist_ok=True)
    if secret_file.exists():
        return secret_file.read_text().strip()
    new_secret = secrets.token_urlsafe(48)
    secret_file.write_text(new_secret)
    secret_file.chmod(0o600)
    return new_secret
```

On startup, `initialize_rotation()` loads or generates both `jwt_current.key` and `jwt_previous.key`. Since `/tmp` is a tmpfs mount in Docker, secrets are ephemeral per container restart.

### Zero-Downtime Rotation

When the rotation interval elapses, `rotate_secrets()` promotes the current secret to previous and generates a new current:

```python
def rotate_secrets():
    _rotation_state["previous_secret"] = _rotation_state["current_secret"]
    _rotation_state["current_secret"] = secrets.token_urlsafe(48)
    _rotation_state["rotation_time"] = datetime.now(timezone.utc)
    # Persist to disk
    Path("/tmp/r3d/jwt_current.key").write_text(_rotation_state["current_secret"])
    Path("/tmp/r3d/jwt_previous.key").write_text(_rotation_state["previous_secret"])
```

Token verification tries both secrets, providing a grace period:

```python
def verify_token_with_rotation(token: str, algorithm: str = "HS256") -> dict:
    try:
        return jwt.decode(token, get_current_secret(), algorithms=[algorithm])
    except jwt.InvalidSignatureError:
        pass
    if _rotation_state["previous_secret"]:
        try:
            return jwt.decode(token, _rotation_state["previous_secret"], algorithms=[algorithm])
        except jwt.InvalidSignatureError:
            pass
    raise jwt.InvalidTokenError("Token signature invalid with current and previous secrets")
```

Tokens signed before rotation continue working until they expire naturally (24 hours for extensions, 1 hour for dashboard). No manual intervention, no downtime, no coordinated restarts.

---

## Security Monitoring

### Internal-Only Metrics

Here's a subtle OPSEC consideration: most monitoring systems (Prometheus, Datadog, etc.) expose metrics endpoints that blue teams can discover. A red team proxy that broadcasts its own metrics is advertising its presence.

The security monitor (`core/security_monitor.py`) tracks events internally only:

```python
SecurityEventType = Literal[
    "credential_access",
    "handshake_attempt",
    "handshake_denied",
    "rate_limit_hit",
    "jwt_verification_failed",
    "kms_decrypt_error",
    "suspicious_pattern"
]

_security_events: deque = deque(maxlen=1000)
_event_counters: dict[str, list[float]] = defaultdict(list)
```

Events are tracked in-process with a rolling 1000-event deque and per-type timestamp lists for rate calculations.

### Anomaly Detection

Thresholds trigger internal alerts when event rates exceed expected baselines:

```python
THRESHOLDS = {
    "credential_access": {"window_minutes": 5, "max_count": 50},
    "handshake_denied": {"window_minutes": 5, "max_count": 10},
    "rate_limit_hit": {"window_minutes": 10, "max_count": 5},
    "jwt_verification_failed": {"window_minutes": 5, "max_count": 20},
    "kms_decrypt_error": {"window_minutes": 10, "max_count": 3},
}
```

When a threshold is exceeded, the monitor logs a warning internally. There are no external webhooks, no Slack alerts, no Prometheus endpoints. The metrics are accessible only through the authenticated `/r3d/security/metrics` endpoint:

```json
{
  "rates": {
    "credential_access": {"1m": 5, "5m": 23, "1h": 142},
    "handshake_denied": {"1m": 0, "5m": 2, "1h": 8}
  },
  "anomalies_detected": 0
}
```

For production deployments that need SIEM integration, the monitoring is designed to be extended -- but the default is silence.

---

## Container Hardening

### Non-Root Execution

The Dockerfile creates a dedicated `r3d` user and switches to it before the entrypoint:

```dockerfile
RUN groupadd -r r3d --gid=1000 && \
    useradd -r -g r3d --uid=1000 --home-dir=/app --shell=/sbin/nologin r3d && \
    chown -R r3d:r3d /app
USER r3d
```

### Attack Surface Reduction

Build tools are removed after use:

```dockerfile
RUN apt-get remove -y curl unzip && apt-get autoremove -y
```

A compromised container can't `curl` payloads or download additional tools.

### Read-Only Root Filesystem

The `docker-compose.yml` mounts the root filesystem read-only:

```yaml
read_only: true
tmpfs:
  - /tmp:mode=1777,size=100M
```

Only `/tmp` (for JWT rotation keys) and the phish cache volume are writable. An attacker can't modify application code, install backdoors, or write persistent artifacts to the filesystem.

### Capability Dropping

All Linux capabilities are dropped, then only the minimum is added back:

```yaml
cap_drop:
  - ALL
cap_add:
  - NET_BIND_SERVICE  # Required for binding to port 4000
security_opt:
  - no-new-privileges:true
```

`no-new-privileges` prevents setuid binaries from escalating permissions. The container can bind to port 4000 and make network requests -- nothing else.

### Resource Limits

Defense against denial-of-service attacks on the host:

```yaml
mem_limit: 2g
mem_reservation: 512m
cpus: 2.0
pids_limit: 512
```

Memory limits prevent runaway processes from exhausting host RAM. PID limits prevent fork bombs. CPU limits prevent monopolization of host compute.

---

## Information Disclosure Reduction

### Health Endpoint

The unauthenticated `/health` endpoint was stripped to minimal disclosure:

**Before:**
```json
{
  "status": "ok",
  "version": "5.3.0",
  "mongodb": "connected",
  "csfle": {"status": "enabled", "provider": "aws", "region": "us-east-1"},
  "model": "gemini/gemini-2.0-flash"
}
```

**After (unauthenticated):**
```json
{"status": "ok"}
```

Full details are available only after authentication. This prevents version fingerprinting and technology stack enumeration by unauthenticated scanners.

### CORS Tightening

Wildcard CORS headers were replaced with explicit allowlists:

**Before:**
```python
allow_methods=["*"]
allow_headers=["*"]
```

**After:**
```python
allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
allow_headers=["Authorization", "Content-Type", "X-Request-ID", "User-Agent"]
```

---

## Putting It All Together

The OPSEC stack is layered -- each measure addresses a different attack vector:

| Layer | Measure | Threat Addressed |
|-------|---------|-----------------|
| Network | TLS fingerprint randomization | JA3/JA4 detection by blue team |
| Network | Header ordering normalization | HTTP fingerprinting |
| Network | Human-like timing jitter | Rate-based detection |
| Application | POST-only handshake | CSRF, accidental discovery |
| Application | Extension ID pinning | Rogue local processes |
| Application | Rate limiting | Brute-force handshake abuse |
| Application | JWT minting (not API key) | Credential theft window |
| Application | JWT rotation (7-day) | Blast radius of compromise |
| Application | Audit logging | Forensics and accountability |
| Application | Internal-only metrics | Blue team detection avoidance |
| Infrastructure | Non-root container | Privilege escalation |
| Infrastructure | Read-only filesystem | Persistence and tampering |
| Infrastructure | Capability dropping | Kernel exploit surface |
| Infrastructure | Resource limits | DoS against host |
| Infrastructure | Minimal disclosure | Reconnaissance prevention |

No single measure is sufficient. Together, they make the proxy significantly harder to detect, compromise, and exploit.

---

*Next up: [Part 6 -- From `docker-compose up` to Production: Deploying R3D](part6-deployment.md)*
