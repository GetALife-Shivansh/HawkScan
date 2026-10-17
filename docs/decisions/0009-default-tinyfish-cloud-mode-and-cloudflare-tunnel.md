# ADR-0009: Default TinyFish Cloud Mode and Cloudflare Quick Tunnel for Localhost Targets

## Status
Accepted

## Context
By design, TinyFish Cloud browser agents execute inside remote cloud containers (AWS US-West). When a user configures HawkScan to evaluate an application hosted locally (e.g. `http://127.0.0.1:8000`), the cloud browser cannot reach `127.0.0.1` because the address resolves to the cloud container's own internal loopback interface, resulting in `net::ERR_CONNECTION_REFUSED`.

Previously, HawkScan guarded against this by falling back to `LOCAL_PLAYWRIGHT` for loopback addresses. However, users requested:
1. Make `TINYFISH_CLOUD` the **default** operational engine.
2. Automatically bridge local host targets (`127.0.0.1` / `localhost`) to TinyFish Cloud in AWS using an ephemeral **Cloudflare Tunnel** (`trycloudflare.com`).

## Decision
We implemented a dedicated **Cloudflare Quick Tunnel Manager** and configured `TinyFishEngine` to default to `TINYFISH_CLOUD`:

1. **`CloudflareTunnelManager` Subsystem (`hawkscan/engine/tunnel_manager.py`)**:
   - Discovers local `cloudflared` binary on system path (`/opt/homebrew/bin/cloudflared` or in `$PATH`).
   - Spawns an account-less quick tunnel: `cloudflared tunnel --url http://127.0.0.1:<port>`.
   - Scans process streams asynchronously using regex `r"https://[a-zA-Z0-9-]+\.trycloudflare\.com"` to capture the assigned public tunnel URL.
   - Provides bidirectional URL translation:
     - `map_local_to_tunnel(url)`: Translates localhost destinations to the public tunnel hostname.
     - `map_tunnel_to_local(url)`: Translates tunnel URLs back to the local address.
   - Maintains tunnel lifecycle and terminates the tunnel cleanly upon shutdown.

2. **Default TinyFish Cloud Initialization**:
   - `TinyFishEngine.start()` defaults to `use_cloud = True` whenever `TINYFISH_API_KEY` is present.
   - If the target URL is a loopback address (`127.0.0.1`, `localhost`, etc.), `TinyFishEngine` automatically provisions a Cloudflare Quick Tunnel, translates the target to the tunnel URL, and queries `https://api.browser.tinyfish.ai`.
   - Connects to TinyFish Cloud over CDP (`wss://...`), acquiring a live cloud session (`tf-XXXX`).

3. **Context Cookie Synchronization**:
   - When injecting session tokens into TinyFish Cloud contexts via `set_cookies()`, domains are adapted to match the active Cloudflare Tunnel hostname, ensuring browser cookie jar compliance and DOM accessibility (`document.cookie`).

4. **War Room UI & Telemetry Integration**:
   - War Room toolbar displays `TINYFISH_CLOUD` badge by default.
   - An active tunnel indicator chip (`🚇 Tunnel: <url>`) is displayed alongside the session identifier.
   - Live screencasts captured by TinyFish Cloud in AWS streaming over the tunnel are rendered directly in the War Room viewport.

## Consequences

### Positive
- **Out-of-the-Box Cloud Execution**: TinyFish Cloud is the default engine across all targets—both public web apps and local development servers.
- **No Complex Networking Setup**: No manual port forwarding, public DNS records, or paid tunneling services required.
- **Fail-Safe Fallback**: If `cloudflared` is not found or fails to start, the engine falls back gracefully to `LOCAL_PLAYWRIGHT`.

### Limitations
- Account-less Quick Tunnels (`trycloudflare.com`) have no SLA guarantees and may take 2-4 seconds during initial DNS propagation.

## Alternatives Rejected
1. *Forcing ngrok with Paid Tokens*: Rejected due to token requirements and friction.
2. *Restricting TinyFish Cloud to Public URLs*: Rejected as it prevented users from auditing local development builds with TinyFish Cloud.
