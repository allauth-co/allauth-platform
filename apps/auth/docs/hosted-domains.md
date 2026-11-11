# Hosted application domains

An app environment has two default addresses: `https://<environment-slug>-accounts.allauth.co` and `https://<environment-slug>-api.allauth.co`. Flat names fit the zone's first-level wildcard certificate. Clients can add `accounts.<customer-domain>` and `frontend-api.<customer-domain>` from the selected environment's Domains screen.

Each address resolves an exact project registry entry and uses that environment's existing PostgreSQL schema and native Better Auth instance. Unrecognized, deleted or inactive customer domains return an error; they never fall through to the platform authentication instance. Both hostnames can serve native authentication and continuation screens so their own host-only challenge cookies remain available.

Cookies are host-only. The accounts and frontend API addresses do not automatically share a browser session. Use the same chosen authentication hostname consistently, or use the supplied app-side server proxy integration. AllAuth's central OAuth broker bridges social login into a realm; it does not merge different apps' user databases. Passkeys are tied to the enrolled hostname and may need re-enrollment after a domain change.

## Infrastructure

Cloudflare for SaaS terminates TLS, then an ordinary Worker forwards to the existing Railway application over HTTPS. The gateway signs the exact method, path, query, body digest, original hostname, Cloudflare client IP and timestamp. Railway verifies that signature and re-resolves the active project mapping. Server-rendered reads require a separate short-lived proof minted by the Next proxy; client-provided proofs are stripped. Platform cookies, foreign project cookies and bearer authorization are removed from hosted requests.

Required Railway variables are `ALLAUTH_EDGE_SECRET` (at least 32 characters), `ALLAUTH_ORIGIN_HOSTNAME`, `ALLAUTH_HOSTING_BASE_DOMAIN`, `CLOUDFLARE_SAAS_ZONE_ID`, `CLOUDFLARE_SAAS_API_TOKEN`, `CLOUDFLARE_SAAS_CNAME_TARGET` and `CLOUDFLARE_SAAS_READY`. The certificate token has only SSL and Certificates Write on the AllAuth zone. Store the same gateway secret as a Worker secret; never embed it in source, browser configuration or SDK packages.

The AllAuth gateway DNS records are proxied `edge.allauth.co AAAA 100::`, `*.allauth.co CNAME edge.allauth.co`, and `frontend-api.allauth.co CNAME edge.allauth.co`. The SaaS fallback origin is `edge.allauth.co`. The zone's `*/*` Worker route captures customer hosts; a more specific `allauth.co/*` route with no Worker preserves the platform origin. Preserve existing apex, verification and email DNS records.

This follows [Cloudflare's Worker fallback-origin documentation](https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/start/advanced-settings/worker-as-origin/). The worker configuration is `wrangler.domains.jsonc`; the origin is the existing `your-service.up.railway.app` service. Deploy the proxy-aware Railway image with readiness disabled before attaching the global Worker route. Verify a forged direct envelope returns 403, a signed request to an unregistered hostname returns 404, and the apex readiness endpoint returns 200. Then set `CLOUDFLARE_SAAS_READY=true` and verify the resulting deployment. Railway's unsigned GET/HEAD health probe can reach only the exact `/api/health` readiness endpoint through an internal hostname.


## Customer verification

Registering a domain reserves both hostnames and generates distinct AllAuth ownership TXT records. Verify requires both proofs before attempting provider registration. The console separately shows provider ownership, certificate validation, routing CNAME, TLS status and last checked time. Both names need active provider status, active TLS and the expected CNAME route before the pair becomes usable.

Verification is manual in this release. Last checked describes the latest operator-triggered DNS/provider read; it does not imply continuous monitoring. Removing a domain immediately disables the binding and removes its broker redirects, then confirms provider cleanup before releasing the reservation. If cleanup fails, the reservation stays in a pending cleanup state.

The app caps automatic registrations at 100 hostnames and checks Cloudflare quota before creation. External operators can independently consume Cloudflare quota; the app's counter cannot provide an account-wide billing lock. No extra paid hostname capacity should be enabled automatically.
