-- Self-hosted audit/control schema. Existing authentication and legacy audit data remain intact.
CREATE TABLE "allauthEvent" (
	"id" text PRIMARY KEY,
	"type" text NOT NULL,
	"outcome" text NOT NULL CHECK ("outcome" IN ('success', 'failure', 'blocked')),
	"actorId" text,
	"userId" text,
	"organizationId" text,
	"clientId" text,
	"targetId" text,
	"ipAddress" text,
	"userAgent" text,
	"createdAt" timestamptz NOT NULL,
	"metadata" jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX "allauthEvent_createdAt_id_idx" ON "allauthEvent" ("createdAt" DESC, "id" DESC);
CREATE INDEX "allauthEvent_userId_createdAt_idx" ON "allauthEvent" ("userId", "createdAt" DESC);
CREATE INDEX "allauthEvent_organizationId_createdAt_idx" ON "allauthEvent" ("organizationId", "createdAt" DESC);
CREATE INDEX "allauthEvent_actorId_createdAt_idx" ON "allauthEvent" ("actorId", "createdAt" DESC);
CREATE INDEX "allauthEvent_type_outcome_createdAt_idx" ON "allauthEvent" ("type", "outcome", "createdAt" DESC);

-- Stable IDs make legacy imports identifiable and repeat-safe; historical rows are not invented sign-ins.
INSERT INTO "allauthEvent" ("id", "type", "outcome", "actorId", "organizationId", "targetId", "createdAt", "metadata")
SELECT 'legacy:' || "id", 'legacy.audit', 'success', "actorId", "organizationId", "targetId", "createdAt", jsonb_build_object('legacy', true, 'version', 1, 'action', "action")
FROM "allauthAudit"
ON CONFLICT ("id") DO NOTHING;

CREATE TABLE "allauthSecurityPolicy" (
	"id" text PRIMARY KEY,
	"policy" jsonb NOT NULL,
	"updatedAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE "allauthSecurityCounter" (
	"key" text PRIMARY KEY,
	"scope" text NOT NULL,
	"count" integer NOT NULL CHECK ("count" >= 0),
	"windowStartedAt" timestamptz NOT NULL,
	"blockedUntil" timestamptz,
	"updatedAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX "allauthSecurityCounter_expiry" ON "allauthSecurityCounter" ("updatedAt");
CREATE TABLE "allauthSecurityRule" (
	"id" text PRIMARY KEY,
	"type" text NOT NULL CHECK ("type" IN ('ip','email-domain')),
	"value" text NOT NULL,
	"reason" text NOT NULL,
	"expiresAt" timestamptz,
	"createdAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE ("type","value")
);
CREATE TABLE "allauthKnownDevice" (
	"id" text PRIMARY KEY,
	"userId" text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
	"deviceHash" text NOT NULL,
	"createdAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
	"lastSeenAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE ("userId","deviceHash")
);
CREATE INDEX "allauthKnownDevice_userId" ON "allauthKnownDevice" ("userId");
