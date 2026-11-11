-- Realm-local, immutable source provenance. It survives invitation cancellation or deletion.
CREATE TABLE IF NOT EXISTS "allauthInvitationImport" (
  id TEXT PRIMARY KEY,
  "sourceInstance" TEXT NOT NULL,
  "sourceInvitationId" TEXT NOT NULL,
  "invitationId" TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  "sourceUpdatedAt" TIMESTAMPTZ,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE ("sourceInstance", "sourceInvitationId")
);
