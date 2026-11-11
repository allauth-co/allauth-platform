-- Platform registry only: a Google OAuth client belongs to one exact application environment.
CREATE TABLE IF NOT EXISTS public."allauthProjectGoogleProvider" (
  "projectId" TEXT PRIMARY KEY REFERENCES public."allauthProject"(id) ON DELETE CASCADE,
  version INTEGER NOT NULL CHECK (version > 0),
  enabled BOOLEAN NOT NULL DEFAULT false,
  "clientId" TEXT NOT NULL DEFAULT '',
  "encryptedClientSecret" TEXT NOT NULL DEFAULT '',
  "updatedBy" TEXT NOT NULL,
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
