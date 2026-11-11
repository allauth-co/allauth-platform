-- Platform registry only. These credentials grant bounded directory reads, never sessions or administration.
CREATE TABLE IF NOT EXISTS public."allauthProjectBackendCredential" (
  id TEXT PRIMARY KEY,
  "projectId" TEXT NOT NULL REFERENCES public."allauthProject"(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  scope TEXT NOT NULL CHECK (scope = 'directory:read'),
  "keyHash" TEXT NOT NULL UNIQUE,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
  "expiresAt" TIMESTAMPTZ NOT NULL,
  "revokedAt" TIMESTAMPTZ,
  "createdBy" TEXT NOT NULL,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS "allauthProjectBackendCredential_project" ON public."allauthProjectBackendCredential" ("projectId");
