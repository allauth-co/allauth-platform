-- Platform registry only. Project auth data lives in separate PostgreSQL schemas.
CREATE TABLE IF NOT EXISTS public."allauthProject" (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z][a-z0-9-]{1,47}$'),
  "schemaName" TEXT NOT NULL UNIQUE CHECK ("schemaName" ~ '^allauth_project_[a-f0-9]{32}$'),
  "primaryOrigin" TEXT NOT NULL,
  origins JSONB NOT NULL DEFAULT '[]'::jsonb,
  "brokerClientId" TEXT NOT NULL,
  "brokerSecret" TEXT NOT NULL,
  "proxyVersion" TEXT NOT NULL,
  "createdBy" TEXT NOT NULL,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
