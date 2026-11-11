CREATE TABLE IF NOT EXISTS "allauthAuthConfiguration" (
  id TEXT PRIMARY KEY,
  policy JSONB NOT NULL,
  version INTEGER NOT NULL CHECK (version > 0),
  "updatedBy" TEXT NOT NULL,
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
