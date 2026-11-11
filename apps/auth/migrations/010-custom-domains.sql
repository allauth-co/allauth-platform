-- Platform-only ownership registry. Native tenant schemas must skip this migration.
CREATE TABLE public."allauthDomainPair" (
  id TEXT PRIMARY KEY,
  "projectId" TEXT NOT NULL REFERENCES public."allauthProject"(id) ON DELETE RESTRICT,
  domain TEXT NOT NULL CHECK (domain=lower(domain) AND char_length(domain) BETWEEN 4 AND 240),
  deleting BOOLEAN NOT NULL DEFAULT false,
  "createdBy" TEXT REFERENCES public."user"(id) ON DELETE SET NULL,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (id,"projectId"),
  UNIQUE ("projectId",domain)
);
CREATE TABLE public."allauthCustomHostname" (
  id TEXT PRIMARY KEY,
  "pairId" TEXT NOT NULL,
  "projectId" TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('accounts','frontend-api')),
  hostname TEXT NOT NULL UNIQUE CHECK (hostname=lower(hostname) AND char_length(hostname)<=253),
  "proofToken" TEXT NOT NULL,
  "ownershipVerifiedAt" TIMESTAMPTZ,
  "providerId" TEXT UNIQUE,
  "providerAttemptedAt" TIMESTAMPTZ,
  "providerStatus" TEXT,
  "sslStatus" TEXT,
  "validationRecords" JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof("validationRecords")='array'),
  "routingVerifiedAt" TIMESTAMPTZ,
  "checkedAt" TIMESTAMPTZ,
  "lastIssue" TEXT,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY ("pairId","projectId") REFERENCES public."allauthDomainPair"(id,"projectId") ON DELETE CASCADE,
  UNIQUE ("pairId",kind)
);
CREATE INDEX "allauthCustomHostname_project" ON public."allauthCustomHostname" ("projectId","pairId");
CREATE INDEX "allauthDomainPair_project" ON public."allauthDomainPair" ("projectId","createdAt");
