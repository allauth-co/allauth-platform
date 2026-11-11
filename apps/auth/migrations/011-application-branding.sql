-- Platform-only settings shared by an application's isolated development/production realms.
CREATE TABLE public."allauthApplicationBranding" (
  "applicationId" TEXT NOT NULL,
  "workspaceId" TEXT NOT NULL REFERENCES public."allauthWorkspace"(id) ON DELETE RESTRICT,
  version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
  branding JSONB NOT NULL CHECK (jsonb_typeof(branding)='object'),
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedBy" TEXT REFERENCES public."user"(id) ON DELETE SET NULL,
  PRIMARY KEY ("applicationId","workspaceId")
);
-- Prefer the production display name so selecting either environment yields the same initial presentation.
INSERT INTO public."allauthApplicationBranding" ("applicationId","workspaceId",branding,"createdAt","updatedAt")
SELECT "applicationId","workspaceId",jsonb_build_object('name',name,'supportEmail',NULL,'logoUrl',NULL,'logoDarkUrl',NULL,'faviconUrl',NULL,'primaryColor','#315bff','darkPrimaryColor','#7892ff','showPoweredBy',true),"createdAt",NOW()
FROM (SELECT DISTINCT ON ("applicationId","workspaceId") * FROM public."allauthProject" ORDER BY "applicationId","workspaceId",(environment='production') DESC,"createdAt",id) applications;
