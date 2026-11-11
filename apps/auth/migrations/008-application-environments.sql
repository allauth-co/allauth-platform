-- Each environment remains a distinct authentication realm and storage namespace.
ALTER TABLE public."allauthProject" ADD COLUMN IF NOT EXISTS "applicationId" TEXT;
ALTER TABLE public."allauthProject" ADD COLUMN IF NOT EXISTS environment TEXT CHECK (environment IN ('development','production'));
UPDATE public."allauthProject" SET "applicationId"=id WHERE "applicationId" IS NULL;
UPDATE public."allauthProject" SET environment=CASE WHEN "primaryOrigin" LIKE 'http://%' THEN 'development' ELSE 'production' END WHERE environment IS NULL;
ALTER TABLE public."allauthProject" ALTER COLUMN "applicationId" SET NOT NULL;
ALTER TABLE public."allauthProject" ALTER COLUMN environment SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS "allauthProject_application_environment" ON public."allauthProject" ("applicationId",environment);
