-- Durable UTC identity analytics is independent of audit/event retention.
-- No pre-install activity is inferred from retained sessions or audit rows.
CREATE TABLE "allauthAnalyticsCoverage" (
	"id" text PRIMARY KEY CHECK ("id" = 'native-v1'),
	"startedAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO "allauthAnalyticsCoverage" ("id") VALUES ('native-v1');

CREATE TABLE "allauthAnalyticsEntity" (
	"entityType" text NOT NULL CHECK ("entityType" IN ('users', 'organizations')),
	"entityId" text NOT NULL,
	"createdAt" timestamptz NOT NULL,
	"deletedAt" timestamptz,
	"anonymous" boolean NOT NULL DEFAULT false,
	"firstActivityDay" date,
	"lastActivityDay" date,
	PRIMARY KEY ("entityType", "entityId")
);
CREATE INDEX "allauthAnalyticsEntity_createdAt_idx" ON "allauthAnalyticsEntity" ("entityType", "createdAt", "entityId");
CREATE TABLE "allauthAnalyticsActivity" (
	"entityType" text NOT NULL CHECK ("entityType" IN ('users', 'organizations')),
	"entityId" text NOT NULL,
	"day" date NOT NULL,
	"sources" smallint NOT NULL CHECK ("sources" BETWEEN 1 AND 7),
	PRIMARY KEY ("entityType", "entityId", "day"),
	FOREIGN KEY ("entityType", "entityId") REFERENCES "allauthAnalyticsEntity" ("entityType", "entityId")
);
CREATE INDEX "allauthAnalyticsActivity_day_idx" ON "allauthAnalyticsActivity" ("entityType", "day", "entityId");
CREATE TABLE "allauthAnalyticsDaily" (
	"day" date PRIMARY KEY,
	"signIns" bigint NOT NULL DEFAULT 0,
	"failedSignIns" bigint NOT NULL DEFAULT 0
);

-- Existing identities provide actual creation dates and current all-user totals.
-- Coverage still begins now: prior deletions and prior activity are unknown.
INSERT INTO "allauthAnalyticsEntity" ("entityType", "entityId", "createdAt", "anonymous")
SELECT 'users', "id", "createdAt", COALESCE("isAnonymous", false) FROM "user";
INSERT INTO "allauthAnalyticsEntity" ("entityType", "entityId", "createdAt")
SELECT 'organizations', "id", "createdAt" FROM "organization";

CREATE FUNCTION "allauthAnalyticsIdentity"() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE kind text := CASE WHEN TG_TABLE_NAME = 'user' THEN 'users' ELSE 'organizations' END;
BEGIN
	IF TG_OP = 'DELETE' THEN
		EXECUTE format('UPDATE %I."allauthAnalyticsEntity" SET "deletedAt" = CURRENT_TIMESTAMP WHERE "entityType" = $1 AND "entityId" = $2', TG_TABLE_SCHEMA) USING kind, OLD.id;
		RETURN OLD;
	END IF;
	IF TG_OP = 'UPDATE' THEN
		IF TG_TABLE_NAME = 'user' THEN
			EXECUTE format('UPDATE %I."allauthAnalyticsEntity" SET "anonymous" = $1 WHERE "entityType" = $2 AND "entityId" = $3', TG_TABLE_SCHEMA) USING COALESCE(NEW."isAnonymous", false), kind, NEW.id;
		END IF;
		RETURN NEW;
	END IF;
	EXECUTE format('INSERT INTO %I."allauthAnalyticsEntity" ("entityType", "entityId", "createdAt", "anonymous") VALUES ($1,$2,$3,$4)', TG_TABLE_SCHEMA)
	USING kind, NEW.id, NEW."createdAt", CASE WHEN TG_TABLE_NAME = 'user' THEN COALESCE((to_jsonb(NEW)->>'isAnonymous')::boolean, false) ELSE false END;
	RETURN NEW;
END;
$$;
CREATE TRIGGER "allauthAnalytics_user" AFTER INSERT OR DELETE OR UPDATE OF "isAnonymous" ON "user" FOR EACH ROW EXECUTE FUNCTION "allauthAnalyticsIdentity"();
CREATE TRIGGER "allauthAnalytics_organization" AFTER INSERT OR DELETE ON "organization" FOR EACH ROW EXECUTE FUNCTION "allauthAnalyticsIdentity"();

CREATE FUNCTION "allauthAnalyticsFirstActivity"() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	EXECUTE format('UPDATE %I."allauthAnalyticsEntity" SET "firstActivityDay" = LEAST(COALESCE("firstActivityDay", $1), $1), "lastActivityDay" = GREATEST(COALESCE("lastActivityDay", $1), $1) WHERE "entityType" = $2 AND "entityId" = $3', TG_TABLE_SCHEMA)
	USING NEW.day, NEW."entityType", NEW."entityId";
	RETURN NEW;
END;
$$;
CREATE TRIGGER "allauthAnalytics_firstActivity" AFTER INSERT ON "allauthAnalyticsActivity" FOR EACH ROW EXECUTE FUNCTION "allauthAnalyticsFirstActivity"();

-- Only completed canonical sign-ins count. Pending MFA and security-failure mirrors do not.
CREATE FUNCTION "allauthAnalyticsSignIn"() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE event_day date := (NEW."createdAt" AT TIME ZONE 'UTC')::date;
DECLARE eligible boolean := false;
BEGIN
	IF NEW.type <> 'auth.sign-in' OR NEW.outcome NOT IN ('success', 'failure') THEN RETURN NEW; END IF;
	IF NEW.outcome = 'success' THEN
		EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I."allauthAnalyticsEntity" WHERE "entityType" = ''users'' AND "entityId" = $1 AND NOT "anonymous")', TG_TABLE_SCHEMA) INTO eligible USING NEW."userId";
		IF NOT eligible THEN RETURN NEW; END IF;
		EXECUTE format('INSERT INTO %I."allauthAnalyticsActivity" ("entityType", "entityId", "day", "sources") VALUES (''users'',$1,$2,1) ON CONFLICT ("entityType", "entityId", "day") DO UPDATE SET "sources" = "allauthAnalyticsActivity"."sources" | 1 WHERE ("allauthAnalyticsActivity"."sources" & 1) = 0', TG_TABLE_SCHEMA) USING NEW."userId", event_day;
	END IF;
	EXECUTE format('INSERT INTO %I."allauthAnalyticsDaily" ("day", "signIns", "failedSignIns") VALUES ($1,$2,$3) ON CONFLICT ("day") DO UPDATE SET "signIns" = "allauthAnalyticsDaily"."signIns" + EXCLUDED."signIns", "failedSignIns" = "allauthAnalyticsDaily"."failedSignIns" + EXCLUDED."failedSignIns"', TG_TABLE_SCHEMA)
	USING event_day, CASE WHEN NEW.outcome = 'success' THEN 1 ELSE 0 END, CASE WHEN NEW.outcome = 'failure' THEN 1 ELSE 0 END;
	RETURN NEW;
END;
$$;
CREATE TRIGGER "allauthAnalytics_signIn" AFTER INSERT ON "allauthEvent" FOR EACH ROW EXECUTE FUNCTION "allauthAnalyticsSignIn"();
