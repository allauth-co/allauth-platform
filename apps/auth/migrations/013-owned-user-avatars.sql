-- Per-realm additive ownership. Never backfill or infer legacy branding/external URL ownership.
CREATE TABLE "allauthAvatarLifecycle" (
 id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id), "protocolVersion" INTEGER NOT NULL DEFAULT 1 CHECK ("protocolVersion"=1),
 "assetOrigin" TEXT, "healthyAt" TIMESTAMPTZ
);
INSERT INTO "allauthAvatarLifecycle" (id) VALUES (TRUE);
CREATE TABLE "allauthAvatarUserState" (
 "userId" TEXT PRIMARY KEY REFERENCES "user"(id) ON DELETE CASCADE, deleting BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TABLE "allauthAvatarAsset" (
 id TEXT PRIMARY KEY, "userId" TEXT REFERENCES "user"(id) ON DELETE SET NULL,
 "projectId" TEXT NOT NULL, "workspaceId" TEXT NOT NULL, "applicationId" TEXT NOT NULL,
 url TEXT UNIQUE NOT NULL, "objectPath" TEXT UNIQUE NOT NULL,
 state TEXT NOT NULL CHECK (state IN ('prepared','draft','active','delete_pending','deleted')),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts>=0), "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 "expiresAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()+INTERVAL '24 hours', "availableAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(), "erasedAt" TIMESTAMPTZ
);
CREATE INDEX "allauthAvatarAsset_owner" ON "allauthAvatarAsset" ("userId",state);
CREATE INDEX "allauthAvatarAsset_cleanup" ON "allauthAvatarAsset" ("availableAt") WHERE state<>'deleted';
CREATE FUNCTION allauth_avatar_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE origin TEXT; permitted BOOLEAN; ending BOOLEAN; owned BOOLEAN;
BEGIN
 IF TG_OP='DELETE' THEN
  EXECUTE format('UPDATE %I."allauthAvatarAsset" SET state=''delete_pending'',"availableAt"=NOW() WHERE "userId"=$1 AND state<>''deleted''',TG_TABLE_SCHEMA) USING OLD.id;
  RETURN OLD;
 END IF;
 EXECUTE format('SELECT "assetOrigin" FROM %I."allauthAvatarLifecycle" WHERE id=TRUE',TG_TABLE_SCHEMA) INTO origin;
 owned := btrim(NEW.image) ~* '^(https?:)?//[^/]+/avatars/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/){3}[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}[.](png|jpg|webp)([?#].*)?$';
 IF TG_OP='INSERT' THEN
  IF owned OR (origin IS NOT NULL AND NEW.image LIKE origin||'/avatars/%%') THEN RAISE EXCEPTION 'Upload a profile photo after creating this account.'; END IF;
  RETURN NEW;
 END IF;
 IF owned OR (origin IS NOT NULL AND NEW.image LIKE origin||'/avatars/%%') THEN
  EXECUTE format('SELECT deleting FROM %I."allauthAvatarUserState" WHERE "userId"=$1',TG_TABLE_SCHEMA) INTO ending USING NEW.id;
  EXECUTE format('SELECT TRUE FROM %I."allauthAvatarAsset" WHERE "userId"=$1 AND url=$2 AND state IN (''draft'',''active'') AND (state=''active'' OR "expiresAt">NOW()) FOR UPDATE',TG_TABLE_SCHEMA) INTO permitted USING NEW.id,NEW.image;
  IF ending OR permitted IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'Choose a current profile photo uploaded for this account.'; END IF;
 END IF;
 IF OLD.image IS DISTINCT FROM NEW.image THEN
  EXECUTE format('UPDATE %I."allauthAvatarAsset" SET state=''delete_pending'',"availableAt"=NOW() WHERE "userId"=$1 AND url IS DISTINCT FROM $2 AND state<>''deleted''',TG_TABLE_SCHEMA) USING NEW.id,NEW.image;
  EXECUTE format('UPDATE %I."allauthAvatarAsset" SET state=''active'' WHERE "userId"=$1 AND url=$2 AND state IN (''draft'',''active'')',TG_TABLE_SCHEMA) USING NEW.id,NEW.image;
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER allauth_avatar_image_guard BEFORE UPDATE OF image ON "user" FOR EACH ROW EXECUTE FUNCTION allauth_avatar_guard();
CREATE TRIGGER allauth_avatar_delete_guard BEFORE DELETE ON "user" FOR EACH ROW EXECUTE FUNCTION allauth_avatar_guard();
CREATE TRIGGER allauth_avatar_insert_guard BEFORE INSERT ON "user" FOR EACH ROW EXECUTE FUNCTION allauth_avatar_guard();
