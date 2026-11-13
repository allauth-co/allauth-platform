-- cspell:words plpgsql xact
-- Realm provisioning also replays this file and records its checksum.
DO $migration$
BEGIN
  IF current_schema() <> 'public' THEN RETURN; END IF;

  CREATE TABLE public."allauthProjectEngineWriter" (
    "projectId" TEXT PRIMARY KEY REFERENCES public."allauthProject"(id) ON DELETE CASCADE,
    writer TEXT NOT NULL CHECK (writer IN ('legacy','allauth')),
    revision INTEGER NOT NULL CHECK (revision > 0),
    "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
  );

  CREATE FUNCTION public.allauth_project_engine_admission_key(project_id TEXT)
  RETURNS BIGINT LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $key$
    SELECT hashtextextended('allauth:project-engine-admission:v1:' || project_id,0)
  $key$;

  CREATE FUNCTION public.allauth_project_engine_writer_key(project_id TEXT)
  RETURNS BIGINT LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $key$
    SELECT hashtextextended('allauth:project-engine-writer:v1:' || project_id,0)
  $key$;

  CREATE FUNCTION public.allauth_guard_project_engine_write()
  RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $guard$
  DECLARE
    project_id TEXT := TG_ARGV[0];
    tagged_writer TEXT := nullif(current_setting('allauth.project_engine_writer',true),'');
    tagged_project TEXT := nullif(current_setting('allauth.project_engine_project_id',true),'');
    tagged_revision TEXT := nullif(current_setting('allauth.project_engine_writer_revision',true),'');
    current_writer TEXT;
    current_revision INTEGER;
  BEGIN
    IF TG_TABLE_SCHEMA <> 'allauth_project_' || replace(project_id,'-','') THEN
      RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='The project authentication writer binding is invalid.';
    END IF;
    PERFORM pg_advisory_xact_lock_shared(public.allauth_project_engine_writer_key(project_id));
    -- A stale transaction snapshot cannot treat an invisible mode row as legacy.
    SELECT f.writer,f.revision INTO current_writer,current_revision
      FROM public."allauthProjectEngineWriter" f WHERE f."projectId"=project_id FOR SHARE;
    IF NOT FOUND OR (
      (tagged_writer IS NOT NULL OR tagged_project IS NOT NULL OR tagged_revision IS NOT NULL)
      AND (tagged_writer IS DISTINCT FROM current_writer OR tagged_project IS DISTINCT FROM project_id
           OR tagged_revision IS DISTINCT FROM current_revision::text)
    ) OR (tagged_writer IS NULL AND current_writer <> 'legacy') THEN
      RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='The project authentication writer is not authoritative.';
    END IF;
    RETURN NULL;
  END;
  $guard$;

  CREATE FUNCTION public.allauth_switch_project_engine_writer(
    project_id TEXT, expected_writer TEXT, expected_revision INTEGER, next_writer TEXT
  ) RETURNS TABLE(writer TEXT, revision INTEGER) LANGUAGE plpgsql SET search_path=pg_catalog AS $switch$
  DECLARE
    realm_schema TEXT;
    auth_table TEXT;
    current_writer TEXT;
    current_revision INTEGER;
  BEGIN
    IF project_id IS NULL OR project_id !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
       OR expected_writer IS NULL OR expected_writer NOT IN ('legacy','allauth')
       OR expected_revision IS NULL OR expected_revision < 0
       OR (expected_revision=0 AND expected_writer <> 'legacy')
       OR next_writer IS NULL OR next_writer NOT IN ('legacy','allauth') THEN
      RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='Invalid project authentication writer switch.';
    END IF;

    -- Drain outer operations before blocking their guarded database transactions.
    PERFORM pg_advisory_xact_lock(public.allauth_project_engine_admission_key(project_id));
    PERFORM pg_advisory_xact_lock(public.allauth_project_engine_writer_key(project_id));
    SELECT p."schemaName" INTO realm_schema FROM public."allauthProject" p
      JOIN public."allauthWorkspace" w ON w.id=p."workspaceId"
      WHERE p.id=project_id AND p."schemaName"='allauth_project_' || replace(p.id,'-','')
        AND p.environment='development' AND w.protected
        AND w.id='00000000-0000-4000-8000-000000000001' FOR SHARE OF p,w;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='AU001', MESSAGE='The project authentication writer binding is invalid.';
    END IF;

    SELECT f.writer,f.revision INTO current_writer,current_revision
      FROM public."allauthProjectEngineWriter" f WHERE f."projectId"=project_id;
    IF NOT FOUND THEN
      current_writer := 'legacy';
      current_revision := 0;
    END IF;
    IF current_writer <> expected_writer OR current_revision <> expected_revision THEN
      RAISE EXCEPTION USING ERRCODE='AU002', MESSAGE='The project authentication writer revision changed.';
    END IF;
    IF current_writer=next_writer THEN
      RETURN QUERY SELECT current_writer,current_revision;
      RETURN;
    END IF;

    IF current_revision=0 THEN
      FOREACH auth_table IN ARRAY ARRAY[
        'user','account','session','verification','twoFactor','passkey','walletAddress','apikey',
        'oauthClient','oauthResource','oauthClientResource','oauthConsent','oauthAccessToken','oauthRefreshToken',
        'oauthClientAssertion','deviceCode','jwks','ssoProvider','scimManagedConnection','scimManagedCredential',
        'scimConnectionBinding','scimProjectionGrant','scimSubject','scimUser','scimIdentityTombstone',
        'scimGroup','scimGroupMember','allauthDirectory','allauthDirectoryMembership',
        'organization','organizationRole','member','invitation','team','teamMember','allauthInvitationImport',
        'allauthSecurityPolicy','allauthSecurityRule','allauthSecurityCounter','allauthKnownDevice','rateLimit',
        'agentHost','agent','agentCapabilityGrant','approvalRequest'
      ] LOOP
        EXECUTE format(
          'CREATE TRIGGER allauth_project_engine_writer BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON %I.%I FOR EACH STATEMENT EXECUTE FUNCTION public.allauth_guard_project_engine_write(%L)',
          realm_schema,auth_table,project_id
        );
      END LOOP;
    END IF;

    RETURN QUERY INSERT INTO public."allauthProjectEngineWriter" AS f ("projectId",writer,revision)
      VALUES (project_id,next_writer,current_revision+1)
      ON CONFLICT ("projectId") DO UPDATE SET writer=EXCLUDED.writer,revision=EXCLUDED.revision,"updatedAt"=clock_timestamp()
      RETURNING f.writer,f.revision;
  END;
  $switch$;

  REVOKE EXECUTE ON FUNCTION public.allauth_switch_project_engine_writer(TEXT,TEXT,INTEGER,TEXT) FROM PUBLIC;
END;
$migration$;
