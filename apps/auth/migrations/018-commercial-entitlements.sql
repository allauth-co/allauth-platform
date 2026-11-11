-- Hosted commercial policy is platform state; tenant authentication data stays realm-local.
CREATE TABLE public."allauthCommercialConfiguration" (
  singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton=true),
  "deploymentMode" TEXT NOT NULL DEFAULT 'hosted' CHECK ("deploymentMode" IN ('hosted','self-hosted')),
  "enforcementEnabled" BOOLEAN NOT NULL DEFAULT false,
  "enforcementStartedAt" TIMESTAMPTZ,
  "stripeAccountId" TEXT,
  "stripeLivemode" BOOLEAN,
  "stripePriceId" TEXT,
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO public."allauthCommercialConfiguration"(singleton) VALUES(true);

CREATE TABLE public."allauthImpersonationUsage" (
  "workspaceId" TEXT NOT NULL REFERENCES public."allauthWorkspace"(id) ON DELETE CASCADE,
  "monthStart" DATE NOT NULL CHECK (extract(day FROM "monthStart")=1),
  starts BIGINT NOT NULL DEFAULT 0 CHECK (starts>=0),
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY("workspaceId","monthStart")
);

CREATE FUNCTION public.allauth_sync_commercial_configuration(deployment_mode TEXT, enabled BOOLEAN, account_id TEXT, live_mode BOOLEAN, price_id TEXT) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF deployment_mode NOT IN ('hosted','self-hosted') THEN RAISE EXCEPTION 'Invalid AllAuth deployment mode'; END IF;
  UPDATE public."allauthCommercialConfiguration" SET
    "deploymentMode"=deployment_mode,
    "enforcementEnabled"=enabled AND deployment_mode='hosted',
    "enforcementStartedAt"=CASE WHEN enabled AND deployment_mode='hosted' THEN COALESCE("enforcementStartedAt",clock_timestamp()) ELSE "enforcementStartedAt" END,
    "stripeAccountId"=NULLIF(account_id,''),"stripeLivemode"=live_mode,"stripePriceId"=NULLIF(price_id,''),"updatedAt"=clock_timestamp()
  WHERE singleton=true;
END;
$$;

CREATE FUNCTION public.allauth_workspace_has_pro(workspace_id TEXT, at_time TIMESTAMPTZ) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
  SELECT EXISTS(SELECT 1 FROM public."allauthWorkspaceBilling" b CROSS JOIN public."allauthCommercialConfiguration" c
    WHERE b."workspaceId"=workspace_id AND c.singleton=true
      AND b."stripeAccountId"=c."stripeAccountId" AND b."stripeLivemode"=c."stripeLivemode" AND b."stripePriceId"=c."stripePriceId"
      AND b."paidThrough" IS NOT NULL
      AND (b."paidThrough">at_time OR (b."firstPaymentFailureAt"<=at_time AND b."firstPaymentFailureAt"+INTERVAL '7 days'>at_time)));
$$;

CREATE FUNCTION public.allauth_guard_organization_members() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE workspace_id TEXT; exempt BOOLEAN; total BIGINT;
BEGIN
  IF NOT EXISTS(SELECT 1 FROM public."allauthCommercialConfiguration" WHERE singleton=true AND "deploymentMode"='hosted' AND "enforcementEnabled"=true) THEN RETURN NEW; END IF;
  IF TG_OP='UPDATE' AND NEW."organizationId" IS NOT DISTINCT FROM OLD."organizationId" THEN RETURN NEW; END IF;
  SELECT p."workspaceId",w.protected INTO workspace_id,exempt FROM public."allauthProject" p JOIN public."allauthWorkspace" w ON w.id=p."workspaceId" WHERE p."schemaName"=TG_TABLE_SCHEMA;
  IF workspace_id IS NULL THEN RAISE EXCEPTION 'Native realm ownership is unavailable'; END IF;
  IF exempt OR public.allauth_workspace_has_pro(workspace_id,clock_timestamp()) THEN RETURN NEW; END IF;
  -- Serialize additions across SDK, invitations, direct console writes, SSO and SCIM.
  PERFORM pg_advisory_xact_lock(hashtextextended(TG_TABLE_SCHEMA||':allauth-members:'||NEW."organizationId",0));
  EXECUTE format('SELECT count(*) FROM %I.member WHERE "organizationId"=$1',TG_TABLE_SCHEMA) INTO total USING NEW."organizationId";
  IF total>20 THEN RAISE EXCEPTION 'Free organisations include up to 20 members' USING ERRCODE='PAA01'; END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.allauth_record_impersonation_start() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE workspace_id TEXT; exempt BOOLEAN; month_start DATE; used BIGINT;
BEGIN
  IF NEW."impersonatedBy" IS NULL THEN RETURN NEW; END IF;
  -- Normal-to-support transitions are also starts; ordinary updates and existing support markers are not.
  IF TG_OP='UPDATE' AND OLD."impersonatedBy" IS NOT NULL THEN RETURN NEW; END IF;
  IF NOT EXISTS(SELECT 1 FROM public."allauthCommercialConfiguration" WHERE singleton=true AND "deploymentMode"='hosted' AND "enforcementEnabled"=true) THEN RETURN NEW; END IF;
  SELECT p."workspaceId",w.protected INTO workspace_id,exempt FROM public."allauthProject" p JOIN public."allauthWorkspace" w ON w.id=p."workspaceId" WHERE p."schemaName"=TG_TABLE_SCHEMA;
  IF workspace_id IS NULL THEN RAISE EXCEPTION 'Native realm ownership is unavailable'; END IF;
  IF exempt THEN RETURN NEW; END IF;
  month_start=date_trunc('month',clock_timestamp() AT TIME ZONE 'UTC')::date;
  INSERT INTO public."allauthImpersonationUsage"("workspaceId","monthStart") VALUES(workspace_id,month_start) ON CONFLICT DO NOTHING;
  SELECT starts INTO used FROM public."allauthImpersonationUsage" WHERE "workspaceId"=workspace_id AND "monthStart"=month_start FOR UPDATE;
  IF used>=5 AND NOT public.allauth_workspace_has_pro(workspace_id,clock_timestamp()) THEN RAISE EXCEPTION 'Free monthly impersonation limit reached' USING ERRCODE='PAA02'; END IF;
  UPDATE public."allauthImpersonationUsage" SET starts=starts+1,"updatedAt"=clock_timestamp() WHERE "workspaceId"=workspace_id AND "monthStart"=month_start;
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.allauth_install_commercial_guards(schema_name TEXT) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF schema_name !~ '^allauth_project_[a-f0-9]{32}$' OR NOT EXISTS(SELECT 1 FROM public."allauthProject" WHERE "schemaName"=schema_name) THEN RAISE EXCEPTION 'Invalid native realm'; END IF;
  EXECUTE format('DROP TRIGGER IF EXISTS allauth_commercial_member_guard ON %I.member',schema_name);
  EXECUTE format('CREATE TRIGGER allauth_commercial_member_guard AFTER INSERT OR UPDATE OF "organizationId" ON %I.member FOR EACH ROW EXECUTE FUNCTION public.allauth_guard_organization_members()',schema_name);
  EXECUTE format('DROP TRIGGER IF EXISTS allauth_commercial_impersonation_guard ON %I.session',schema_name);
  EXECUTE format('CREATE TRIGGER allauth_commercial_impersonation_guard AFTER INSERT OR UPDATE OF "impersonatedBy" ON %I.session FOR EACH ROW EXECUTE FUNCTION public.allauth_record_impersonation_start()',schema_name);
END;
$$;

-- Existing sessions and memberships are deliberately untouched. Guards start disabled.
DO $$ DECLARE realm RECORD;
BEGIN
  FOR realm IN SELECT "schemaName" FROM public."allauthProject" LOOP
    PERFORM public.allauth_install_commercial_guards(realm."schemaName");
  END LOOP;
END;
$$;
