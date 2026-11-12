-- cspell:words plpgsql xact
-- Pin an ordinary development realm without changing its authentication writer.
DO $migration$
BEGIN
  IF current_schema() <> 'public' THEN RETURN; END IF;

  CREATE TABLE public."allauthProjectEngineDevelopment" (
    "projectId" TEXT PRIMARY KEY REFERENCES public."allauthProject"(id) ON DELETE CASCADE
      CHECK ("projectId" ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'),
    "workspaceId" TEXT NOT NULL REFERENCES public."allauthWorkspace"(id) ON DELETE RESTRICT
      CHECK ("workspaceId" ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
        AND "workspaceId" <> '00000000-0000-4000-8000-000000000001'),
    "schemaName" TEXT NOT NULL CHECK ("schemaName" = 'allauth_project_' || replace("projectId",'-','')),
    "registeredAt" TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
  );
  REVOKE ALL ON public."allauthProjectEngineDevelopment" FROM PUBLIC;

  CREATE OR REPLACE FUNCTION public.allauth_guard_project_engine_registry_binding()
  RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $guard$
  BEGIN
    IF TG_OP='UPDATE' AND OLD."projectEngineFenced" AND (
      NOT NEW."projectEngineFenced" OR NEW.id IS DISTINCT FROM OLD.id
      OR NEW."workspaceId" IS DISTINCT FROM OLD."workspaceId"
      OR NEW."schemaName" IS DISTINCT FROM OLD."schemaName"
      OR NEW.environment IS DISTINCT FROM OLD.environment
    ) THEN
      RAISE EXCEPTION USING ERRCODE='AU001', MESSAGE='The registered project authentication writer binding cannot change.';
    END IF;
    IF NEW."projectEngineFenced" AND NOT (CASE NEW.environment
      WHEN 'production' THEN EXISTS (
        SELECT 1 FROM public."allauthProjectEngineProduction" e
        WHERE e."projectId"=NEW.id AND e."workspaceId"=NEW."workspaceId" AND e."schemaName"=NEW."schemaName"
      )
      WHEN 'development' THEN EXISTS (
        SELECT 1 FROM public."allauthProjectEngineDevelopment" e
        JOIN public."allauthWorkspace" w ON w.id=e."workspaceId"
        WHERE e."projectId"=NEW.id AND e."workspaceId"=NEW."workspaceId" AND e."schemaName"=NEW."schemaName"
          AND NOT w.protected
      )
      ELSE FALSE
    END) THEN
      RAISE EXCEPTION USING ERRCODE='AU001', MESSAGE='The project authentication writer registration is missing.';
    END IF;
    RETURN NEW;
  END;
  $guard$;

  CREATE FUNCTION public.allauth_register_project_engine_development(project_id TEXT, workspace_id TEXT)
  RETURNS VOID LANGUAGE plpgsql SET search_path=pg_catalog AS $register$
  DECLARE
    realm_schema TEXT;
    fenced BOOLEAN;
  BEGIN
    IF project_id IS NULL OR project_id !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
       OR workspace_id IS NULL OR workspace_id !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' THEN
      RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='Invalid development project authentication writer registration.';
    END IF;

    PERFORM pg_advisory_xact_lock(public.allauth_project_engine_admission_key(project_id));
    PERFORM pg_advisory_xact_lock(public.allauth_project_engine_writer_key(project_id));
    SELECT p."schemaName", p."projectEngineFenced" INTO realm_schema, fenced
      FROM public."allauthProject" p JOIN public."allauthWorkspace" w ON w.id=p."workspaceId"
      WHERE p.id=project_id AND p."workspaceId"=workspace_id AND p.environment='development'
        AND NOT w.protected AND w.id<>'00000000-0000-4000-8000-000000000001'
        AND p."schemaName"='allauth_project_' || replace(project_id,'-','')
      FOR NO KEY UPDATE OF p FOR SHARE OF w;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='AU001', MESSAGE='The development project authentication writer binding is invalid.';
    END IF;
    IF NOT fenced AND EXISTS (
      SELECT 1 FROM public."allauthProjectEngineWriter" f WHERE f."projectId"=project_id
    ) THEN
      RAISE EXCEPTION USING ERRCODE='AU001', MESSAGE='The unregistered development project already has a writer revision.';
    END IF;

    INSERT INTO public."allauthProjectEngineDevelopment" ("projectId","workspaceId","schemaName")
      VALUES (project_id,workspace_id,realm_schema) ON CONFLICT ("projectId") DO NOTHING;
    IF NOT EXISTS (
      SELECT 1 FROM public."allauthProjectEngineDevelopment" e
      WHERE e."projectId"=project_id AND e."workspaceId"=workspace_id AND e."schemaName"=realm_schema
    ) THEN
      RAISE EXCEPTION USING ERRCODE='AU001', MESSAGE='The registered project authentication writer binding cannot change.';
    END IF;
    UPDATE public."allauthProject" p SET "projectEngineFenced"=TRUE
      WHERE p.id=project_id AND NOT p."projectEngineFenced";
  END;
  $register$;

  CREATE FUNCTION public.allauth_project_engine_development_allowed(project_id TEXT, workspace_id TEXT, realm_schema TEXT)
  RETURNS BOOLEAN LANGUAGE sql STABLE SET search_path=pg_catalog AS $allowed$
    SELECT EXISTS (
      SELECT 1 FROM public."allauthProjectEngineDevelopment" e
      JOIN public."allauthProject" p ON p.id=e."projectId"
      JOIN public."allauthWorkspace" w ON w.id=e."workspaceId"
      WHERE e."projectId"=project_id AND e."workspaceId"=workspace_id AND e."schemaName"=realm_schema
        AND p."workspaceId"=workspace_id AND p."schemaName"=realm_schema
        AND p.environment='development' AND p."projectEngineFenced" AND NOT w.protected
    )
  $allowed$;

  CREATE OR REPLACE FUNCTION public.allauth_project_engine_binding_allowed(project_id TEXT, realm_schema TEXT)
  RETURNS BOOLEAN LANGUAGE sql STABLE SET search_path=pg_catalog AS $allowed$
    SELECT EXISTS (
      SELECT 1 FROM public."allauthProject" p
      JOIN public."allauthWorkspace" w ON w.id=p."workspaceId"
      WHERE p.id=project_id AND p.id ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
        AND p."schemaName"=realm_schema AND realm_schema='allauth_project_' || replace(project_id,'-','')
        AND CASE
          WHEN p."projectEngineFenced" AND p.environment='development'
            THEN public.allauth_project_engine_development_allowed(p.id,p."workspaceId",realm_schema)
          WHEN p."projectEngineFenced"
            THEN public.allauth_project_engine_production_allowed(p.id,p."workspaceId",realm_schema)
          ELSE p.environment='development' AND w.protected AND w.id='00000000-0000-4000-8000-000000000001'
        END
    )
  $allowed$;

  REVOKE EXECUTE ON FUNCTION public.allauth_register_project_engine_development(TEXT,TEXT) FROM PUBLIC;
END;
$migration$;
