-- The delivery worker reads endpoints and writes the outbox independently of the project writer.
DO $migration$
DECLARE
  existing RECORD;
BEGIN
  IF current_schema() <> 'public' THEN RETURN; END IF;

  CREATE FUNCTION public.allauth_install_project_webhook_writer_guard(project_id TEXT)
  RETURNS VOID LANGUAGE plpgsql SET search_path=pg_catalog AS $install$
  DECLARE
    realm_schema TEXT;
  BEGIN
    SELECT p."schemaName" INTO realm_schema FROM public."allauthProject" p
      JOIN public."allauthWorkspace" w ON w.id=p."workspaceId"
      WHERE p.id=project_id AND p.id ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
        AND p."schemaName"='allauth_project_' || replace(p.id,'-','')
        AND p.environment='development' AND w.protected
        AND w.id='00000000-0000-4000-8000-000000000001';
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE='AU001', MESSAGE='The project authentication writer binding is invalid.';
    END IF;
    EXECUTE format(
      'CREATE TRIGGER allauth_project_engine_writer BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON %I."allauthWebhookEndpoint" FOR EACH STATEMENT EXECUTE FUNCTION public.allauth_guard_project_engine_write(%L)',
      realm_schema, project_id
    );
  END;
  $install$;

  CREATE FUNCTION public.allauth_guard_new_project_webhook_writer()
  RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $install$
  BEGIN
    PERFORM public.allauth_install_project_webhook_writer_guard(NEW."projectId");
    RETURN NULL;
  END;
  $install$;

  REVOKE EXECUTE ON FUNCTION public.allauth_install_project_webhook_writer_guard(TEXT) FROM PUBLIC;
  REVOKE EXECUTE ON FUNCTION public.allauth_guard_new_project_webhook_writer() FROM PUBLIC;

  -- Installing the trigger serializes writer-table changes until backfill commits.
  CREATE TRIGGER allauth_project_webhook_writer_guard AFTER INSERT
    ON public."allauthProjectEngineWriter" FOR EACH ROW
    EXECUTE FUNCTION public.allauth_guard_new_project_webhook_writer();

  FOR existing IN SELECT "projectId" FROM public."allauthProjectEngineWriter" ORDER BY "projectId"
  LOOP
    PERFORM public.allauth_install_project_webhook_writer_guard(existing."projectId");
  END LOOP;
END;
$migration$;
