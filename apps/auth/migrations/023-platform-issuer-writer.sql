-- cspell:ignore plpgsql xact
-- The shared issuer has one writer. Project schemas replay this migration as a no-op.
DO $migration$
BEGIN
  IF current_schema() <> 'public' THEN RETURN; END IF;

  CREATE TABLE public."allauthPlatformIssuerWriter" (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    writer TEXT NOT NULL CHECK (writer IN ('legacy','allauth')),
    revision INTEGER NOT NULL CHECK (revision > 0 OR (revision=0 AND writer='legacy'))
  );
  INSERT INTO public."allauthPlatformIssuerWriter" VALUES (true,'legacy',0);
  REVOKE ALL ON public."allauthPlatformIssuerWriter" FROM PUBLIC;

  CREATE FUNCTION public.allauth_platform_issuer_admission_key()
  RETURNS BIGINT LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $key$
    SELECT hashtextextended('allauth:platform-issuer-admission:v1',0)
  $key$;

  CREATE FUNCTION public.allauth_platform_issuer_write_key()
  RETURNS BIGINT LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $key$
    SELECT hashtextextended('allauth:platform-issuer-write:v1',0)
  $key$;

  CREATE FUNCTION public.allauth_require_platform_issuer_writer()
  RETURNS VOID LANGUAGE plpgsql SET search_path=pg_catalog AS $require$
  DECLARE
    tagged_writer TEXT := nullif(current_setting('allauth.platform_issuer_writer',true),'');
    tagged_revision TEXT := nullif(current_setting('allauth.platform_issuer_writer_revision',true),'');
    current_writer TEXT;
    current_revision INTEGER;
  BEGIN
    PERFORM pg_advisory_xact_lock_shared(public.allauth_platform_issuer_write_key());
    SELECT p.writer,p.revision INTO current_writer,current_revision
      FROM public."allauthPlatformIssuerWriter" p WHERE p.singleton FOR SHARE;
    IF NOT FOUND OR (
      (tagged_writer IS NOT NULL OR tagged_revision IS NOT NULL)
      AND (tagged_writer IS DISTINCT FROM current_writer OR tagged_revision IS DISTINCT FROM current_revision::text)
    ) OR (tagged_writer IS NULL AND tagged_revision IS NULL AND current_revision <> 0) THEN
      RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='The shared issuer writer is not authoritative.';
    END IF;
  END;
  $require$;

  -- Both engines persist OAuth code verification as this typed JSON record. Root
  -- credentials and MFA also use this table with independent, often non-JSON values.
  CREATE FUNCTION public.allauth_is_platform_authorization_code(verification_value TEXT)
  RETURNS BOOLEAN LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $classify$
  BEGIN
    RETURN (verification_value::jsonb ->> 'type') IS NOT DISTINCT FROM 'authorization_code';
  EXCEPTION WHEN invalid_text_representation OR untranslatable_character OR numeric_value_out_of_range THEN
    RETURN false;
  END;
  $classify$;

  CREATE FUNCTION public.allauth_guard_platform_authorization_code()
  RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $guard$
  BEGIN
    IF (TG_OP <> 'DELETE' AND public.allauth_is_platform_authorization_code(NEW.value)) OR
       (TG_OP <> 'INSERT' AND OLD."expiresAt">statement_timestamp() AND
        public.allauth_is_platform_authorization_code(OLD.value)) THEN
      PERFORM public.allauth_require_platform_issuer_writer();
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
  END;
  $guard$;

  CREATE TRIGGER allauth_platform_authorization_code_writer
    BEFORE INSERT OR UPDATE OR DELETE ON public.verification
    FOR EACH ROW EXECUTE FUNCTION public.allauth_guard_platform_authorization_code();

  CREATE FUNCTION public.allauth_guard_platform_issuer_statement()
  RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $guard$
  BEGIN
    PERFORM public.allauth_require_platform_issuer_writer();
    RETURN NULL;
  END;
  $guard$;

  -- Native password, MFA, account and app management may still delete grants or
  -- clear session foreign keys. Only minting and rotation fields are fenced.
  CREATE TRIGGER allauth_platform_access_writer
    BEFORE INSERT ON public."oauthAccessToken"
    FOR EACH STATEMENT EXECUTE FUNCTION public.allauth_guard_platform_issuer_statement();
  CREATE TRIGGER allauth_platform_refresh_writer
    BEFORE INSERT OR UPDATE OF "rotatedAt","rotationReplayResponse","rotationReplayExpiresAt"
    ON public."oauthRefreshToken"
    FOR EACH STATEMENT EXECUTE FUNCTION public.allauth_guard_platform_issuer_statement();
  CREATE TRIGGER allauth_platform_consent_writer
    BEFORE INSERT OR UPDATE ON public."oauthConsent"
    FOR EACH STATEMENT EXECUTE FUNCTION public.allauth_guard_platform_issuer_statement();
  CREATE TRIGGER allauth_platform_assertion_writer
    BEFORE INSERT ON public."oauthClientAssertion"
    FOR EACH STATEMENT EXECUTE FUNCTION public.allauth_guard_platform_issuer_statement();
  CREATE TRIGGER allauth_platform_signing_writer
    BEFORE INSERT ON public.jwks
    FOR EACH STATEMENT EXECUTE FUNCTION public.allauth_guard_platform_issuer_statement();

  CREATE FUNCTION public.allauth_guard_platform_oauth_device()
  RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $guard$
  BEGIN
    IF (TG_OP <> 'DELETE' AND NEW."oauthClientId" IS NOT NULL) OR
       (TG_OP <> 'INSERT' AND OLD."oauthClientId" IS NOT NULL AND OLD."expiresAt">statement_timestamp()) THEN
      PERFORM public.allauth_require_platform_issuer_writer();
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
  END;
  $guard$;

  CREATE TRIGGER allauth_platform_oauth_device_writer
    BEFORE INSERT OR UPDATE OR DELETE ON public."deviceCode"
    FOR EACH ROW EXECUTE FUNCTION public.allauth_guard_platform_oauth_device();

  CREATE FUNCTION public.allauth_switch_platform_issuer_writer(expected_writer TEXT, expected_revision INTEGER, next_writer TEXT)
  RETURNS TABLE(writer TEXT, revision INTEGER) LANGUAGE plpgsql SET search_path=pg_catalog AS $switch$
  DECLARE
    current_writer TEXT;
    current_revision INTEGER;
  BEGIN
    IF expected_writer IS NULL OR expected_writer NOT IN ('legacy','allauth')
       OR expected_revision IS NULL OR expected_revision < 0
       OR (expected_revision=0 AND expected_writer <> 'legacy')
       OR next_writer IS NULL OR next_writer NOT IN ('legacy','allauth') THEN
      RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='Invalid shared issuer writer switch.';
    END IF;

    PERFORM pg_advisory_xact_lock(public.allauth_platform_issuer_admission_key());
    PERFORM pg_advisory_xact_lock(public.allauth_platform_issuer_write_key());
    SELECT p.writer,p.revision INTO current_writer,current_revision
      FROM public."allauthPlatformIssuerWriter" p WHERE p.singleton;
    IF NOT FOUND OR current_writer<>expected_writer OR current_revision<>expected_revision THEN
      RAISE EXCEPTION USING ERRCODE='AU002', MESSAGE='The shared issuer writer revision changed.';
    END IF;
    IF current_writer=next_writer THEN
      RETURN QUERY SELECT current_writer,current_revision;
      RETURN;
    END IF;
    RETURN QUERY UPDATE public."allauthPlatformIssuerWriter" p SET writer=next_writer,revision=current_revision+1
      WHERE p.singleton RETURNING p.writer,p.revision;
  END;
  $switch$;

  REVOKE EXECUTE ON FUNCTION public.allauth_switch_platform_issuer_writer(TEXT,INTEGER,TEXT) FROM PUBLIC;
END;
$migration$;
