-- Console workspaces are platform ownership records, separate from tenant organizations.
-- This migration is platform-only; native project schemas must not run it.
CREATE TABLE public."allauthWorkspace" (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 2 AND 100),
  slug TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z][a-z0-9-]{1,47}$'),
  protected BOOLEAN NOT NULL DEFAULT false,
  "createdBy" TEXT REFERENCES public."user"(id) ON DELETE SET NULL,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE public."allauthWorkspaceMember" (
  id TEXT PRIMARY KEY,
  "workspaceId" TEXT NOT NULL REFERENCES public."allauthWorkspace"(id) ON DELETE CASCADE,
  "userId" TEXT NOT NULL REFERENCES public."user"(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('owner','admin','member')),
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE ("workspaceId","userId")
);
CREATE INDEX "allauthWorkspaceMember_user" ON public."allauthWorkspaceMember" ("userId","workspaceId");
CREATE TABLE public."allauthWorkspaceInvitation" (
  id TEXT PRIMARY KEY,
  "workspaceId" TEXT NOT NULL REFERENCES public."allauthWorkspace"(id) ON DELETE CASCADE,
  email TEXT NOT NULL CHECK (email=lower(email) AND char_length(email)<=320),
  role TEXT NOT NULL CHECK (role IN ('owner','admin','member')),
  status TEXT NOT NULL CHECK (status IN ('pending','accepted','cancelled')) DEFAULT 'pending',
  "invitedBy" TEXT REFERENCES public."user"(id) ON DELETE SET NULL,
  "acceptedBy" TEXT REFERENCES public."user"(id) ON DELETE SET NULL,
  "expiresAt" TIMESTAMPTZ NOT NULL,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX "allauthWorkspaceInvitation_pending" ON public."allauthWorkspaceInvitation" ("workspaceId",email) WHERE status='pending';
CREATE INDEX "allauthWorkspaceInvitation_email" ON public."allauthWorkspaceInvitation" (email,status,"expiresAt");
-- Preserve legacy project ownership: only global platform administrators manage this workspace.
INSERT INTO public."allauthWorkspace" (id,name,slug,protected) VALUES ('00000000-0000-4000-8000-000000000001','AllAuth platform','allauth-platform',true);
ALTER TABLE public."allauthProject" ADD COLUMN "workspaceId" TEXT REFERENCES public."allauthWorkspace"(id) ON DELETE RESTRICT;
UPDATE public."allauthProject" SET "workspaceId"='00000000-0000-4000-8000-000000000001' WHERE "workspaceId" IS NULL;
ALTER TABLE public."allauthProject" ALTER COLUMN "workspaceId" SET NOT NULL;
CREATE INDEX "allauthProject_workspace" ON public."allauthProject" ("workspaceId","applicationId",environment);
-- The invariant is deferred so a workspace and its first owner can be created atomically.
CREATE FUNCTION public.allauth_workspace_owner_required() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE workspace_id text;
BEGIN
  workspace_id := COALESCE(NEW."workspaceId",OLD."workspaceId");
  -- Serialize deferred checks as well as API mutations, including native user CASCADE deletions.
  PERFORM 1 FROM public."allauthWorkspace" WHERE id=workspace_id FOR UPDATE;
  IF EXISTS (SELECT 1 FROM public."allauthWorkspace" WHERE id=workspace_id AND protected=false)
    AND NOT EXISTS (SELECT 1 FROM public."allauthWorkspaceMember" WHERE "workspaceId"=workspace_id AND role='owner') THEN
    RAISE EXCEPTION 'A workspace must retain an owner' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER allauth_workspace_owner_required AFTER INSERT OR UPDATE OR DELETE ON public."allauthWorkspaceMember" DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.allauth_workspace_owner_required();
