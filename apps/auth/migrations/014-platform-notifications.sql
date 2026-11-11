-- Platform account notifications. Public qualification prevents tenant copies.
CREATE TABLE IF NOT EXISTS public."allauthNotificationPreference" (
 "userId" TEXT PRIMARY KEY REFERENCES public."user"(id) ON DELETE CASCADE,
 "releaseEmails" BOOLEAN NOT NULL DEFAULT TRUE,
 "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS public."allauthNotificationRead" (
 "userId" TEXT NOT NULL REFERENCES public."user"(id) ON DELETE CASCADE,
 "notificationId" TEXT NOT NULL CHECK (char_length("notificationId") BETWEEN 1 AND 100),
 "readAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY ("userId","notificationId")
);
CREATE TABLE IF NOT EXISTS public."allauthSdkVersionObservation" (
 "projectId" TEXT PRIMARY KEY REFERENCES public."allauthProject"(id) ON DELETE CASCADE,
 version TEXT NOT NULL CHECK (char_length(version) BETWEEN 1 AND 64),
 "lastSeenAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS public."allauthNotificationEmail" (
 id TEXT PRIMARY KEY,
 "userId" TEXT NOT NULL REFERENCES public."user"(id) ON DELETE CASCADE,
 "releaseId" TEXT NOT NULL CHECK (char_length("releaseId") BETWEEN 1 AND 100),
 status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','processing','accepted','cancelled','failed')),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 6),
 "nextAttemptAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 "leaseId" TEXT, "lockedUntil" TIMESTAMPTZ,
 "acceptedAt" TIMESTAMPTZ, "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE ("userId","releaseId")
);
CREATE INDEX IF NOT EXISTS "allauthNotificationEmail_ready" ON public."allauthNotificationEmail" ("nextAttemptAt",id) WHERE status IN ('pending','processing');
