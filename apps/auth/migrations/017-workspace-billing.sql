-- Hosted billing belongs to a console workspace, never a tenant organization.
-- Keep the workspace identifier after deletion for delayed Stripe events and reconciliation.
CREATE TABLE public."allauthWorkspaceBilling" (
  "workspaceId" TEXT PRIMARY KEY,
  "stripeAccountId" TEXT NOT NULL,
  "stripeLivemode" BOOLEAN NOT NULL,
  "stripeCustomerId" TEXT UNIQUE,
  "stripeSubscriptionId" TEXT UNIQUE,
  "stripePriceId" TEXT,
  "stripeStatus" TEXT NOT NULL DEFAULT 'free',
  "paidThrough" TIMESTAMPTZ,
  "firstPaymentFailureAt" TIMESTAMPTZ,
  "cancelAtPeriodEnd" BOOLEAN NOT NULL DEFAULT false,
  "reconciledAt" TIMESTAMPTZ,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX "allauthWorkspaceBilling_reconcile" ON public."allauthWorkspaceBilling" ("reconciledAt") WHERE "stripeCustomerId" IS NOT NULL;
CREATE TABLE public."allauthBillingCheckout" (
  "workspaceId" TEXT PRIMARY KEY,
  "attemptId" TEXT NOT NULL UNIQUE,
  "sessionId" TEXT UNIQUE,
  url TEXT,
  "expiresAt" TIMESTAMPTZ NOT NULL,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE public."allauthBillingWebhook" (
  id TEXT NOT NULL,
  "stripeAccountId" TEXT NOT NULL,
  "stripeLivemode" BOOLEAN NOT NULL,
  type TEXT NOT NULL,
  "customerId" TEXT,
  "objectId" TEXT NOT NULL,
  "occurredAt" TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','processing','processed','ignored')),
  attempts INTEGER NOT NULL DEFAULT 0,
  "leaseId" TEXT,
  "lockedUntil" TIMESTAMPTZ,
  "nextAttemptAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "processedAt" TIMESTAMPTZ,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY("stripeAccountId","stripeLivemode",id)
);
CREATE INDEX "allauthBillingWebhook_pending" ON public."allauthBillingWebhook" ("nextAttemptAt",id) WHERE status IN ('pending','processing');
