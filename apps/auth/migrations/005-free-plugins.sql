alter table "user" add column "username" text;

alter table "user" add column "displayUsername" text;

create table "deviceCode" ("id" text not null primary key, "deviceCode" text not null, "userCode" text not null, "userId" text, "expiresAt" timestamptz not null, "status" text not null, "lastPolledAt" timestamptz, "pollingInterval" integer, "clientId" text, "scope" text, "resources" jsonb, "oauthClientId" text);

create table "walletAddress" ("id" text not null primary key, "userId" text not null references "user" ("id") on delete cascade, "address" text not null, "chainId" integer not null, "isPrimary" boolean not null, "createdAt" timestamptz not null);

create table "agentHost" ("id" text not null primary key, "name" text, "userId" text references "user" ("id") on delete cascade, "defaultCapabilities" text, "publicKey" text, "kid" text, "jwksUrl" text, "enrollmentTokenHash" text, "enrollmentTokenExpiresAt" timestamptz, "status" text not null, "activatedAt" timestamptz, "expiresAt" timestamptz, "lastUsedAt" timestamptz, "createdAt" timestamptz not null, "updatedAt" timestamptz not null);

create table "agent" ("id" text not null primary key, "name" text not null, "userId" text references "user" ("id") on delete cascade, "hostId" text not null references "agentHost" ("id") on delete cascade, "status" text not null, "mode" text not null, "publicKey" text not null, "kid" text, "jwksUrl" text, "lastUsedAt" timestamptz, "activatedAt" timestamptz, "expiresAt" timestamptz, "metadata" text, "createdAt" timestamptz not null, "updatedAt" timestamptz not null);

create table "agentCapabilityGrant" ("id" text not null primary key, "agentId" text not null references "agent" ("id") on delete cascade, "capability" text not null, "deniedBy" text references "user" ("id") on delete cascade, "grantedBy" text references "user" ("id") on delete cascade, "expiresAt" timestamptz, "createdAt" timestamptz not null, "updatedAt" timestamptz not null, "status" text not null, "reason" text, "constraints" text);

create table "approvalRequest" ("id" text not null primary key, "method" text not null, "agentId" text references "agent" ("id") on delete cascade, "hostId" text references "agentHost" ("id") on delete cascade, "userId" text references "user" ("id") on delete cascade, "capabilities" text, "status" text not null, "userCodeHash" text, "loginHint" text, "bindingMessage" text, "clientNotificationToken" text, "clientNotificationEndpoint" text, "deliveryMode" text, "interval" integer not null, "lastPolledAt" timestamptz, "expiresAt" timestamptz not null, "createdAt" timestamptz not null, "updatedAt" timestamptz not null);

create unique index "user_username_uidx" on "user" ("username");

create index "walletAddress_userId_idx" on "walletAddress" ("userId");

create index "agentHost_userId_idx" on "agentHost" ("userId");

create index "agentHost_kid_idx" on "agentHost" ("kid");

create index "agentHost_enrollmentTokenHash_idx" on "agentHost" ("enrollmentTokenHash");

create index "agentHost_status_idx" on "agentHost" ("status");

create index "agent_userId_idx" on "agent" ("userId");

create index "agent_hostId_idx" on "agent" ("hostId");

create index "agent_status_idx" on "agent" ("status");

create index "agent_kid_idx" on "agent" ("kid");

create index "agentCapabilityGrant_agentId_idx" on "agentCapabilityGrant" ("agentId");

create index "agentCapabilityGrant_capability_idx" on "agentCapabilityGrant" ("capability");

create index "agentCapabilityGrant_grantedBy_idx" on "agentCapabilityGrant" ("grantedBy");

create index "agentCapabilityGrant_status_idx" on "agentCapabilityGrant" ("status");

create index "approvalRequest_agentId_idx" on "approvalRequest" ("agentId");

create index "approvalRequest_hostId_idx" on "approvalRequest" ("hostId");

create index "approvalRequest_userId_idx" on "approvalRequest" ("userId");

create index "approvalRequest_status_idx" on "approvalRequest" ("status");

create unique index "deviceCode_deviceCode_uidx" on "deviceCode" ("deviceCode");

create unique index "deviceCode_userCode_uidx" on "deviceCode" ("userCode");
-- The platform and project schemas share this additive migration. Anonymous
-- sessions are enabled only in project instances, so this nullable field is a
-- deliberate schema superset and preserves all existing platform accounts.
ALTER TABLE "user" ADD COLUMN "isAnonymous" boolean DEFAULT false;
