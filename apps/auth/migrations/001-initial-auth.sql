create table "user" ("id" text not null primary key, "name" text not null, "email" text not null unique, "emailVerified" boolean not null, "image" text, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz default CURRENT_TIMESTAMP not null, "role" text, "banned" boolean, "banReason" text, "banExpires" timestamptz, "twoFactorEnabled" boolean, "publicMetadata" jsonb, "privateMetadata" jsonb, "directoryManaged" boolean, "directoryDisabled" boolean);

create table "session" ("id" text not null primary key, "expiresAt" timestamptz not null, "token" text not null unique, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz not null, "ipAddress" text, "userAgent" text, "userId" text not null references "user" ("id") on delete cascade, "activeOrganizationId" text, "activeTeamId" text, "impersonatedBy" text);

create table "account" ("id" text not null primary key, "accountId" text not null, "providerId" text not null, "userId" text not null references "user" ("id") on delete cascade, "accessToken" text, "refreshToken" text, "idToken" text, "accessTokenExpiresAt" timestamptz, "refreshTokenExpiresAt" timestamptz, "scope" text, "password" text, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz not null);

create table "verification" ("id" text not null primary key, "identifier" text not null, "value" text not null, "expiresAt" timestamptz not null, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz default CURRENT_TIMESTAMP not null);

create table "organization" ("id" text not null primary key, "name" text not null, "slug" text not null unique, "logo" text, "createdAt" timestamptz not null, "metadata" text);

create table "organizationRole" ("id" text not null primary key, "organizationId" text not null references "organization" ("id") on delete cascade, "role" text not null, "permission" text not null, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz);

create table "team" ("id" text not null primary key, "name" text not null, "memberCount" integer not null, "organizationId" text not null references "organization" ("id") on delete cascade, "createdAt" timestamptz not null, "updatedAt" timestamptz);

create table "teamMember" ("id" text not null primary key, "teamId" text not null references "team" ("id") on delete cascade, "userId" text not null references "user" ("id") on delete cascade, "membershipKey" text unique, "createdAt" timestamptz);

create table "member" ("id" text not null primary key, "organizationId" text not null references "organization" ("id") on delete cascade, "userId" text not null references "user" ("id") on delete cascade, "role" text not null, "createdAt" timestamptz not null);

create table "invitation" ("id" text not null primary key, "organizationId" text not null references "organization" ("id") on delete cascade, "email" text not null, "role" text, "teamId" text, "status" text not null, "expiresAt" timestamptz not null, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "inviterId" text not null references "user" ("id") on delete cascade);

create table "twoFactor" ("id" text not null primary key, "secret" text not null, "backupCodes" text not null, "userId" text not null references "user" ("id") on delete cascade, "verified" boolean, "failedVerificationCount" integer, "lockedUntil" timestamptz);

create table "passkey" ("id" text not null primary key, "name" text, "publicKey" text not null, "userId" text not null references "user" ("id") on delete cascade, "credentialID" text not null, "counter" integer not null, "deviceType" text not null, "backedUp" boolean not null, "transports" text, "createdAt" timestamptz, "aaguid" text);

create table "ssoProvider" ("id" text not null primary key, "issuer" text not null, "oidcConfig" text, "samlConfig" text, "userId" text not null references "user" ("id") on delete cascade, "providerId" text not null unique, "organizationId" text, "domain" text not null, "domainVerified" boolean);

create table "scimManagedConnection" ("id" text not null primary key, "creationRequestId" text not null unique, "connectionId" text not null unique, "provisioningDomainId" text not null, "status" text not null, "revision" integer not null, "createdAt" timestamptz not null, "createdBy" text not null, "decommissionStartedAt" timestamptz, "decommissionStartedBy" text, "decommissionedAt" timestamptz, "decommissionedBy" text);

create table "scimManagedCredential" ("id" text not null primary key, "connectionRecordId" text not null references "scimManagedConnection" ("id") on delete cascade, "credentialId" text not null unique, "tokenDigest" text not null, "hashVersion" text not null, "activeSlotKey" text not null unique, "status" text not null, "serializedScopes" text not null, "expiresAt" timestamptz not null, "createdAt" timestamptz not null, "createdBy" text not null, "lastUsedAt" timestamptz, "revokedAt" timestamptz, "revokedBy" text, "decommissionedAt" timestamptz);

create table "scimManagedConnectionEvent" ("id" text not null primary key, "connectionRecordId" text not null references "scimManagedConnection" ("id") on delete cascade, "eventKey" text not null unique, "sequence" integer not null, "type" text not null, "actorId" text not null, "credentialId" text, "createdAt" timestamptz not null);

create table "scimConnectionBinding" ("id" text not null primary key, "connectionId" text not null, "connectionKey" text not null unique, "provisioningDomainId" text not null, "createdAt" timestamptz not null, "decommissionedAt" timestamptz, "decommissionStatus" text not null, "decommissionCursorUserId" text, "decommissionReconciledUserCount" integer not null, "decommissionBatchCount" integer not null, "decommissionRevision" integer not null, "decommissionCompletedAt" timestamptz, "decommissionLeaseId" text, "decommissionLeaseExpiresAt" timestamptz);

create table "scimIdentityTombstone" ("id" text not null primary key, "connectionId" text not null, "provisioningDomainId" text not null, "externalId" text not null, "externalIdKey" text not null unique, "userId" text not null references "user" ("id") on delete cascade, "profile" text not null, "deletedAt" timestamptz not null);

create table "scimSubject" ("id" text not null primary key, "userId" text not null unique references "user" ("id") on delete cascade, "profileSourceId" text, "revision" integer not null, "createdAt" timestamptz not null, "updatedAt" timestamptz not null);

create table "scimUser" ("id" text not null primary key, "connectionId" text not null, "provisioningDomainId" text not null, "userId" text not null references "user" ("id") on delete cascade, "connectionUserKey" text not null unique, "userName" text not null, "userNameKey" text not null unique, "primaryEmail" text not null, "workEmailValueIndex" text not null, "emailValueIndex" text not null, "displayName" text not null, "formattedName" text not null, "givenName" text, "familyName" text, "serializedEmails" text not null, "serializedAttributes" text, "externalId" text, "externalIdKey" text unique, "active" boolean not null, "orderKey" text not null unique, "createdAt" timestamptz not null, "updatedAt" timestamptz not null);

create table "scimProjectionGrant" ("id" text not null primary key, "connectionId" text not null, "provisioningDomainId" text not null, "scimUserId" text not null references "scimUser" ("id") on delete cascade, "userId" text not null references "user" ("id") on delete cascade, "sourceKind" text not null, "sourceId" text not null, "sourceValue" text, "role" text not null, "grantKey" text not null unique, "createdAt" timestamptz not null, "updatedAt" timestamptz not null);

create table "scimGroup" ("id" text not null primary key, "connectionId" text not null, "provisioningDomainId" text not null, "revision" integer not null, "displayName" text not null, "displayNameKey" text not null unique, "externalId" text, "externalIdKey" text unique, "orderKey" text not null unique, "createdAt" timestamptz not null, "updatedAt" timestamptz not null);

create table "scimGroupMember" ("id" text not null primary key, "connectionId" text not null, "groupId" text not null references "scimGroup" ("id") on delete cascade, "scimUserId" text not null references "scimUser" ("id") on delete cascade, "membershipKey" text not null unique, "createdAt" timestamptz not null);

create table "apikey" ("id" text not null primary key, "configId" text not null, "name" text, "start" text, "referenceId" text not null, "prefix" text, "key" text not null, "refillInterval" integer, "refillAmount" integer, "lastRefillAt" timestamptz, "enabled" boolean, "rateLimitEnabled" boolean, "rateLimitTimeWindow" integer, "rateLimitMax" integer, "requestCount" integer, "remaining" integer, "lastRequest" timestamptz, "expiresAt" timestamptz, "createdAt" timestamptz not null, "updatedAt" timestamptz not null, "permissions" text, "metadata" text);

create table "jwks" ("id" text not null primary key, "publicKey" text not null, "privateKey" text not null, "createdAt" timestamptz not null, "expiresAt" timestamptz, "alg" text, "crv" text);

create table "oauthClient" ("id" text not null primary key, "clientId" text not null unique, "clientSecret" text, "clientDiscoveryId" text, "disabled" boolean, "skipConsent" boolean, "enableEndSession" boolean, "subjectType" text, "scopes" jsonb, "clientCredentialsScopes" jsonb, "userId" text references "user" ("id") on delete cascade, "createdAt" timestamptz, "updatedAt" timestamptz, "name" text, "uri" text, "icon" text, "contacts" jsonb, "tos" text, "policy" text, "softwareId" text, "softwareVersion" text, "softwareStatement" text, "redirectUris" jsonb not null, "postLogoutRedirectUris" jsonb, "backchannelLogoutUri" text, "backchannelLogoutSessionRequired" boolean, "tokenEndpointAuthMethod" text, "applicationType" text, "jwks" text, "jwksUri" text, "grantTypes" jsonb, "responseTypes" jsonb, "requirePKCE" boolean, "dpopBoundAccessTokens" boolean, "referenceId" text, "metadata" jsonb);

create table "oauthResource" ("id" text not null primary key, "identifier" text not null unique, "name" text not null, "accessTokenTtl" integer, "refreshTokenTtl" integer, "signingAlgorithm" text, "signingKeyId" text, "allowedScopes" jsonb, "customClaims" jsonb, "dpopBoundAccessTokensRequired" boolean, "disabled" boolean, "createdAt" timestamptz, "updatedAt" timestamptz, "policyVersion" integer, "metadata" jsonb);

create table "oauthClientResource" ("id" text not null primary key, "clientId" text not null references "oauthClient" ("clientId") on delete cascade, "resourceId" text not null references "oauthResource" ("identifier") on delete cascade, "metadata" jsonb, "createdAt" timestamptz);

create table "oauthRefreshToken" ("id" text not null primary key, "token" text not null unique, "clientId" text not null references "oauthClient" ("clientId") on delete cascade, "sessionId" text references "session" ("id") on delete set null, "userId" text not null references "user" ("id") on delete cascade, "referenceId" text, "authorizationCodeId" text, "resources" jsonb, "requestedUserInfoClaims" jsonb, "expiresAt" timestamptz not null, "createdAt" timestamptz not null, "revoked" timestamptz, "rotatedAt" timestamptz, "rotationReplayResponse" text, "rotationReplayExpiresAt" timestamptz, "authTime" timestamptz, "confirmation" jsonb, "scopes" jsonb not null);

create table "oauthAccessToken" ("id" text not null primary key, "token" text not null unique, "clientId" text not null references "oauthClient" ("clientId") on delete cascade, "sessionId" text references "session" ("id") on delete set null, "userId" text references "user" ("id") on delete cascade, "referenceId" text, "authorizationCodeId" text, "resources" jsonb, "requestedUserInfoClaims" jsonb, "refreshId" text references "oauthRefreshToken" ("id") on delete cascade, "expiresAt" timestamptz not null, "createdAt" timestamptz not null, "revoked" timestamptz, "confirmation" jsonb, "scopes" jsonb not null);

create table "oauthConsent" ("id" text not null primary key, "clientId" text not null references "oauthClient" ("clientId") on delete cascade, "userId" text references "user" ("id") on delete cascade, "referenceId" text, "resources" jsonb, "requestedUserInfoClaims" jsonb, "scopes" jsonb not null, "createdAt" timestamptz not null, "updatedAt" timestamptz not null);

create table "oauthClientAssertion" ("id" text not null primary key, "expiresAt" timestamptz not null);

create table "allauthAudit" ("id" text not null primary key, "actorId" text not null, "action" text not null, "targetId" text, "organizationId" text, "createdAt" timestamptz not null);

create table "allauthDirectory" ("id" text not null primary key, "providerId" text not null unique, "organizationId" text not null references "organization" ("id") on delete cascade, "connectionId" text not null unique, "createdAt" timestamptz not null);

create table "allauthDirectoryMembership" ("id" text not null primary key, "organizationId" text not null references "organization" ("id") on delete cascade, "userId" text not null references "user" ("id") on delete cascade, "memberId" text not null unique, "createdAt" timestamptz not null);

create table "rateLimit" ("id" text not null primary key, "key" text not null unique, "count" integer not null, "lastRequest" bigint not null);

create index "session_userId_idx" on "session" ("userId");

create index "account_userId_idx" on "account" ("userId");

create index "verification_identifier_idx" on "verification" ("identifier");

create index "organizationRole_organizationId_idx" on "organizationRole" ("organizationId");

create index "organizationRole_role_idx" on "organizationRole" ("role");

create index "team_organizationId_idx" on "team" ("organizationId");

create index "teamMember_teamId_idx" on "teamMember" ("teamId");

create index "teamMember_userId_idx" on "teamMember" ("userId");

create index "member_organizationId_idx" on "member" ("organizationId");

create index "member_userId_idx" on "member" ("userId");

create index "invitation_organizationId_idx" on "invitation" ("organizationId");

create index "invitation_email_idx" on "invitation" ("email");

create index "twoFactor_secret_idx" on "twoFactor" ("secret");

create index "twoFactor_userId_idx" on "twoFactor" ("userId");

create index "passkey_userId_idx" on "passkey" ("userId");

create index "passkey_credentialID_idx" on "passkey" ("credentialID");

create index "scimManagedConnection_provisioningDomainId_idx" on "scimManagedConnection" ("provisioningDomainId");

create index "scimManagedCredential_connectionRecordId_idx" on "scimManagedCredential" ("connectionRecordId");

create index "scimManagedConnectionEvent_connectionRecordId_idx" on "scimManagedConnectionEvent" ("connectionRecordId");

create index "scimConnectionBinding_connectionId_idx" on "scimConnectionBinding" ("connectionId");

create index "scimIdentityTombstone_connectionId_idx" on "scimIdentityTombstone" ("connectionId");

create index "scimIdentityTombstone_provisioningDomainId_idx" on "scimIdentityTombstone" ("provisioningDomainId");

create index "scimIdentityTombstone_userId_idx" on "scimIdentityTombstone" ("userId");

create index "scimSubject_profileSourceId_idx" on "scimSubject" ("profileSourceId");

create index "scimUser_connectionId_idx" on "scimUser" ("connectionId");

create index "scimUser_provisioningDomainId_idx" on "scimUser" ("provisioningDomainId");

create index "scimUser_userId_idx" on "scimUser" ("userId");

create index "scimProjectionGrant_connectionId_idx" on "scimProjectionGrant" ("connectionId");

create index "scimProjectionGrant_provisioningDomainId_idx" on "scimProjectionGrant" ("provisioningDomainId");

create index "scimProjectionGrant_scimUserId_idx" on "scimProjectionGrant" ("scimUserId");

create index "scimProjectionGrant_userId_idx" on "scimProjectionGrant" ("userId");

create index "scimGroup_connectionId_idx" on "scimGroup" ("connectionId");

create index "scimGroup_provisioningDomainId_idx" on "scimGroup" ("provisioningDomainId");

create index "scimGroupMember_connectionId_idx" on "scimGroupMember" ("connectionId");

create index "scimGroupMember_groupId_idx" on "scimGroupMember" ("groupId");

create index "scimGroupMember_scimUserId_idx" on "scimGroupMember" ("scimUserId");

create index "apikey_configId_idx" on "apikey" ("configId");

create index "apikey_referenceId_idx" on "apikey" ("referenceId");

create index "apikey_key_idx" on "apikey" ("key");

create index "oauthClient_userId_idx" on "oauthClient" ("userId");

create index "oauthClientResource_clientId_idx" on "oauthClientResource" ("clientId");

create index "oauthClientResource_resourceId_idx" on "oauthClientResource" ("resourceId");

create index "oauthRefreshToken_clientId_idx" on "oauthRefreshToken" ("clientId");

create index "oauthRefreshToken_sessionId_idx" on "oauthRefreshToken" ("sessionId");

create index "oauthRefreshToken_userId_idx" on "oauthRefreshToken" ("userId");

create index "oauthRefreshToken_authorizationCodeId_idx" on "oauthRefreshToken" ("authorizationCodeId");

create index "oauthAccessToken_clientId_idx" on "oauthAccessToken" ("clientId");

create index "oauthAccessToken_sessionId_idx" on "oauthAccessToken" ("sessionId");

create index "oauthAccessToken_userId_idx" on "oauthAccessToken" ("userId");

create index "oauthAccessToken_authorizationCodeId_idx" on "oauthAccessToken" ("authorizationCodeId");

create index "oauthAccessToken_refreshId_idx" on "oauthAccessToken" ("refreshId");

create index "oauthConsent_clientId_idx" on "oauthConsent" ("clientId");

create index "oauthConsent_userId_idx" on "oauthConsent" ("userId");

create index "allauthAudit_actorId_idx" on "allauthAudit" ("actorId");

create index "allauthAudit_organizationId_idx" on "allauthAudit" ("organizationId");

create index "allauthAudit_createdAt_idx" on "allauthAudit" ("createdAt");

create unique index "oauthClientResource_clientId_resourceId_uidx" on "oauthClientResource" ("clientId", "resourceId");
