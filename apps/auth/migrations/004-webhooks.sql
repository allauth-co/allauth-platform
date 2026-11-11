-- Signing credentials are encrypted in the native plugin; management reads never select them.
CREATE TABLE "allauthWebhookEndpoint" (
	"id" text PRIMARY KEY,
	"url" text NOT NULL,
	"description" text NOT NULL DEFAULT '',
	"eventTypes" jsonb NOT NULL,
	"encryptedSecret" text NOT NULL,
	"enabled" boolean NOT NULL DEFAULT true,
	"createdAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
	"updatedAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE "allauthWebhookDelivery" (
	"id" text PRIMARY KEY,
	"endpointId" text NOT NULL REFERENCES "allauthWebhookEndpoint"("id") ON DELETE CASCADE,
	"eventId" text NOT NULL,
	"eventType" text NOT NULL,
	"payload" jsonb NOT NULL,
	"status" text NOT NULL DEFAULT 'pending' CHECK ("status" IN ('pending','processing','delivered','failed')),
	"attempts" integer NOT NULL DEFAULT 0 CHECK ("attempts" BETWEEN 0 AND 8),
	"nextAttemptAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
	"leaseId" text,
	"lockedUntil" timestamptz,
	"createdAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
	"deliveredAt" timestamptz,
	"statusCode" integer,
	"lastError" text,
	UNIQUE ("endpointId","eventId")
);
CREATE INDEX "allauthWebhookDelivery_pending" ON "allauthWebhookDelivery" ("status","nextAttemptAt") WHERE "status" IN ('pending','processing');
CREATE INDEX "allauthWebhookDelivery_endpoint_createdAt" ON "allauthWebhookDelivery" ("endpointId","createdAt" DESC);
CREATE INDEX "allauthWebhookDelivery_createdAt" ON "allauthWebhookDelivery" ("createdAt");

-- TG_TABLE_SCHEMA, not an assumed public schema, binds the trigger to its project's tables.
-- Its invoker privileges remain the restricted app role; no SECURITY DEFINER escalation exists.
CREATE FUNCTION "enqueueAllauthWebhookEvent"() RETURNS trigger LANGUAGE plpgsql AS $function$
DECLARE
	event_json jsonb;
	user_json jsonb;
	payload_json jsonb;
BEGIN
	event_json := jsonb_strip_nulls(jsonb_build_object(
		'id', NEW."id", 'type', NEW."type", 'outcome', NEW."outcome", 'actorId', NEW."actorId", 'userId', NEW."userId",
		'organizationId', NEW."organizationId", 'clientId', NEW."clientId", 'targetId', NEW."targetId",
		'ipAddress', NEW."ipAddress", 'userAgent', NEW."userAgent", 'createdAt', NEW."createdAt", 'metadata', NEW."metadata"
	));
	IF NEW."userId" IS NOT NULL AND NEW."type" LIKE 'user.%' THEN
		EXECUTE format('SELECT jsonb_strip_nulls(jsonb_build_object(''id'',id,''name'',name,''email'',email,''emailVerified'',"emailVerified",''image'',image,''publicMetadata'',CASE WHEN octet_length("publicMetadata"::text)<=16384 THEN "publicMetadata" ELSE NULL END)) FROM %I."user" WHERE id=$1', TG_TABLE_SCHEMA)
		INTO user_json USING NEW."userId";
	END IF;
	payload_json := jsonb_build_object('id',NEW."id",'type',NEW."type",'timestamp',NEW."createdAt",'data',jsonb_strip_nulls(jsonb_build_object('event',event_json,'user',user_json)));
	EXECUTE format('INSERT INTO %I."allauthWebhookDelivery" ("id","endpointId","eventId","eventType","payload","status","attempts","nextAttemptAt","createdAt") SELECT md5(w.id || $1)::uuid::text,w.id,$1,$2,$3,''pending'',0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM %I."allauthWebhookEndpoint" w WHERE w.enabled=true AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(w."eventTypes") s(value) WHERE s.value=''*'' OR s.value=$2 OR (right(s.value,2)=''.*'' AND left($2,length(s.value)-1)=left(s.value,length(s.value)-1))) ON CONFLICT ("endpointId","eventId") DO NOTHING', TG_TABLE_SCHEMA,TG_TABLE_SCHEMA)
	USING NEW."id",NEW."type",payload_json;
	RETURN NEW;
END;
$function$;
CREATE TRIGGER "allauthEvent_webhook_outbox" AFTER INSERT ON "allauthEvent" FOR EACH ROW EXECUTE FUNCTION "enqueueAllauthWebhookEvent"();
