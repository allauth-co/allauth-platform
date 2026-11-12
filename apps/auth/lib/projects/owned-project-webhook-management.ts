import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { canonicalIP } from "../control/security-policy";
import type { ControlPrincipal } from "../control/types";
import type { Resolver } from "../control/webhook-contract";
import {
	newWebhookSigningSecret,
	publicDelivery,
	publicEndpoint,
	validateWebhookDestination,
	webhookCreateInput,
	webhookDeliveryInput,
	webhookDeliveryQuery,
	webhookEndpointInput,
} from "../control/webhook-contract";
import { sealLegacyMfaRecord } from "./legacy-mfa-record";
import {
	accountLinkError,
	accountLinkJson,
} from "./owned-project-account-links";
import { lockOwnedProjectWorkspaceAdministrator } from "./owned-project-admin-authority";
import type { createProjectEngineStore } from "./owned-project-engine-store";
import { admitOwnedProjectNativeRoute } from "./owned-project-native-admission";
import type { Project } from "./registry";

type Store = ReturnType<typeof createProjectEngineStore>;
const webhookRoutes = new Map([
	["/control/webhooks", "GET"],
	["/control/webhooks/deliveries", "GET"],
	["/control/webhooks/create", "POST"],
	["/control/webhooks/rotate", "POST"],
	["/control/webhooks/delete", "POST"],
	["/control/webhooks/retry", "POST"],
]);
const forbidden = (
	message = "A verified workspace administrator is required.",
) => accountLinkError(403, "FORBIDDEN", message);
const invalid = () =>
	accountLinkError(400, "INVALID_BODY", "The request contains invalid fields.");
const badRequest = (message: string) =>
	accountLinkError(400, "BAD_REQUEST", message);

const endpointProjection =
	'id,url,description,"eventTypes",enabled,"createdAt","updatedAt"';

function audit(
	client: PoolClient,
	event: string,
	actorId: string,
	targetId: string,
	ip: string | null,
	request: Request,
) {
	const userAgent =
		request.headers
			.get("user-agent")
			?.slice(0, 512)
			.replace(/[\u0000-\u001f]/g, "") || null;
	return client.query(
		`INSERT INTO "allauthEvent" (id,type,outcome,"actorId","targetId","ipAddress","userAgent","createdAt")
		 VALUES ($1,$2,'success',$3,$4,$5,$6,statement_timestamp())`,
		[randomUUID(), event, actorId, targetId, ip, userAgent],
	);
}

/** Manage the existing endpoint and delivery records through a live, exact-realm console session. */
export function createOwnedProjectWebhookManagement(options: {
	store: Store;
	project: Pick<Project, "id" | "schemaName" | "slug" | "workspaceId">;
	origin: string;
	basePath: string;
	platformOrigin: string;
	/** The derived project key used by the existing delivery worker. */
	encryptionSecret: string;
	readWorkspacePrincipal(headers: Headers): Promise<ControlPrincipal | null>;
	readBody(request: Request): Promise<unknown>;
	trustedIP(request: Request): string | null;
	resolver?: Resolver;
}) {
	const { store, project } = options;
	const direct = `/api/projects/${project.slug}/auth`;
	const encrypt = (value: string) =>
		sealLegacyMfaRecord(value, { secret: options.encryptionSecret });

	return async (request: Request, path: string) => {
		const method = webhookRoutes.get(path);
		if (!method || request.method !== method) return null;
		const url = new URL(request.url);
		const browserOrigin = request.headers.get("origin");
		if (
			options.basePath !== direct ||
			options.origin !== options.platformOrigin ||
			url.origin !== options.platformOrigin ||
			url.pathname !== direct + path ||
			request.headers.has("authorization")
		)
			return forbidden();
		const actor = await options.readWorkspacePrincipal(request.headers);
		if (
			!actor ||
			actor.session.userId !== actor.user.id ||
			actor.session.impersonatedBy ||
			!actor.user.emailVerified ||
			actor.user.banned
		)
			return forbidden();
		if (
			method === "POST" &&
			(browserOrigin !== options.platformOrigin ||
				request.headers.get("sec-fetch-site") === "cross-site")
		)
			return forbidden("Webhook changes require a same-origin request.");
		const ip = canonicalIP(options.trustedIP(request));
		const actorId = actor.user.id;
		const authorized = async (
			work: (client: PoolClient) => Promise<Response>,
		) =>
			store.transaction(async (client) => {
				if (
					!(await lockOwnedProjectWorkspaceAdministrator(
						client,
						project,
						actor,
					))
				)
					return forbidden();
				const limited = ip
					? await admitOwnedProjectNativeRoute(client, ip, path, {
							max: 100,
							windowMs: 60_000,
						})
					: null;
				if (limited) {
					limited.headers.set("cache-control", "no-store");
					limited.headers.set("pragma", "no-cache");
					return limited;
				}
				return work(client);
			});

		if (path === "/control/webhooks") {
			return authorized(async (client) => {
				const { rows } = await client.query(
					`SELECT ${endpointProjection} FROM "allauthWebhookEndpoint" ORDER BY "createdAt" DESC LIMIT 20`,
				);
				return accountLinkJson({
					endpoints: rows.map(publicEndpoint),
					deliveryRetentionDays: 30,
					maxAttempts: 8,
				});
			});
		}
		if (path === "/control/webhooks/deliveries") {
			const parsed = webhookDeliveryQuery.safeParse(
				Object.fromEntries(url.searchParams),
			);
			if (!parsed.success) return invalid();
			const { endpointId, limit, offset } = parsed.data;
			return authorized(async (client) => {
				const where = `"createdAt" >= CURRENT_TIMESTAMP - INTERVAL '30 days'
				 AND ($1::text IS NULL OR "endpointId"=$1)`;
				const { rows } = await client.query(
					`SELECT id,"endpointId","eventId","eventType",status,attempts,"nextAttemptAt","createdAt","deliveredAt","statusCode","lastError"
					 FROM "allauthWebhookDelivery" WHERE ${where}
					 ORDER BY "createdAt" DESC,id DESC LIMIT $2 OFFSET $3`,
					[endpointId ?? null, limit, offset],
				);
				const count = await client.query<{ total: string }>(
					`SELECT COUNT(*)::text AS total FROM "allauthWebhookDelivery" WHERE ${where}`,
					[endpointId ?? null],
				);
				return accountLinkJson({
					deliveries: rows.map(publicDelivery),
					total: Number(count.rows[0].total),
					limit,
					offset,
					retentionDays: 30,
				});
			});
		}
		const body = await options.readBody(request);
		if (path === "/control/webhooks/create") {
			const parsed = webhookCreateInput.safeParse(body);
			if (!parsed.success) return invalid();
			let destination: Awaited<ReturnType<typeof validateWebhookDestination>>;
			try {
				destination = await validateWebhookDestination(
					parsed.data.url,
					options.resolver,
				);
			} catch {
				return badRequest(
					"Webhook destinations require public HTTPS on port 443.",
				);
			}
			const { description, eventTypes } = parsed.data;
			return authorized(async (client) => {
				// Coordinate with the legacy writer's endpoint limit during rollback.
				await client.query(
					"SELECT pg_advisory_xact_lock(hashtext('allauth-webhook-endpoint-limit'))",
				);
				const count = await client.query<{ total: string }>(
					'SELECT count(*)::text AS total FROM "allauthWebhookEndpoint"',
				);
				if (Number(count.rows[0].total) >= 20)
					return badRequest(
						"A project can register at most 20 webhook endpoints.",
					);
				const secret = newWebhookSigningSecret();
				const id = randomUUID();
				const { rows } = await client.query(
					`INSERT INTO "allauthWebhookEndpoint" (id,url,description,"eventTypes","encryptedSecret")
					 VALUES ($1,$2,$3,$4::jsonb,$5) RETURNING ${endpointProjection}`,
					[
						id,
						destination.url.href,
						description,
						JSON.stringify([...new Set(eventTypes)]),
						encrypt(secret),
					],
				);
				await audit(client, "webhook.created", actorId, id, ip, request);
				return accountLinkJson({ endpoint: publicEndpoint(rows[0]), secret });
			});
		}
		const parsed = (
			path === "/control/webhooks/retry"
				? webhookDeliveryInput
				: webhookEndpointInput
		).safeParse(body);
		if (!parsed.success) return invalid();
		const { id } = parsed.data;
		return authorized(async (client) => {
			if (path === "/control/webhooks/rotate") {
				const secret = newWebhookSigningSecret();
				const updated = await client.query(
					`UPDATE "allauthWebhookEndpoint" SET "encryptedSecret"=$2,"updatedAt"=CURRENT_TIMESTAMP WHERE id=$1 RETURNING id`,
					[id, encrypt(secret)],
				);
				if (updated.rowCount !== 1)
					return accountLinkError(
						404,
						"NOT_FOUND",
						"Webhook endpoint not found.",
					);
				await audit(client, "webhook.secret-rotated", actorId, id, ip, request);
				return accountLinkJson({ secret });
			}
			if (path === "/control/webhooks/delete") {
				await client.query('DELETE FROM "allauthWebhookEndpoint" WHERE id=$1', [
					id,
				]);
				await audit(client, "webhook.deleted", actorId, id, ip, request);
				return accountLinkJson({ success: true });
			}
			const updated = await client.query(
				`UPDATE "allauthWebhookDelivery" SET status='pending',"nextAttemptAt"=CURRENT_TIMESTAMP,
				 "lastError"=NULL,"leaseId"=NULL,"lockedUntil"=NULL
				 WHERE id=$1 AND status='failed' AND attempts < 8
				 AND "createdAt" >= CURRENT_TIMESTAMP-INTERVAL '30 days' RETURNING id`,
				[id],
			);
			if (updated.rowCount !== 1)
				return badRequest(
					"Only failed deliveries with remaining attempts can be retried.",
				);
			await audit(client, "webhook.delivery-retried", actorId, id, ip, request);
			return accountLinkJson({ success: true });
		});
	};
}
