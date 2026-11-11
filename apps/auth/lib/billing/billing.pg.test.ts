import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import type Stripe from "@allauth/stripe-client";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { AuthEnvironment } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { projectRegistryPool } from "../projects/registry";
import { createWorkspace, deleteWorkspace } from "../workspaces/repository";
import { readWorkspaceEntitlements, synchronizeCommercialConfiguration } from "./entitlements";
import { processBillingJobs, reconcileWorkspaceBilling } from "./jobs";
import { createWorkspaceCheckout, createWorkspacePortal, readLocalWorkspaceBilling, readWorkspaceBillingSummary, verifyBillingProvider } from "./repository";
import type { BillingProvider } from "./types";
import { receiveStripeWebhook } from "./webhook";

const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);
const stripeObject = <T>(value: unknown) => value as T;

describe.skipIf(!existsSync(fixturePath))("workspace billing with isolated PostgreSQL", () => {
	const databaseName = `allauth_billing_${randomUUID().replaceAll("-", "")}`;
	let administrator: Pool; let env: AuthEnvironment; let database: Pool;
	let owner: ControlPrincipal; let manager: ControlPrincipal; let member: ControlPrincipal; let outsider: ControlPrincipal;

	async function actor(name: string): Promise<ControlPrincipal> {
		const id = randomUUID(), sessionId = randomUUID();
		await database.query('INSERT INTO public."user" (id,name,email,"emailVerified",role) VALUES ($1,$2,$3,true,\'user\')', [id, name, `${name}@billing.fixture.example`]);
		await database.query('INSERT INTO public.session (id,"userId",token,"expiresAt","updatedAt") VALUES ($1,$2,$3,NOW()+INTERVAL \'10 days\',NOW())', [sessionId, id, randomUUID()]);
		return { user: { id, name, email: `${name}@billing.fixture.example`, emailVerified: true, role: "user" }, session: { id: sessionId, userId: id } };
	}
	async function workspace() {
		const id = (await createWorkspace(owner, { name: `Billing ${randomUUID().slice(0, 8)}` }, env)).workspace.id;
		for (const [principal, role] of [[manager, "admin"], [member, "member"]] as const) await database.query('INSERT INTO public."allauthWorkspaceMember" (id,"workspaceId","userId",role) VALUES ($1,$2,$3,$4)', [randomUUID(), id, principal.user.id, role]);
		return id;
	}
	function provider() {
		const state = { subscriptions: [] as Stripe.Subscription[], invoices: [] as Stripe.Invoice[], sessions: new Map<string, Stripe.Checkout.Session>() };
		const result = {
			accounts: { retrieve: vi.fn().mockResolvedValue(stripeObject<Stripe.Account>({ id: "acct_fixture" })) },
			prices: { retrieve: vi.fn().mockResolvedValue(stripeObject<Stripe.Price>({ id: "price_fixture", active: true, currency: "usd", unit_amount: 999, livemode: false, recurring: { interval: "month", interval_count: 1, usage_type: "licensed" } })) },
			customers: { create: vi.fn().mockImplementation(async () => stripeObject<Stripe.Customer>({ id: `cus_${randomUUID().replaceAll("-", "")}`, livemode: false })) },
			subscriptions: { list: vi.fn().mockImplementation(async () => ({ data: state.subscriptions, has_more: false, object: "list", url: "/subscriptions" })) },
			invoices: { list: vi.fn().mockImplementation(async () => ({ data: state.invoices, has_more: false, object: "list", url: "/invoices" })) },
			checkout: { sessions: { create: vi.fn().mockImplementation(async (params: Stripe.Checkout.SessionCreateParams, _options: Stripe.RequestOptions) => {
				const session = stripeObject<Stripe.Checkout.Session>({ id: `cs_${randomUUID().replaceAll("-", "")}`, status: "open", url: "https://checkout.stripe.com/fixture", livemode: false, expires_at: params.expires_at });
				state.sessions.set(session.id, session); return session;
			}), retrieve: vi.fn().mockImplementation(async (id: string) => state.sessions.get(id)!) } },
			billingPortal: { sessions: { create: vi.fn().mockImplementation(async (_params: Stripe.BillingPortal.SessionCreateParams) => stripeObject<Stripe.BillingPortal.Session>({ url: "https://billing.stripe.com/fixture" })) } },
		};
		return { api: result satisfies BillingProvider, state };
	}
	function subscription(workspaceId: string, status: Stripe.Subscription.Status = "active") {
		return stripeObject<Stripe.Subscription>({ id: `sub_${workspaceId}`, livemode: false, status, created: 1_794_355_200, cancel_at_period_end: false, metadata: { allauthWorkspaceId: workspaceId }, items: { data: [{ quantity: 1, price: { id: "price_fixture" } }] } });
	}
	function paidInvoice(sub: Stripe.Subscription, until: Date) {
		return stripeObject<Stripe.Invoice>({ id: `in_${sub.id}`, status: "paid", parent: { subscription_details: { subscription: sub.id } }, lines: { data: [{ pricing: { price_details: { price: "price_fixture" } }, period: { end: Math.floor(until.getTime() / 1000) } }] } });
	}
	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath, "utf8"));
		const url = new URL(fixture.DATABASE_URL);
		if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445") throw new Error("Only the isolated local AllAuth fixture is permitted.");
		administrator = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
		await administrator.query(`CREATE DATABASE "${databaseName}"`); url.pathname = `/${databaseName}`;
		env = { DATABASE_URL: url.toString(), BETTER_AUTH_URL: "http://localhost:3000", WORKSPACE_MAX_OWNED: "100", ALLAUTH_DEPLOYMENT_MODE: "hosted", ALLAUTH_BILLING_CHECKOUT_ENABLED: "true", ALLAUTH_BILLING_ENFORCEMENT_ENABLED: "true", ALLAUTH_STRIPE_ACCOUNT_ID: "acct_fixture", ALLAUTH_STRIPE_LIVEMODE: "false", ALLAUTH_STRIPE_PRO_PRICE_ID: "price_fixture", ALLAUTH_STRIPE_SECRET_KEY: "rk_test_fixture", ALLAUTH_STRIPE_WEBHOOK_SECRET: "whsec_fixture" };
		for (const [key, value] of Object.entries(env)) vi.stubEnv(key, String(value));
		database = projectRegistryPool(env);
		for (const filename of readdirSync(new URL("../../migrations", import.meta.url)).filter((name) => name.endsWith(".sql")).sort()) await database.query(readFileSync(new URL(`../../migrations/${filename}`, import.meta.url), "utf8"));
		await synchronizeCommercialConfiguration(database, env);
		owner = await actor("owner"); manager = await actor("manager"); member = await actor("member"); outsider = await actor("outsider");
	}, 30_000);
	 afterAll(async () => {
		if (database) await database.end();
		if (administrator) { try { await dropClosedFixtureDatabase(administrator, databaseName); } finally { await administrator.end(); } }
		vi.unstubAllEnvs();
	});

	it("allows owner mutations and admin reads while rejecting members, outsiders and impersonated principals", async () => {
		const id = await workspace(), stripe = provider();
		expect((await readWorkspaceBillingSummary(manager, id, env)).billing.canManageBilling).toBe(false);
		for (const principal of [member, outsider, { ...owner, session: { ...owner.session, impersonatedBy: "someone" } }]) await expect(readWorkspaceBillingSummary(principal, id, env)).rejects.toMatchObject({ statusCode: 403 });
		await expect(createWorkspaceCheckout(manager, id, env, stripe.api)).rejects.toMatchObject({ statusCode: 403 });
		await expect(createWorkspacePortal(manager, id, env, stripe.api)).rejects.toMatchObject({ statusCode: 403 });
		expect(stripe.api.customers.create).not.toHaveBeenCalled();
	});
	it("serializes concurrent upgrades into one Customer and one Checkout using fixed server inputs", async () => {
		const id = await workspace(), stripe = provider();
		const results = await Promise.all([createWorkspaceCheckout(owner, id, env, stripe.api), createWorkspaceCheckout(owner, id, env, stripe.api)]);
		expect(results[0]).toEqual(results[1]); expect(stripe.api.customers.create).toHaveBeenCalledTimes(1); expect(stripe.api.checkout.sessions.create).toHaveBeenCalledTimes(1);
		const params = stripe.api.checkout.sessions.create.mock.calls[0]![0];
		expect(params).toMatchObject({ client_reference_id: id, line_items: [{ price: "price_fixture", quantity: 1 }], metadata: { allauthWorkspaceId: id } });
		expect(params.success_url).toBe(`http://localhost:3000/admin/workspaces?workspace=${id}&tab=billing&checkout=success`);
		expect(params).not.toHaveProperty("payment_method_types");
		expect((await readWorkspaceEntitlements(id, env)).plan).toBe("free");
	});

	it("reuses the durable checkout idempotency key after a response failure", async () => {
		const id = await workspace(), stripe = provider();
		stripe.api.checkout.sessions.create.mockRejectedValueOnce(new Error("network timeout"));
		await expect(createWorkspaceCheckout(owner, id, env, stripe.api)).rejects.toThrow("network timeout");
		await createWorkspaceCheckout(owner, id, env, stripe.api);
		expect(stripe.api.checkout.sessions.create.mock.calls[0]![1]).toEqual(stripe.api.checkout.sessions.create.mock.calls[1]![1]);
		expect(stripe.api.checkout.sessions.create.mock.calls[0]![0]).toEqual(stripe.api.checkout.sessions.create.mock.calls[1]![0]);
	});
	it("recovers the same remote Checkout if saving the successful response fails", async () => {
		const id = await workspace(), stripe = provider();
		const remote = stripe.api.checkout.sessions.create.getMockImplementation()!;
		const byKey = new Map<string, Stripe.Checkout.Session>();
		stripe.api.checkout.sessions.create.mockImplementation(async (params, options) => {
			const key = options.idempotencyKey!; const existing = byKey.get(key); if (existing) return existing;
			const session = await remote(params, options); byKey.set(key, session); return session;
		});
		await database.query(`CREATE FUNCTION public.allauth_fixture_fail_checkout_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture checkout persistence failure'; END; $$; CREATE TRIGGER fixture_checkout_write BEFORE UPDATE ON public."allauthBillingCheckout" FOR EACH ROW WHEN(NEW."sessionId" IS NOT NULL) EXECUTE FUNCTION public.allauth_fixture_fail_checkout_write()`);
		try { await expect(createWorkspaceCheckout(owner, id, env, stripe.api)).rejects.toThrow("fixture checkout persistence failure"); }
		finally { await database.query("DROP FUNCTION public.allauth_fixture_fail_checkout_write() CASCADE"); }
		await expect(createWorkspaceCheckout(owner, id, env, stripe.api)).resolves.toHaveProperty("url");
		expect(byKey.size).toBe(1); expect(stripe.state.sessions.size).toBe(1);
		expect(stripe.api.checkout.sessions.create.mock.calls[0]?.[1]).toEqual(stripe.api.checkout.sessions.create.mock.calls[1]?.[1]);
	});

	it("requires confirmed invoice payment, retains a single renewal grace window, and reconciles cancellation", async () => {
		const id = await workspace(), stripe = provider(), now = new Date();
		await createWorkspaceCheckout(owner, id, env, stripe.api);
		stripe.state.subscriptions = [subscription(id)];
		await reconcileWorkspaceBilling(id, env, stripe.api, now);
		expect((await readWorkspaceEntitlements(id, env)).plan).toBe("free");
		const until = new Date(now.getTime() + 30 * 86_400_000);
		stripe.state.invoices = [paidInvoice(stripe.state.subscriptions[0]!, until)];
		await reconcileWorkspaceBilling(id, env, stripe.api, now);
		expect((await readWorkspaceEntitlements(id, env)).plan).toBe("pro");
		stripe.state.subscriptions = [subscription(id, "past_due")];
		const failure = new Date(until.getTime() + 1000);
		stripe.state.invoices.push(stripeObject<Stripe.Invoice>({ ...paidInvoice(stripe.state.subscriptions[0]!, new Date(until.getTime() + 30 * 86_400_000)), id: "in_failed_renewal", status: "open", attempted: true, created: Math.floor(failure.getTime() / 1000), status_transitions: { finalized_at: Math.floor(failure.getTime() / 1000) } }));
		await reconcileWorkspaceBilling(id, env, stripe.api, failure);
		await reconcileWorkspaceBilling(id, env, stripe.api, new Date(failure.getTime() + 86_400_000));
		expect((await readLocalWorkspaceBilling(id, env))?.firstPaymentFailureAt).toEqual(new Date(Math.floor(failure.getTime() / 1000) * 1000));
		expect((await readWorkspaceEntitlements(id, env, { now: new Date(failure.getTime() + 6 * 86_400_000) })).plan).toBe("pro");
		expect((await readWorkspaceEntitlements(id, env, { now: new Date(failure.getTime() + 8 * 86_400_000) })).plan).toBe("free");
		stripe.state.subscriptions = [subscription(id, "canceled")];
		await reconcileWorkspaceBilling(id, env, stripe.api, now);
		expect((await readWorkspaceEntitlements(id, env)).plan).toBe("free");
	});

	it("deduplicates event delivery and leases current-state reconciliation across workers", async () => {
		const id = await workspace(), stripe = provider();
		await createWorkspaceCheckout(owner, id, env, stripe.api);
		const billing = (await readLocalWorkspaceBilling(id, env))!;
		const event = stripeObject<Stripe.Event>({ id: `evt_${id}`, type: "invoice.paid", livemode: false, created: Math.floor(Date.now() / 1000), data: { object: { id: "in_old", customer: billing.stripeCustomerId } } });
		const receive = () => receiveStripeWebhook(new Request("http://localhost:3000/webhook", { method: "POST", headers: { "stripe-signature": "fixture" }, body: "{}" }), env, { verify: async () => event });
		await receive(); await receive();
		stripe.state.subscriptions = [subscription(id, "canceled")];
		const reconcile = vi.fn(reconcileWorkspaceBilling);
		const results = await Promise.all([processBillingJobs(env, { provider: stripe.api, maximum: 1, reconcile }), processBillingJobs(env, { provider: stripe.api, maximum: 1, reconcile })]);
		expect(results.reduce((total, result) => total + result.claimed, 0)).toBe(1); expect(reconcile).toHaveBeenCalledTimes(1);
		expect((await readLocalWorkspaceBilling(id, env))?.stripeStatus).toBe("canceled");
		expect((await readWorkspaceEntitlements(id, env)).plan).toBe("free");
	});

	it("rejects wrong configured accounts and prices before creating a customer", async () => {
		const id = await workspace(), stripe = provider();
		stripe.api.accounts.retrieve.mockResolvedValueOnce(stripeObject<Stripe.Account>({ id: "acct_other" }));
		await expect(createWorkspaceCheckout(owner, id, env, stripe.api)).rejects.toMatchObject({ statusCode: 503 });
		stripe.api.prices.retrieve.mockResolvedValueOnce(stripeObject<Stripe.Price>({ active: true, livemode: false, currency: "usd", unit_amount: 1999, recurring: { interval: "month", interval_count: 1 } }));
		await expect(createWorkspaceCheckout(owner, id, env, stripe.api)).rejects.toMatchObject({ statusCode: 503 });
		expect(stripe.api.customers.create).not.toHaveBeenCalled();
	});

	it("keeps customer ownership workspace-scoped and prevents deleting pending or chargeable billing", async () => {
		const id = await workspace(), stripe = provider();
		await createWorkspaceCheckout(owner, id, env, stripe.api);
		await expect(deleteWorkspace(owner, id, env)).rejects.toMatchObject({ statusCode: 409 });
		await createWorkspacePortal(owner, id, env, stripe.api);
		expect(stripe.api.billingPortal.sessions.create.mock.calls[0]![0].customer).toBe((await readLocalWorkspaceBilling(id, env))!.stripeCustomerId);
		await database.query('UPDATE public."allauthBillingCheckout" SET "expiresAt"=NOW()-INTERVAL \'1 hour\' WHERE "workspaceId"=$1', [id]);
		await database.query('UPDATE public."allauthWorkspaceBilling" SET "stripeStatus"=\'canceled\',"reconciledAt"=NOW() WHERE "workspaceId"=$1', [id]);
		await expect(deleteWorkspace(owner, id, env)).resolves.toEqual({ success: true });
		expect((await readLocalWorkspaceBilling(id, env))?.stripeCustomerId).toBeTruthy();
	});
	it("rechecks stored ownership after provider latency and never returns a payment URL to a revoked actor", async () => {
		const id = await workspace(), stripe = provider();
		stripe.api.accounts.retrieve.mockImplementationOnce(async () => {
			await database.query('UPDATE public."user" SET banned=true WHERE id=$1', [owner.user.id]);
			return stripeObject<Stripe.Account>({ id: "acct_fixture" });
		});
		try { await expect(createWorkspaceCheckout(owner, id, env, stripe.api)).rejects.toMatchObject({ statusCode: 403 }); expect(stripe.api.customers.create).not.toHaveBeenCalled(); }
		finally { await database.query('UPDATE public."user" SET banned=false WHERE id=$1', [owner.user.id]); }
		await createWorkspaceCheckout(owner, id, env, stripe.api);
		stripe.api.billingPortal.sessions.create.mockImplementationOnce(async () => {
			await database.query('UPDATE public."user" SET banned=true WHERE id=$1', [owner.user.id]);
			return stripeObject<Stripe.BillingPortal.Session>({ url: "https://billing.stripe.com/private" });
		});
		try { await expect(createWorkspacePortal(owner, id, env, stripe.api)).rejects.toMatchObject({ statusCode: 403 }); }
		finally { await database.query('UPDATE public."user" SET banned=false WHERE id=$1', [owner.user.id]); }
	});
	it("does not open another Checkout for a completed session until its subscription is confirmed ended", async () => {
		const id = await workspace(), stripe = provider(); await createWorkspaceCheckout(owner, id, env, stripe.api);
		const session = [...stripe.state.sessions.values()][0]!; const ended = subscription(id, "canceled");
		stripe.state.sessions.set(session.id, { ...session, status: "complete", subscription: ended.id });
		await database.query('UPDATE public."allauthWorkspaceBilling" SET "stripeStatus"=\'canceled\' WHERE "workspaceId"=$1', [id]);
		await expect(createWorkspaceCheckout(owner, id, env, stripe.api)).rejects.toMatchObject({ statusCode: 409 }); expect(stripe.api.checkout.sessions.create).toHaveBeenCalledTimes(1);
		stripe.state.subscriptions = [ended]; await expect(createWorkspaceCheckout(owner, id, env, stripe.api)).resolves.toHaveProperty("url"); expect(stripe.api.checkout.sessions.create).toHaveBeenCalledTimes(2);
	});
	it("checks every subscription page before opening another Checkout", async () => {
		const id = await workspace(), stripe = provider(); await createWorkspaceCheckout(owner, id, env, stripe.api);
		stripe.api.subscriptions.list.mockResolvedValueOnce({ data: [subscription(id, "canceled")], has_more: true, object: "list", url: "/subscriptions" }).mockResolvedValueOnce({ data: [subscription(id)], has_more: false, object: "list", url: "/subscriptions" });
		await expect(createWorkspaceCheckout(owner, id, env, stripe.api)).rejects.toMatchObject({ statusCode: 409 });
		expect(stripe.api.subscriptions.list.mock.calls.at(-1)?.[0]).toMatchObject({ starting_after: `sub_${id}` }); expect(stripe.api.checkout.sessions.create).toHaveBeenCalledTimes(1);
	});
	it("keeps cancellation and reconciliation working when new sales fail Price or tax checks", async () => {
		const id = await workspace(), stripe = provider(); await createWorkspaceCheckout(owner, id, env, stripe.api);
		stripe.api.prices.retrieve.mockRejectedValue(new Error("archived price"));
		const taxEnv = { ...env, ALLAUTH_STRIPE_AUTOMATIC_TAX_ENABLED: "true" };
		await expect(createWorkspaceCheckout(owner, id, taxEnv, stripe.api)).rejects.toThrow("archived price");
		await expect(createWorkspacePortal(owner, id, taxEnv, stripe.api)).resolves.toHaveProperty("url");
		stripe.state.subscriptions = [subscription(id, "canceled")]; await expect(reconcileWorkspaceBilling(id, taxEnv, stripe.api)).resolves.toBe(true);
	});
	it("enables automatic tax only with an exclusive Price, active registration and Product classification", async () => {
		const stripe = provider(); const taxEnv = { ...env, ALLAUTH_STRIPE_AUTOMATIC_TAX_ENABLED: "true" };
		await expect(verifyBillingProvider(taxEnv, stripe.api)).rejects.toMatchObject({ statusCode: 503 });
		const price = stripeObject<Stripe.Price>({ id: "price_fixture", product: "prod_fixture", active: true, currency: "usd", unit_amount: 999, livemode: false, tax_behavior: "exclusive", recurring: { interval: "month", interval_count: 1, usage_type: "licensed" } });
		stripe.api.prices.retrieve.mockResolvedValue(price);
		const registrations = vi.fn().mockResolvedValue({ data: [], has_more: false, object: "list", url: "/tax/registrations" });
		const product = vi.fn().mockResolvedValue(stripeObject<Stripe.Product>({ id: "prod_fixture", tax_code: "txcd_fixture" }));
		const configured = { ...stripe.api, tax: { registrations: { list: registrations } }, products: { retrieve: product } } satisfies BillingProvider;
		await expect(verifyBillingProvider(taxEnv, configured)).rejects.toMatchObject({ statusCode: 503 });
		registrations.mockResolvedValue({ data: [stripeObject<Stripe.Tax.Registration>({ id: "taxreg_fixture", status: "active" })], has_more: false, object: "list", url: "/tax/registrations" });
		await expect(verifyBillingProvider(taxEnv, configured)).resolves.toMatchObject({ automaticTaxEnabled: true });
		product.mockResolvedValue(stripeObject<Stripe.Product>({ id: "prod_fixture", tax_code: null })); await expect(verifyBillingProvider(taxEnv, configured)).rejects.toMatchObject({ statusCode: 503 });
	});
	it("does not acknowledge or report another worker's replacement lease", async () => {
		const id = await workspace(), stripe = provider(); await createWorkspaceCheckout(owner, id, env, stripe.api);
		const row = (await readLocalWorkspaceBilling(id, env))!; const eventId = `evt_lease_${id}`;
		await database.query('INSERT INTO public."allauthBillingWebhook"(id,"stripeAccountId","stripeLivemode",type,"customerId","objectId","occurredAt") VALUES($1,\'acct_fixture\',false,\'invoice.paid\',$2,\'in_fixture\',NOW())', [eventId, row.stripeCustomerId]);
		const reconcile = vi.fn(async () => { await database.query('UPDATE public."allauthBillingWebhook" SET "leaseId"=\'replacement-lease\' WHERE id=$1', [eventId]); return true; });
		const result = await processBillingJobs(env, { provider: stripe.api, maximum: 1, reconcile });
		expect(result).toMatchObject({ claimed: 1, processed: 0, ignored: 0 });
		expect((await database.query('SELECT status,"leaseId" FROM public."allauthBillingWebhook" WHERE id=$1', [eventId])).rows[0]).toEqual({ status: "processing", leaseId: "replacement-lease" });
	});
	it("deduplicates and claims event identities separately for each Stripe account and mode", async () => {
		const id = await workspace(), stripe = provider(); await createWorkspaceCheckout(owner, id, env, stripe.api);
		const row = (await readLocalWorkspaceBilling(id, env))!; const eventId = `evt_scoped_${id}`;
		const deliver = (configuration: AuthEnvironment, mode: boolean) => receiveStripeWebhook(new Request("http://localhost:3000/webhook", { method: "POST", headers: { "stripe-signature": "fixture" }, body: "{}" }), configuration, { verify: async () => stripeObject<Stripe.Event>({ id: eventId, type: "invoice.paid", livemode: mode, created: Math.floor(Date.now() / 1000), data: { object: { id: "in_fixture", customer: row.stripeCustomerId } } }) });
		await deliver(env, false); await deliver(env, false);
		await deliver({ ...env, ALLAUTH_STRIPE_LIVEMODE: "true", ALLAUTH_STRIPE_SECRET_KEY: "rk_live_fixture" }, true);
		await deliver({ ...env, ALLAUTH_STRIPE_ACCOUNT_ID: "acct_other" }, false);
		expect((await database.query('SELECT id FROM public."allauthBillingWebhook" WHERE id=$1', [eventId])).rows).toHaveLength(3);
		const result = await processBillingJobs(env, { provider: stripe.api, maximum: 1, reconcile: async () => true }); expect(result).toMatchObject({ claimed: 1, processed: 1, ignored: 0 });
		const rows = (await database.query<{ stripeAccountId: string; stripeLivemode: boolean; status: string }>('SELECT "stripeAccountId","stripeLivemode",status FROM public."allauthBillingWebhook" WHERE id=$1', [eventId])).rows;
		expect(rows.find(value => value.stripeAccountId === "acct_fixture" && !value.stripeLivemode)?.status).toBe("processed");
		expect(rows.filter(value => value.stripeAccountId !== "acct_fixture" || value.stripeLivemode).every(value => value.status === "pending")).toBe(true);
	});
});
