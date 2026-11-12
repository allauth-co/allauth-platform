// cspell:words xact
import { AsyncLocalStorage } from "node:async_hooks";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import { platformWorkspaceId } from "../workspaces/types";
import type { Project } from "./registry";

const writer = z.enum(["legacy", "allauth"]);
const state = z
	.strictObject({
		writer,
		revision: z.number().int().min(0).max(2_147_483_647),
	})
	.refine(({ writer, revision }) => revision > 0 || writer === "legacy");
const projectId = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;

/** A revision distinguishes successive cutovers, including a return to the original writer. */
export type ProjectEngineWriterState = z.infer<typeof state>;
export type ProjectEngineWriter = z.infer<typeof writer>;

/** Cancellation reports loss of the dedicated lock connection to the realm operation. */
export interface ProjectEngineWriterLease extends ProjectEngineWriterState {
	readonly signal: AbortSignal;
}

type Binding = Pick<
	Project,
	"id" | "schemaName" | "workspaceId" | "environment"
>;
type Database = Pick<Pool, "connect">;
interface Options {
	database: Database;
	project: Binding;
	selectedProjectId: string;
}

interface ActiveLease {
	database: Database;
	projectId: string;
	lease: ProjectEngineWriterLease;
	accepting: boolean;
	pending: Set<Promise<unknown>>;
}

const activeLease = new AsyncLocalStorage<ActiveLease>();

function failure(code: string, message: string) {
	return Object.assign(new Error(message), { code });
}

function scopeFailure() {
	return failure(
		"ALLAUTH_PROJECT_WRITER_SCOPE_FORBIDDEN",
		"The project writer requires the exact protected internal development realm.",
	);
}

/** Keep the advisory lock on its own connection until the operation and its nested work settle. */
async function transaction<Result>(
	database: Database,
	work: (client: PoolClient, signal: AbortSignal) => Promise<Result>,
) {
	const client = await database.connect();
	const connection = new AbortController();
	let discard = false;
	const disconnected = () => {
		discard = true;
		connection.abort(
			failure(
				"ALLAUTH_PROJECT_WRITER_LEASE_LOST",
				"The project writer connection is unavailable.",
			),
		);
	};
	client.on("error", disconnected);
	client.on("end", disconnected);
	try {
		// A waiter must read the mode after acquisition using a fresh statement snapshot.
		await client.query("BEGIN ISOLATION LEVEL READ COMMITTED");
		const result = await work(client, connection.signal);
		connection.signal.throwIfAborted();
		await client.query("COMMIT");
		return result;
	} catch (error) {
		try {
			await client.query("ROLLBACK");
		} catch {
			discard = true;
		}
		throw error;
	} finally {
		client.removeListener("error", disconnected);
		client.removeListener("end", disconnected);
		client.release(discard);
	}
}

/** Tag an engine pool with its admitted writer and revision for the PostgreSQL mutation guards. */
export function projectEngineWriterConnectionOptions(
	id: string,
	admitted: ProjectEngineWriterState,
) {
	if (!projectId.test(id)) throw scopeFailure();
	const { writer, revision } = state.parse(admitted);
	return `-c allauth.project_engine_writer=${writer} -c allauth.project_engine_project_id=${id} -c allauth.project_engine_writer_revision=${revision}`;
}

/**
 * Fence operations and compare-and-set switches for one trusted internal project.
 * Use a dedicated lease pool shared by nested direct and hosted calls, and tag
 * each engine's mutation pool with the admitted project, writer and revision.
 */
export function createProjectEngineWriterLease(options: Options) {
	const { database, selectedProjectId } = options;
	const project = Object.freeze({ ...options.project });
	if (
		!projectId.test(selectedProjectId) ||
		project.id !== selectedProjectId ||
		project.workspaceId !== platformWorkspaceId ||
		project.environment !== "development" ||
		project.schemaName !==
			`allauth_project_${selectedProjectId.replaceAll("-", "")}`
	)
		throw scopeFailure();

	async function read(client: PoolClient) {
		const { rows } = await client.query<{
			id: string;
			schemaName: string;
			workspaceId: string;
			environment: string;
			protected: boolean;
			writer: string;
			revision: number;
			webhookGuardReady: boolean;
		}>(
			`SELECT p.id, p."schemaName", p."workspaceId", p.environment, w.protected,
			 COALESCE(f.writer,'legacy') AS writer, COALESCE(f.revision,0) AS revision,
			 CASE WHEN f.writer='allauth' THEN EXISTS (
			   SELECT 1 FROM pg_catalog.pg_trigger t
			   WHERE t.tgrelid=pg_catalog.to_regclass(pg_catalog.format('%I.%I',p."schemaName",'allauthWebhookEndpoint'))
			     AND t.tgname='allauth_project_engine_writer' AND t.tgenabled IN ('O','A')
			     AND t.tgfoid=pg_catalog.to_regprocedure('public.allauth_guard_project_engine_write()')
			 ) ELSE TRUE END AS "webhookGuardReady"
			 FROM public."allauthProject" p
			 JOIN public."allauthWorkspace" w ON w.id=p."workspaceId"
			 LEFT JOIN public."allauthProjectEngineWriter" f ON f."projectId"=p.id
			 WHERE p.id=$1`,
			[project.id],
		);
		const binding = rows[0];
		if (
			!binding ||
			binding.id !== project.id ||
			binding.schemaName !== project.schemaName ||
			binding.workspaceId !== project.workspaceId ||
			binding.environment !== "development" ||
			binding.protected !== true
		)
			throw scopeFailure();
		if (!binding.webhookGuardReady)
			throw failure(
				"ALLAUTH_PROJECT_WRITER_GUARD_MISSING",
				"The active project writer is missing its webhook endpoint guard.",
			);
		return state.parse({ writer: binding.writer, revision: binding.revision });
	}

	function nested() {
		const current = activeLease.getStore();
		if (!current) return;
		if (
			current.database !== database ||
			current.projectId !== project.id ||
			!current.accepting
		)
			throw failure(
				"ALLAUTH_PROJECT_WRITER_NESTING_FORBIDDEN",
				"A nested project operation must reuse its active realm writer lease.",
			);
		current.lease.signal.throwIfAborted();
		return current;
	}

	function checkExpected(
		lease: ProjectEngineWriterState,
		expected: ProjectEngineWriter | undefined,
	) {
		if (expected !== undefined && lease.writer !== expected)
			throw failure(
				"ALLAUTH_PROJECT_WRITER_MISMATCH",
				"The requested project engine is not the authoritative writer.",
			);
	}

	async function shared<Result>(
		expected: ProjectEngineWriter | undefined,
		work: (lease: ProjectEngineWriterLease) => Promise<Result>,
	) {
		const current = nested();
		if (current) {
			checkExpected(current.lease, expected);
			const operation = Promise.resolve().then(() => work(current.lease));
			current.pending.add(operation);
			void operation.then(
				() => current.pending.delete(operation),
				() => current.pending.delete(operation),
			);
			return operation;
		}
		return transaction(database, async (client, signal) => {
			await client.query(
				"SELECT pg_advisory_xact_lock_shared(public.allauth_project_engine_admission_key($1))",
				[project.id],
			);
			await client.query(
				"SELECT pg_advisory_xact_lock_shared(public.allauth_project_engine_writer_key($1))",
				[project.id],
			);
			const lease = Object.freeze({ ...(await read(client)), signal });
			checkExpected(lease, expected);
			const context: ActiveLease = {
				database,
				projectId: project.id,
				lease,
				accepting: true,
				pending: new Set(),
			};
			return activeLease.run(context, async () => {
				try {
					return await work(lease);
				} finally {
					context.accepting = false;
					await Promise.allSettled(context.pending);
				}
			});
		});
	}

	return {
		/** Read the authoritative writer while holding the same shared lease as an operation. */
		read() {
			return shared(undefined, async ({ writer, revision }) => ({
				writer,
				revision,
			}));
		},
		/** Use the current writer and revision for the whole leased operation. */
		withCurrent<Result>(
			work: (lease: ProjectEngineWriterLease) => Promise<Result>,
		) {
			return shared(undefined, work);
		},
		/** Run a complete realm operation with its expected authoritative writer. */
		run<Result>(
			expected: ProjectEngineWriter,
			work: (lease: ProjectEngineWriterLease) => Promise<Result>,
		) {
			return shared(writer.parse(expected), work);
		},
		/** Wait for in-flight realm operations and atomically replace the expected writer revision. */
		async switch(
			expected: ProjectEngineWriterState,
			next: ProjectEngineWriter,
		) {
			const previous = state.parse(expected);
			const selected = writer.parse(next);
			if (activeLease.getStore())
				throw failure(
					"ALLAUTH_PROJECT_WRITER_SWITCH_IN_LEASE",
					"A project writer cannot switch during a leased operation.",
				);
			return transaction(database, async (client) => {
				try {
					const { rows } = await client.query<ProjectEngineWriterState>(
						"SELECT writer,revision FROM public.allauth_switch_project_engine_writer($1,$2,$3,$4)",
						[project.id, previous.writer, previous.revision, selected],
					);
					return state.parse(rows[0]);
				} catch (error) {
					if (error && typeof error === "object" && "code" in error) {
						if (error.code === "AU001") throw scopeFailure();
						if (error.code === "AU002")
							throw failure(
								"ALLAUTH_PROJECT_WRITER_REVISION_CONFLICT",
								"The project writer changed before this switch.",
							);
					}
					throw error;
				}
			});
		},
	};
}
