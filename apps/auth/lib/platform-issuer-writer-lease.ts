// cspell:ignore xact
import type { Pool } from "pg";

export type PlatformIssuerWriterState =
	| { writer: "legacy"; revision: number }
	| { writer: "allauth"; revision: number };

type Database = Pick<Pool, "query">;

function validatedState(state: PlatformIssuerWriterState | undefined) {
	if (
		!state ||
		!["legacy", "allauth"].includes(state.writer) ||
		!Number.isSafeInteger(state.revision) ||
		state.revision < 0 ||
		state.revision > 2_147_483_647 ||
		(state.revision === 0 && state.writer !== "legacy")
	)
		throw new Error("The shared issuer writer state is unavailable.");
	return state;
}

/** Read the authoritative revision from an already migrated public issuer store. */
export async function readPlatformIssuerWriter(
	database: Database,
): Promise<PlatformIssuerWriterState> {
	const { rows } = await database.query<PlatformIssuerWriterState>(
		`SELECT writer,revision FROM public."allauthPlatformIssuerWriter" WHERE singleton`,
	);
	return validatedState(rows[0]);
}

/** Apply the admitted revision to a dedicated native pool's PostgreSQL startup options. */
export function platformIssuerWriterConnectionOptions(
	state: PlatformIssuerWriterState,
) {
	const { writer, revision } = validatedState(state);
	return `-c allauth.platform_issuer_writer=${writer} -c allauth.platform_issuer_writer_revision=${revision}`;
}

/** Tag each protocol mutation transaction or give a native pool equivalent startup settings. */
export async function tagPlatformIssuerWriter(
	database: Database,
	state: PlatformIssuerWriterState,
) {
	const { writer, revision } = validatedState(state);
	await database.query(
		`SELECT set_config('allauth.platform_issuer_writer',$1,true),
		        set_config('allauth.platform_issuer_writer_revision',$2,true)`,
		[writer, String(revision)],
	);
}

/** Hold admission on a dedicated pool so a multi-transaction protocol request cannot straddle a switch. */
export async function withPlatformIssuerWriterLease<T>(
	database: Pick<Pool, "connect">,
	operation: (
		state: PlatformIssuerWriterState,
		signal: AbortSignal,
	) => Promise<T>,
): Promise<T> {
	const client = await database.connect();
	const controller = new AbortController();
	let discard = false;
	const disconnected = () => {
		discard = true;
		controller.abort(new Error("The shared issuer writer lease was lost."));
	};
	client.on("error", disconnected);
	client.on("end", disconnected);
	try {
		await client.query("BEGIN ISOLATION LEVEL READ COMMITTED");
		await client.query(
			"SELECT pg_advisory_xact_lock_shared(public.allauth_platform_issuer_admission_key())",
		);
		const state = await readPlatformIssuerWriter(client);
		controller.signal.throwIfAborted();
		const result = await operation(state, controller.signal);
		controller.signal.throwIfAborted();
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
