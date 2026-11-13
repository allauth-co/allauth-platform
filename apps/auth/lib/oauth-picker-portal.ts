import * as z from "zod";
import { getAuthEnvironment } from "./auth";
import { authOrigin } from "./configuration";
import { withPortalHeadersEngine } from "./domains/hosting";

const id = z.string().min(1).max(256);
const currentSession = z
	.object({ session: z.object({ id, userId: id }), user: z.object({ id }) })
	.nullable();

const accountChoice = z
	.object({
		session: z.object({ id, token: z.string().min(1).max(256) }),
		user: z.object({
			name: z.string(),
			email: z.string(),
			image: z.string().nullish(),
		}),
	})
	.transform(({ session, user }) => ({
		id: session.id,
		sessionToken: session.token,
		name: user.name,
		email: user.email,
		image: user.image ?? null,
	}));

const organizationChoice = z.object({
	id,
	name: z.string(),
	logo: z.string().nullish(),
});

export type OAuthAccountChoice = z.output<typeof accountChoice>;
export type OAuthOrganizationChoice = z.output<typeof organizationChoice>;

interface PickerRead<T> {
	path: "/multi-session/list-device-sessions" | "/organization/list";
	choices: z.ZodType<T[]>;
}

function readPickerChoices<T>(
	incoming: Headers,
	read: PickerRead<T>,
): Promise<T[] | null> {
	return withPortalHeadersEngine(incoming, async (engine, bound, binding) => {
		const origin = binding
			? `https://${binding.hostname}`
			: authOrigin(await getAuthEnvironment());
		const headers = new Headers({ accept: "application/json" });
		for (const name of [
			"cookie",
			"user-agent",
			"x-real-ip",
			"cf-connecting-ip",
		]) {
			const value = bound.get(name);
			if (value) headers.set(name, value);
		}
		const session = await engine.readSession(
			new Request(
				`${origin}/api/auth/get-session?disableCookieCache=true&disableRefresh=true`,
				{ headers },
			),
		);
		if (session.status === 401) return null;
		if (!session.ok) throw new Error("Unable to check the current sign-in.");
		const current = currentSession.parse(await session.json());
		if (!current || current.session.userId !== current.user.id) return null;
		const choices = await engine.dispatch(
			new Request(`${origin}/api/auth${read.path}`, { headers }),
		);
		if (choices.status === 401) return null;
		if (!choices.ok) throw new Error("Unable to load authorization choices.");
		return read.choices.parse(await choices.json());
	});
}

/** Read only the current browser's device accounts through its verified realm. */
export function readPortalOAuthAccounts(headers: Headers) {
	return readPickerChoices(headers, {
		path: "/multi-session/list-device-sessions",
		choices: z.array(accountChoice),
	});
}

/** Read the current user's organizations through the same selected realm. */
export function readPortalOAuthOrganizations(headers: Headers) {
	return readPickerChoices(headers, {
		path: "/organization/list",
		choices: z.array(organizationChoice),
	});
}

export function oauthPickerQuery(
	params: Record<string, string | string[] | undefined>,
) {
	const query = new URLSearchParams();
	for (const [key, value] of Object.entries(params)) {
		if (typeof value === "string") query.append(key, value);
		else if (Array.isArray(value))
			for (const item of value) query.append(key, item);
	}
	return query.toString();
}
