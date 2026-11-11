/** Dated primary-source observations for public comparisons. Recheck before republishing. */
export const competitorCheckedAt = "2026-11-11";

export const competitors = {
	clerk: {
		name: "Clerk", pricingUrl: "https://clerk.com/pricing",
		priceSummary: "Pro starts at $25/month on monthly billing, or $20/month billed annually. Enhanced B2B and Administration each add $100/month on monthly billing. All plans include unlimited applications; usage charges may apply.",
		freeSummary: "Includes up to 20 members per organization and five impersonations per month.",
		strength: "A broad SDK and prebuilt component ecosystem, established hosted operations, and optional enterprise and advanced protection features.",
		tradeoff: "For a small SaaS needing larger organizations and frequent support impersonation, compare the relevant add-ons as well as the base plan.",
		migration: "Replace Clerk components and server session checks, map organization roles, configure providers and callbacks, and plan a deliberate user migration. Existing sessions do not transfer automatically.",
	},
	auth0: {
		name: "Auth0", pricingUrl: "https://auth0.com/pricing",
		priceSummary: "Essentials starts at $35/month for B2C or $150/month for B2B at 500 monthly active users. Select the use case and MAU tier before comparing.",
		freeSummary: "The published Free tier includes up to 25,000 monthly active users and five organizations.",
		strength: "A mature identity platform with a broad language ecosystem, enterprise identity integrations, and higher-tier support and SLA options.",
		tradeoff: "Its B2B and B2C plans serve different needs. The B2C entry price is not an equivalent quote for a B2B organization deployment.",
		migration: "Inventory applications, connections, Actions, claims and organization mappings. Validate equivalent flows and a user migration path before changing the issuer or production callbacks.",
	},
	supabase: {
		name: "Supabase", pricingUrl: "https://supabase.com/pricing",
		priceSummary: "Pro starts at $25/month for a backend platform, including the first project. Additional projects start at $10/month, with separate resource and usage pricing.",
		freeSummary: "The Free tier includes 50,000 monthly active users and two active projects; inactive free projects can pause.",
		strength: "Authentication alongside PostgreSQL, storage, realtime and functions, with an established self-hosting option. Particularly useful when you also need the backend stack.",
		tradeoff: "The $25 buys a broader backend platform. AllAuth is a focused authentication service; replacing Supabase Auth also requires checking row-level security and JWT dependencies.",
		migration: "Review JWT claims, database policies, auth triggers and account linking. Move identity deliberately and test database authorization before replacing Supabase sessions.",
	},
} as const;

export type CompetitorSlug = keyof typeof competitors;
