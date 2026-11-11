import { CompetitorPage } from "@/components/marketing/competitor-page";
import { publicSdkMetadata } from "@/lib/public-sdk";
export const metadata = publicSdkMetadata("AllAuth vs Auth0 — compare hosted authentication pricing", "Compare AllAuth's $9.99 USD workspace plan with Auth0's B2B and B2C pricing. Understand MAU tiers, enterprise capabilities and migration considerations.", "/compare/auth0");
export default function Page() { return <CompetitorPage slug="auth0" />; }
