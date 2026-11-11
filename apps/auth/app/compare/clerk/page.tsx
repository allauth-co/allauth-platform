import { CompetitorPage } from "@/components/marketing/competitor-page";
import { publicSdkMetadata } from "@/lib/public-sdk";
export const metadata = publicSdkMetadata("AllAuth vs Clerk — compare pricing, organizations and impersonation", "Compare AllAuth Pro at $9.99 USD per workspace with Clerk's base plans and B2B and Administration add-ons. Dated prices, clear tradeoffs and migration considerations.", "/compare/clerk");
export default function Page() { return <CompetitorPage slug="clerk" />; }
