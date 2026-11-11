import { CompetitorPage } from "@/components/marketing/competitor-page";
import { publicSdkMetadata } from "@/lib/public-sdk";
export const metadata = publicSdkMetadata("AllAuth vs Supabase Auth — authentication or a full backend?", "Compare AllAuth's focused $9.99 USD authentication plan with Supabase's broader backend platform. Review included services, project costs and JWT migration tradeoffs.", "/compare/supabase");
export default function Page() { return <CompetitorPage slug="supabase" />; }
