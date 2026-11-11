/** Public commercial terms shared by the service and marketing pages. */
export const proMonthlyPriceUsd = 9.99;
export const proMonthlyPriceCents = 999;
export const freeOrganizationMemberLimit = 20;
export const freeMonthlyImpersonations = 5;
export const renewalGraceDays = 7;

export const commercialPlans = {
	free: { id: "free", name: "Free", monthlyPriceUsd: 0, showPoweredBy: true, organizationMemberLimit: freeOrganizationMemberLimit, monthlyImpersonationLimit: freeMonthlyImpersonations },
	pro: { id: "pro", name: "Pro", monthlyPriceUsd: proMonthlyPriceUsd, showPoweredBy: false, organizationMemberLimit: null, monthlyImpersonationLimit: null },
	selfHosted: { id: "self-hosted", name: "Self-hosted", monthlyPriceUsd: 0, showPoweredBy: false, organizationMemberLimit: null, monthlyImpersonationLimit: null },
} as const;

export type CommercialPlanId = (typeof commercialPlans)[keyof typeof commercialPlans]["id"];
