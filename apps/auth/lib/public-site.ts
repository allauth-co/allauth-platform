export const publicSiteOrigin = "https://allauth.co";
export const sdkRepositoryUrl = "https://github.com/thegarty/allauth-sdk";
export const platformRepositoryUrl = "https://github.com/thegarty/allauth-platform";
export const commercialPublicPaths = ["/pricing", "/self-host", "/compare", "/compare/clerk", "/compare/auth0", "/compare/supabase", "/fair-use"] as const;

/** Public product documentation must render independently of account configuration and sessions. */
export function isPublicProductPath(pathname: string): boolean {
	return pathname === "/" || commercialPublicPaths.some(path => path === pathname) || pathname === "/sdk" || pathname.startsWith("/sdk/") || pathname === "/releases" || pathname.startsWith("/releases/");
}
