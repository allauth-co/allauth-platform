/** The gateway marks the exact verified requests eligible for a larger signed OAuth form. */
export const hostedSocialSignInRequests = new WeakSet<Request>();
export const hostedPasswordSignInRequests = new WeakSet<Request>();
export const hostedOAuthBrowserActionRequests = new WeakSet<Request>();
