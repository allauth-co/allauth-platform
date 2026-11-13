/** The gateway marks verified hosted requests eligible to carry longer signed OAuth continuations. */
export const hostedSocialSignInRequests = new WeakSet<Request>();
export const hostedPasswordSignInRequests = new WeakSet<Request>();
export const hostedOAuthBrowserActionRequests = new WeakSet<Request>();
export const hostedVerificationLinkRequests = new WeakSet<Request>();
