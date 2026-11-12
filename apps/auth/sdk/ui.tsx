"use client";

// Share the provider and context with the main SDK entry point.
export {
	AccountSettings,
	AllAuthProvider,
	AvatarUpload,
	ForgotPassword,
	OrganizationProfile,
	OrganizationProfileModal,
	OrganizationSwitcher,
	ResetPassword,
	SignIn,
	SignUp,
	UserButton,
	UserProfile,
	UserProfileModal,
	useAllAuth,
} from "./react";
export type {
	AccountSettingsProps,
	AllAuthBranding,
	AllAuthCapabilities,
	AllAuthProviderProps,
	AllAuthResolvedBranding,
	AuthAppearance,
	HeaderOrganization,
	OrganizationHeaderProps,
	SignInProps,
	SignUpProps,
} from "./react";
