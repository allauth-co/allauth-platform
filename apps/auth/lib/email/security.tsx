import { Text } from "@react-email/components";
import type { ApplicationBranding } from "../branding/types";
import { emailBranding } from "./branding";
import { EmailAction, EmailCode, EmailLayout, emailMutedTextStyle, emailTextStyle } from "./layout";

/** Build the branded account verification email. */
export function reactVerificationEmail({ username, verificationUrl, branding }: { username: string; verificationUrl: string; branding?: ApplicationBranding | null }) {
	const brand = emailBranding(branding);
	return <EmailLayout title={`Verify your ${brand.name} email address`} branding={branding} footer={<Text style={emailMutedTextStyle}>If you did not request this email, you can ignore it.</Text>}>
		<Text style={emailTextStyle}>Hello {username},</Text>
		<Text style={emailTextStyle}>Confirm your email address to verify your {brand.name} account.</Text>
		<EmailAction url={verificationUrl} label="Verify email" branding={branding} />
	</EmailLayout>;
}

/** Build the branded two-factor verification code email. */
export function reactTwoFactorEmail({ username, otp, branding }: { username: string; otp: string; branding?: ApplicationBranding | null }) {
	const brand = emailBranding(branding);
	return <EmailLayout title={`Your ${brand.name} verification code`} branding={branding} footer={<Text style={emailMutedTextStyle}>If you did not try to sign in, you can ignore this email.</Text>}>
		<Text style={emailTextStyle}>Hello {username},</Text>
		<Text style={emailTextStyle}>Use this code to finish signing in. Do not share this code with anyone.</Text>
		<EmailCode code={otp} />
	</EmailLayout>;
}
