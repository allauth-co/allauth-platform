import { Text } from "@react-email/components";
import type { ApplicationBranding } from "../branding/types";
import { emailBranding } from "./branding";
import { EmailAction, EmailLayout, emailMutedTextStyle, emailTextStyle } from "./layout";

interface ResetPasswordEmailProps {
	username?: string;
	resetLink?: string;
	branding?: ApplicationBranding | null;
}

/** Render a password reset without leaking framework branding into account mail. */
export const ResetPasswordEmail = ({ username, resetLink, branding }: ResetPasswordEmailProps) => {
	const brand = emailBranding(branding);
	return <EmailLayout title={`Reset your ${brand.name} password`} branding={branding} footer={<Text style={emailMutedTextStyle}>If you did not request a password reset, you can ignore this email. Contact support if you have concerns.</Text>}>
		<Text style={emailTextStyle}>Hello{username ? ` ${username}` : ""},</Text>
		<Text style={emailTextStyle}>We received a request to reset the password for your {brand.name} account. Follow the link to choose a new password.</Text>
		{resetLink && <EmailAction url={resetLink} label="Reset password" branding={branding} />}
	</EmailLayout>;
};

/** Build the password reset email. */
export function reactResetPasswordEmail(props: ResetPasswordEmailProps) {
	return <ResetPasswordEmail {...props} />;
}
