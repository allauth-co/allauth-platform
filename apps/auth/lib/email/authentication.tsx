import { Text } from "@react-email/components";
import type { ApplicationBranding } from "../branding/types";
import { EmailAction, EmailCode, EmailLayout, emailMutedTextStyle, emailTextStyle } from "./layout";

/** Render account links, authentication codes, and security notices in the selected brand. */
export function authenticationEmail({ title, description, url, code, actionLabel = "Continue", branding }: {
	title: string;
	description: string;
	url?: string;
	code?: string;
	actionLabel?: string;
	branding?: ApplicationBranding | null;
}) {
	return <EmailLayout title={title} branding={branding} footer={<Text style={emailMutedTextStyle}>If you did not request this email, you can ignore it. Never share a verification code.</Text>}>
		<Text style={emailTextStyle}>{description}</Text>
		{url && <EmailAction url={url} label={actionLabel} branding={branding} />}
		{code && <EmailCode code={code} />}
	</EmailLayout>;
}
