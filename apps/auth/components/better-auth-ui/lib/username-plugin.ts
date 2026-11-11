// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
import { createAuthPlugin } from "@better-auth-ui/core";
import type { AdditionalField, AuthPluginBase, AuthPluginLocalizationContext } from "@better-auth-ui/core";
import {
	usernamePlugin as coreUsernamePlugin,
	type UsernamePluginOptions,
} from "@better-auth-ui/core/plugins/username";

import { SignInUsername } from "@/components/better-auth-ui/username/sign-in-username";
import { UsernameField } from "@/components/better-auth-ui/username/username-field";

export const usernamePlugin = createAuthPlugin(
	coreUsernamePlugin.id,
	(options: UsernamePluginOptions = {}) => {
		const core = coreUsernamePlugin(options);
		const usernameFields = (fields: AdditionalField[] | undefined) =>
			fields?.map((field) => field.name === "username" ? {
				...field,
				required: false,
				render: UsernameField,
				validateDebounceMs: 0,
				validate(value: unknown) {
					if (value === null || value === undefined || value === "") return;
					if (typeof value !== "string" || !/^[a-zA-Z0-9_.]+$/.test(value))
						throw new Error("Use letters, numbers, underscores or dots for your username.");
					if (value.length < core.minUsernameLength || value.length > core.maxUsernameLength)
						throw new Error(`Use ${core.minUsernameLength}–${core.maxUsernameLength} characters for your username.`);
				},
			} : field);

		return {
			...core,
			additionalFields: usernameFields(core.additionalFields),
			_localizationResolver(plugin: AuthPluginBase, context: AuthPluginLocalizationContext) {
				const localized = core._localizationResolver(plugin, context);
				return { ...localized, additionalFields: usernameFields(localized.additionalFields) };
			},
			views: {
				auth: { signIn: SignInUsername },
			},
		};
	},
);
