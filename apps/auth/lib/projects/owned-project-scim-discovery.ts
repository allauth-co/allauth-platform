export const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User";
export const scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group";
export const scimEnterpriseUserSchema =
	"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const schemaPrefix = "urn:ietf:params:scim:schemas:core:2.0:";
const messagePrefix = "urn:ietf:params:scim:api:messages:2.0:";
const discoveryPath = "/scim/v2/";

function attribute(name: string, description: string) {
	return {
		name,
		description,
		multiValued: false,
		required: false,
		mutability: "readWrite",
		returned: "default",
	};
}

function stringAttribute(
	name: string,
	description: string,
	options: {
		required?: boolean;
		mutability?: "readOnly" | "immutable";
		uniqueness?: "server";
		canonicalValues?: string[];
	} = {},
) {
	return {
		...attribute(name, description),
		type: "string",
		caseExact: false,
		uniqueness: "none",
		...options,
	};
}

function referenceAttribute(
	description: string,
	mutability: "readWrite" | "immutable",
) {
	return {
		...attribute("$ref", description),
		type: "reference",
		referenceTypes: ["User"],
		caseExact: false,
		mutability,
		uniqueness: "none",
	};
}

function booleanAttribute(name: string, description: string) {
	return { ...attribute(name, description), type: "boolean" };
}

function complexAttribute(
	name: string,
	description: string,
	subAttributes: object[],
	multiValued = false,
) {
	return {
		...attribute(name, description),
		type: "complex",
		multiValued,
		subAttributes,
		uniqueness: "none",
	};
}

const typeAndPrimary = [
	stringAttribute("type", "A label indicating the attribute's function."),
	booleanAttribute(
		"primary",
		"Whether this is the primary value for the attribute.",
	),
];

function schema(
	id: string,
	name: string,
	description: string,
	attributes: object[],
) {
	return {
		id,
		schemas: [`${schemaPrefix}Schema`],
		name,
		description,
		attributes,
		meta: { resourceType: "Schema", location: `${discoveryPath}Schemas/${id}` },
	};
}

const schemas = [
	schema(scimUserSchema, "User", "User Account", [
		stringAttribute(
			"userName",
			"Unique identifier for the User within its provisioning connection.",
			{
				required: true,
				uniqueness: "server",
			},
		),
		stringAttribute(
			"displayName",
			"The name of the User, suitable for display to end-users.",
		),
		booleanAttribute(
			"active",
			"A Boolean value indicating the User's administrative status.",
		),
		complexAttribute("name", "The components of the User's real name.", [
			stringAttribute("formatted", "The complete formatted name."),
			stringAttribute("givenName", "The given name of the User."),
			stringAttribute("familyName", "The family name of the User."),
			stringAttribute("middleName", "The middle name of the User."),
			stringAttribute("honorificPrefix", "The honorific prefix of the User."),
			stringAttribute("honorificSuffix", "The honorific suffix of the User."),
		]),
		complexAttribute(
			"emails",
			"Email addresses for the User.",
			[
				stringAttribute("value", "Email address for the User.", {
					required: true,
				}),
				...typeAndPrimary,
			],
			true,
		),
		stringAttribute("title", "The User's title."),
		stringAttribute("userType", "The User's relationship to the organization."),
		stringAttribute(
			"preferredLanguage",
			"The User's preferred written or spoken language.",
		),
		stringAttribute("locale", "The User's default location."),
		stringAttribute("timezone", "The User's time zone."),
		complexAttribute(
			"phoneNumbers",
			"Phone numbers for the User.",
			[
				stringAttribute("value", "Phone number for the User.", {
					required: true,
				}),
				...typeAndPrimary,
			],
			true,
		),
		complexAttribute(
			"addresses",
			"Postal addresses for the User.",
			[
				stringAttribute("formatted", "The complete formatted address."),
				stringAttribute("streetAddress", "The full street address."),
				stringAttribute("locality", "The city or locality."),
				stringAttribute("region", "The state or region."),
				stringAttribute("postalCode", "The postal code."),
				stringAttribute("country", "The country."),
				...typeAndPrimary,
			],
			true,
		),
		complexAttribute(
			"roles",
			"Roles for the User.",
			[
				stringAttribute("value", "The role value.", { required: true }),
				stringAttribute("display", "A human-readable role name."),
				...typeAndPrimary,
			],
			true,
		),
		complexAttribute(
			"entitlements",
			"Entitlements for the User.",
			[
				stringAttribute("value", "The entitlement value.", { required: true }),
				stringAttribute("display", "A human-readable entitlement name."),
				...typeAndPrimary,
			],
			true,
		),
	]),
	schema(scimEnterpriseUserSchema, "EnterpriseUser", "Enterprise User", [
		stringAttribute("employeeNumber", "A number assigned to the User."),
		stringAttribute("costCenter", "The User's cost center."),
		stringAttribute("organization", "The User's organization."),
		stringAttribute("division", "The User's division."),
		stringAttribute("department", "The User's department."),
		complexAttribute("manager", "The User's manager.", [
			stringAttribute("value", "The manager's identifier."),
			referenceAttribute(
				"The URI of the manager's SCIM User resource.",
				"readWrite",
			),
			stringAttribute("displayName", "The manager's display name.", {
				mutability: "readOnly",
			}),
		]),
	]),
	schema(scimGroupSchema, "Group", "Group", [
		stringAttribute("displayName", "A human-readable name for the Group.", {
			required: true,
			uniqueness: "server",
		}),
		complexAttribute(
			"members",
			"A list of members of the Group.",
			[
				stringAttribute("value", "Identifier of the member of this Group.", {
					required: true,
					mutability: "immutable",
				}),
				referenceAttribute(
					"The URI corresponding to a SCIM member resource.",
					"immutable",
				),
				stringAttribute("display", "A human-readable name for the member.", {
					mutability: "readOnly",
				}),
				stringAttribute(
					"type",
					"A label indicating the member resource type.",
					{ canonicalValues: ["User"], mutability: "immutable" },
				),
			],
			true,
		),
	]),
];

const resourceTypes = (["User", "Group"] as const).map((name) => ({
	schemas: [`${schemaPrefix}ResourceType`],
	id: name,
	name,
	endpoint: `/${name}s`,
	description: name === "User" ? "User Account" : "Group",
	schema: `${schemaPrefix}${name}`,
	...(name === "User"
		? {
				schemaExtensions: [
					{ schema: scimEnterpriseUserSchema, required: false },
				],
			}
		: {}),
	meta: {
		resourceType: "ResourceType",
		location: `${discoveryPath}ResourceTypes/${name}`,
	},
}));

export function ownedSCIMResponse(body: object, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			"Content-Type": "application/scim+json",
			"Cache-Control": "no-store",
			Pragma: "no-cache",
			...(status === 401 ? { "WWW-Authenticate": 'Bearer realm="SCIM"' } : {}),
		},
	});
}

export function ownedSCIMError(status: number, detail: string): Response {
	return ownedSCIMResponse(
		{ schemas: [`${messagePrefix}Error`], status: String(status), detail },
		status,
	);
}

export function ownedSCIMList(
	Resources: object[],
	totalResults = Resources.length,
	startIndex = 1,
) {
	return {
		schemas: [`${messagePrefix}ListResponse`],
		totalResults,
		startIndex,
		itemsPerPage: Resources.length,
		Resources,
	};
}

function decodedIdentifier(value: string) {
	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}

/** Serves the public SCIM discovery contract for a server-selected project auth URL. */
export function createOwnedProjectSCIMDiscovery(baseURL: string) {
	const url = new URL(baseURL);
	if (
		!/^https?:$/.test(url.protocol) ||
		url.username ||
		url.password ||
		url.search ||
		url.hash
	)
		throw new Error("Invalid project SCIM auth URL.");
	const basePath = url.pathname.replace(/\/+$/, "");
	const prefix = `${basePath}${discoveryPath}`;
	const location = (path: string) =>
		new URL(path.replace(/^\/+/, ""), `${url.origin}${basePath}/`).toString();
	const describe = <T extends { meta: { location: string } }>(resource: T) => ({
		...resource,
		meta: { ...resource.meta, location: location(resource.meta.location) },
	});
	const schemaResources = schemas.map(describe);
	const typeResources = resourceTypes.map(describe);

	return function discovery(request: Request): Response | null {
		const pathname = new URL(request.url).pathname;
		if (request.method !== "GET" || !pathname.startsWith(prefix)) return null;
		const route = pathname.slice(prefix.length);
		if (route === "ServiceProviderConfig") {
			return ownedSCIMResponse({
				schemas: [`${schemaPrefix}ServiceProviderConfig`],
				patch: { supported: true },
				bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
				filter: { supported: true, maxResults: 100 },
				changePassword: { supported: false },
				sort: { supported: false },
				etag: { supported: false },
				authenticationSchemes: [
					{
						name: "OAuth Bearer Token",
						description:
							"Authentication using a bearer token in the Authorization header.",
						specUri: "https://www.rfc-editor.org/info/rfc6750",
						type: "oauthbearertoken",
						primary: true,
					},
				],
				meta: {
					resourceType: "ServiceProviderConfig",
					location: location(`${discoveryPath}ServiceProviderConfig`),
				},
			});
		}
		const [collection, id, extra] = route.split("/");
		if (extra !== undefined) return null;
		const resources =
			collection === "Schemas"
				? schemaResources
				: collection === "ResourceTypes"
					? typeResources
					: null;
		if (!resources) return null;
		if (id === undefined) return ownedSCIMResponse(ownedSCIMList(resources));
		if (id === "") return null;
		const identifier = collection === "Schemas" ? decodedIdentifier(id) : id;
		const resource = resources.find((item) => item.id === identifier);
		return resource
			? ownedSCIMResponse(resource)
			: ownedSCIMError(
					404,
					collection === "Schemas"
						? "Schema not found"
						: "Resource type not found",
				);
	};
}
