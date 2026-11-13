const auditErrorCodes = new WeakMap<Response, string>();

export function organizationJson(
	value: unknown,
	status = 200,
	headers = new Headers(),
) {
	headers.set("Cache-Control", "no-store");
	headers.set("Pragma", "no-cache");
	return Response.json(value, { status, headers });
}

export function organizationFailure(
	status: number,
	code: string,
	message: string,
	auditErrorCode?: string,
) {
	const response = organizationJson({ code, message }, status);
	if (auditErrorCode) auditErrorCodes.set(response, auditErrorCode);
	return response;
}

export function organizationValidationFailure(
	message = "Invalid organization request.",
) {
	return organizationFailure(400, "BAD_REQUEST", message, "VALIDATION_ERROR");
}

export function organizationAuditErrorCode(response: Response) {
	return auditErrorCodes.get(response);
}
