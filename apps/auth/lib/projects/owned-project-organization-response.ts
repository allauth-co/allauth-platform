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
) {
	return organizationJson({ code, message }, status);
}
