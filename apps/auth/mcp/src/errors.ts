const publicErrors = new WeakSet<Error>();

/** Mark only application-authored messages that are safe to return to an MCP or CLI user. */
export function publicError(message: string): Error {
	const error = new Error(message);
	publicErrors.add(error);
	return error;
}

/** Untrusted transport, parsing, and service errors have no public message. */
export function publicErrorMessage(error: unknown): string | undefined {
	return error instanceof Error && publicErrors.has(error) ? error.message : undefined;
}
