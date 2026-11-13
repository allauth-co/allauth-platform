/** A public console rejection that the HTTP boundary serializes without leaking internal errors. */
export class ConsoleRequestError extends Error {
	constructor(
		readonly statusCode: 400 | 401 | 403 | 404,
		message?: string,
	) {
		super(message);
	}
}
