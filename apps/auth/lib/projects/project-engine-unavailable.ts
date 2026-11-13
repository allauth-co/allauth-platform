const projectWriterUnavailableCode = "ALLAUTH_PROJECT_WRITER_UNAVAILABLE";

export function projectWriterUnavailable() {
	return Object.assign(new Error("The project writer is unavailable."), {
		code: projectWriterUnavailableCode,
	});
}

export function isProjectWriterUnavailable(error: unknown) {
	return error instanceof Error && "code" in error && error.code === projectWriterUnavailableCode;
}
