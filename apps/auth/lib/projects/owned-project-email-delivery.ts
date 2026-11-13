/** Reserve delivery before issuance, and release it only after the request has persisted its proof. */
export async function scheduleOwnedEmailDelivery(
	defer: (work: () => Promise<void>) => void,
	prepare: () => Promise<(() => Promise<void>) | null>,
	onFailure: () => void,
) {
	const prepared = Promise.withResolvers<(() => Promise<void>) | null>();
	try {
		defer(async () => {
			const deliver = await prepared.promise;
			if (!deliver) return;
			try {
				await deliver();
			} catch {
				onFailure();
			}
		});
	} catch {
		prepared.resolve(null);
		return false;
	}
	let delivery: (() => Promise<void>) | null = null;
	try {
		delivery = await prepare();
		return true;
	} finally {
		prepared.resolve(delivery);
	}
}
