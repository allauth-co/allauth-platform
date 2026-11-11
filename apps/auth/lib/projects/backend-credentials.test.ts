import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { WorkspaceDatabase } from "../workspaces/authorization";
import { backendCredentialRepository } from "./backend-credentials";

describe("project backend credentials", () => {
	it("stores only a hash and binds each verification to exact environment, scope, expiry and revocation", async () => {
		const query = vi.fn().mockResolvedValue({
			rows: [{ id: "credential-id", scope: "directory:read", version: 1 }],
		});
		const repository = backendCredentialRepository({
			query,
		} as unknown as WorkspaceDatabase);
		const result = await repository.create("project-a", "actor-a", {
			name: "StratPlan workers",
		});
		expect(result.key).toMatch(/^aabk_[a-f0-9-]{36}_[\w-]{43}$/);
		const values = query.mock.calls[0][1] as unknown[];
		expect(values).not.toContain(result.key);
		expect(values[3]).toBe(
			createHash("sha256").update(result.key).digest("hex"),
		);
		await repository.authorize(
			"project-a",
			new Headers({ "allauth-backend-key": result.key }),
		);
		expect(query.mock.calls[1][0]).toContain(
			'"revokedAt" IS NULL AND "expiresAt">NOW()',
		);
		expect(query.mock.calls[1][1]).toEqual(["project-a", values[3]]);
		query.mockResolvedValueOnce({ rows: [] });
		await expect(
			repository.authorize(
				"project-b",
				new Headers({ "allauth-backend-key": result.key }),
			),
		).rejects.toMatchObject({ statusCode: 401 });
		await expect(
			repository.authorize(
				"project-a",
				new Headers({ authorization: `Bearer ${result.key}` }),
			),
		).rejects.toMatchObject({ statusCode: 401 });
	});
	it("rejects unsupported scopes and never returns hashes in credential listings", async () => {
		const query = vi.fn().mockResolvedValue({ rows: [] });
		const repository = backendCredentialRepository({
			query,
		} as unknown as WorkspaceDatabase);
		await expect(
			repository.create("project-a", "actor-a", {
				name: "Unauthorized",
				scope: "admin",
			}),
		).rejects.toThrow();
		expect(query).not.toHaveBeenCalled();
		await repository.list("project-a");
		expect(query.mock.calls[0][0]).not.toContain('"keyHash"');
		await expect(
			repository.revoke("project-a", "11111111-1111-4111-8111-111111111111"),
		).rejects.toMatchObject({ statusCode: 404 });
	});
});
