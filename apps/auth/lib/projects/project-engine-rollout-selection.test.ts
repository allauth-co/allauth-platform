import { describe, expect, it } from "vitest";
import {
	developmentAgentReplayApprovalsSetting,
	developmentAgentReplayBridgeIdsSetting,
	productionAgentReplayApprovalsSetting,
	productionAgentReplayBridgeIdsSetting,
} from "../../scripts/project-agent-replay-evidence.mjs";
import {
	developmentEncryptedSamlApprovalsSetting,
	developmentProjectEngineRevisionsSetting,
	productionEncryptedSamlApprovalsSetting,
	readProjectEngineRevisions,
	readProjectEngineApprovalValue,
} from "../../scripts/project-engine-rollout-selection.mjs";
import { platformWorkspaceId } from "../workspaces/types";
import {
	internalProjectEngineIdSetting,
	productionProjectEngineRevisionsSetting,
	projectAgentReplayApprovalValue,
	projectAgentReplayBridgeSelected,
	projectEnginePreparationRevision,
	projectEnginePreparedForWriter,
	projectEngineSelected,
	projectSamlApprovalValue,
} from "./project-engine-internal-selection";

const firstId = "2462e18a-4970-4e12-821a-780814a5a0cf";
const secondId = "35473140-86c9-4d76-8410-dc3611e1d522";
const workspaceId = "c72a582e-103b-4b86-aabf-e53ce1ebfd0e";

function binding(id: string) {
	return {
		id,
		workspaceId,
		schemaName: `allauth_project_${id.replaceAll("-", "")}`,
		environment: "production" as const,
		projectEngineFenced: true,
	};
}

describe("project writer rollout selection", () => {
	it("reads only the exact production project approval from a valid map", () => {
		const first = { projectId: firstId, revision: 0 };
		const second = { projectId: secondId, revision: 2 };
		const raw = JSON.stringify({ [firstId]: first, [secondId]: second });
		expect(readProjectEngineApprovalValue(raw, firstId)).toBe(
			JSON.stringify(first),
		);
		expect(readProjectEngineApprovalValue(raw, secondId)).toBe(
			JSON.stringify(second),
		);
		expect(readProjectEngineApprovalValue(raw, workspaceId)).toBe("");
		expect(readProjectEngineApprovalValue(undefined, firstId)).toBe("");
		for (const invalid of [
			"{",
			"[]",
			"null",
			JSON.stringify({ [firstId]: first, "project-slug": second }),
			JSON.stringify({ [firstId]: "receipt" }),
			JSON.stringify({ [firstId]: [] }),
		])
			expect(() => readProjectEngineApprovalValue(invalid, firstId)).toThrow(
				"project approvals are invalid",
			);
	});

	it("separates an enrolled development realm from the production and protected settings", () => {
		const development = {
			...binding(firstId),
			environment: "development" as const,
		};
		const production = binding(secondId);
		const approval = JSON.stringify({ projectId: firstId });
		const map = JSON.stringify({ [firstId]: JSON.parse(approval) });
		const wrong = {
			[internalProjectEngineIdSetting]: firstId,
			[productionProjectEngineRevisionsSetting]: JSON.stringify({
				[firstId]: 1,
				[secondId]: 2,
			}),
			[productionAgentReplayBridgeIdsSetting]: firstId,
			[productionAgentReplayApprovalsSetting]: map,
			[productionEncryptedSamlApprovalsSetting]: map,
		};
		const env = {
			...wrong,
			[developmentProjectEngineRevisionsSetting]: JSON.stringify({
				[firstId]: 3,
			}),
			[developmentAgentReplayBridgeIdsSetting]: firstId,
			[developmentAgentReplayApprovalsSetting]: map,
			[developmentEncryptedSamlApprovalsSetting]: map,
		};
		expect(projectEngineSelected(wrong, development)).toBe(false);
		expect(projectAgentReplayBridgeSelected(development, wrong)).toBe(false);
		expect(projectAgentReplayApprovalValue(development, wrong)).toBe("");
		expect(projectSamlApprovalValue(development, wrong)).toBe("");
		expect(projectEnginePreparationRevision(env, development)).toBe(3);
		expect(projectEnginePreparationRevision(env, production)).toBe(2);
		expect(projectAgentReplayBridgeSelected(development, env)).toBe(true);
		expect(projectAgentReplayApprovalValue(development, env)).toBe(approval);
		expect(projectSamlApprovalValue(development, env)).toBe(approval);
		expect(
			projectEngineSelected(env, {
				...development,
				projectEngineFenced: false,
			}),
		).toBe(false);
		expect(
			projectEngineSelected(env, {
				...development,
				workspaceId: platformWorkspaceId,
			}),
		).toBe(false);
	});

	it("prepares each enrolled production project at its exact configured revision", () => {
		const first = binding(firstId);
		const second = binding(secondId);
		const env = {
			[productionProjectEngineRevisionsSetting]: JSON.stringify({
				[firstId]: 0,
				[secondId]: 2,
			}),
		};
		expect(projectEngineSelected(env, first)).toBe(true);
		expect(projectEngineSelected(env, second)).toBe(true);
		expect(projectEnginePreparationRevision(env, first)).toBe(0);
		expect(projectEnginePreparationRevision(env, second)).toBe(2);
		expect(
			projectEngineSelected(
				{ [productionProjectEngineRevisionsSetting]: "" },
				first,
			),
		).toBe(false);
		for (const invalid of [
			{ ...first, projectEngineFenced: false },
			{ ...first, workspaceId: "invalid-workspace" },
			{ ...first, schemaName: second.schemaName },
			{ ...first, environment: "development" as const },
		]) {
			expect(projectEngineSelected(env, invalid)).toBe(false);
			expect(projectEnginePreparationRevision(env, invalid)).toBeUndefined();
		}
	});

	it("keeps the protected development preparation independent from production", () => {
		const internal = {
			...binding(firstId),
			environment: "development" as const,
			workspaceId: platformWorkspaceId,
			projectEngineFenced: false,
		};
		const env = {
			[internalProjectEngineIdSetting]: firstId,
			ALLAUTH_PROJECT_ENGINE_INTERNAL_PREPARE_REVISION: "4",
			[productionProjectEngineRevisionsSetting]: JSON.stringify({
				[secondId]: 2,
			}),
		};
		expect(projectEngineSelected(env, internal)).toBe(true);
		expect(projectEnginePreparationRevision(env, internal)).toBe(4);
		expect(projectEnginePreparationRevision(env, binding(secondId))).toBe(2);
	});

	it("accepts only the prepared legacy revision for a later active writer", () => {
		const production = binding(firstId);
		const stale = {
			[productionProjectEngineRevisionsSetting]: JSON.stringify({
				[firstId]: 0,
			}),
		};
		const ready = {
			[productionProjectEngineRevisionsSetting]: JSON.stringify({
				[firstId]: 2,
			}),
		};
		expect(
			projectEnginePreparedForWriter(stale, production, {
				revision: 1,
				preparing: false,
			}),
		).toBe(true);
		expect(
			projectEnginePreparedForWriter(stale, production, {
				revision: 3,
				preparing: false,
			}),
		).toBe(false);
		expect(
			projectEnginePreparedForWriter(ready, production, {
				revision: 2,
				preparing: true,
			}),
		).toBe(true);
		expect(
			projectEnginePreparedForWriter(ready, production, {
				revision: 3,
				preparing: false,
			}),
		).toBe(true);
	});

	it("rejects noncanonical project identifiers and invalid revisions as a whole", () => {
		expect(readProjectEngineRevisions(undefined)).toEqual(new Map());
		for (const raw of [
			"[0]",
			"null",
			"{",
			JSON.stringify({ [firstId]: 0, "project-slug": 1 }),
			JSON.stringify({ [firstId.toUpperCase()]: 1 }),
			JSON.stringify({ [firstId]: -1 }),
			JSON.stringify({ [firstId]: 0.5 }),
			JSON.stringify({ [firstId]: "0" }),
			JSON.stringify({ [firstId]: 2147483648 }),
		])
			expect(() => readProjectEngineRevisions(raw)).toThrow(
				"production project preparation revisions",
			);
	});
});
