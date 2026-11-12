import type { DBAdapter } from "@better-auth/core/db/adapter";
import type { Kysely } from "kysely";

/** Outcomes deliberately exclude arbitrary endpoint response bodies. */
export type ControlOutcome = "success" | "failure" | "blocked";

/** A normalized, credential-free identity audit event. */
export interface ControlEvent {
	id: string;
	type: string;
	outcome: ControlOutcome;
	actorId?: string;
	userId?: string;
	organizationId?: string;
	clientId?: string;
	targetId?: string;
	ipAddress?: string;
	userAgent?: string;
	createdAt: string;
	metadata: Record<string, unknown>;
}

/** Server-owned event input; caller-controlled request bodies must never be passed wholesale. */
export interface ControlEventInput extends Omit<ControlEvent, "id" | "createdAt" | "metadata"> {
	id?: string;
	createdAt?: Date;
	metadata?: Record<string, unknown>;
}

export interface ControlEventFilters {
	scope: "admin" | "organization" | "user";
	organizationId?: string;
	userId?: string;
	type?: string;
	outcome?: ControlOutcome;
	from?: string;
	to?: string;
	q?: string;
	limit: number;
	offset: number;
}

export interface ControlEventsResponse {
	events: ControlEvent[];
	total: number;
	limit: number;
	offset: number;
	retentionDays: number;
}

export interface ControlOverview {
	totals: { users: number; organizations: number; applications: number; activeSessions: number; mfaUsers: number };
	today: { signIns: number; failedSignIns: number; signUps: number; blockedRequests: number };
	series: { date: string; signIns: number; failedSignIns: number; signUps: number }[];
	recentEvents: ControlEvent[];
	retentionDays: number;
}

/** Safe session attributes: the underlying session token is never selected or returned. */
export interface ControlSession {
	id: string;
	userId: string;
	name: string;
	email: string;
	createdAt: string;
	expiresAt: string;
	ipAddress?: string;
	userAgent?: string;
	impersonatedBy?: string;
}

export interface ControlSessionsResponse {
	sessions: ControlSession[];
	total: number;
	limit: number;
	offset: number;
}

export interface ControlPrincipal {
	session: { id: string; userId: string; impersonatedBy?: string };
	user: { id: string; name: string; email: string; emailVerified: boolean; role?: string; banned?: boolean };
}

export type ControlDatabase = Kysely<Record<string, Record<string, unknown>>>;

/** PostgreSQL is optional for audit hooks, required for indexed dashboard analytics/search. */
export interface AllauthControlOptions {
	project?: boolean;
	database?: ControlDatabase;
	secret?: string;
	baseURL?: string;
	ipHeader?: "x-real-ip" | "cf-connecting-ip";
	requireTrustedIP?: boolean;
	retentionDays?: number;
	/** Trusted server-side registry may authorize a fresh root session for this workspace-owned realm only. */
	authorizeAdmin?: (headers: Headers) => Promise<ControlPrincipal | null>;
	onRevokeUser?: (adapter: DBAdapter, userId: string) => Promise<void>;
	onVerifiedNewDevice?: (user: { id: string; name: string; email: string }, context: { ipAddress?: string; userAgent?: string }) => Promise<void>;
}
