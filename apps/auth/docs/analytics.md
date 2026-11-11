# Authentication analytics

AllAuth records native **authenticated activity**, rather than app engagement. A completed native sign-in, a valid native `get-session` request, or a successful authenticated native mutation can mark an identity active for a UTC day. Anonymous users, impersonation, and control/admin API requests do not generate activity. Organization activity requires a current member using an active organization or performing an authorized organization action.

Daily activity and actual identity creation/deletion facts live in each realm's PostgreSQL schema. They survive audit-log retention. Repeated polling records one row per identity/day, with bounded source flags and a bounded process cache. No tokens, cookies, passwords, IP addresses, user agents, or profile metadata enter the analytics tables. Deleted identities retain an ID and historical dates/counts; drill-downs return no deleted profile.

## Endpoints

Both endpoints require a fresh, verified, active administrator. Project selection uses the existing scoped control request; a genuine platform owner can administer a selected project through the trusted server callback. Requests cannot choose a database schema or grant themselves a project role.

- `GET /api/auth/control/analytics` returns summary metrics, chart buckets, definitions and collection coverage.
- `GET /api/auth/control/analytics/entities` returns the exact identities represented by a cohort, with bounded pagination and safe current profiles.

Common query parameters:

| Parameter | Values | Default |
| --- | --- | --- |
| `entity` | `users`, `organizations` | `users` |
| `range` | `7d`, `30d`, `90d`, `6m` | `30d` |
| `bucket` | `day`, `week`, `month` | `day` |
| `end` | Inclusive UTC calendar date, `YYYY-MM-DD` | Today |
| `from`, `to` | Paired inclusive UTC dates overriding range/end; 1–186 days | Omitted |

Drill-down also accepts `cohort`, `limit` (1–100, default 25), `offset` (0–100000, default 0), and `q` (1–128 characters). Search is parameterized and wildcard characters are literal. `cohort` defaults to `active` and accepts every cohort below plus `all`.

Weeks start Monday. Calendar-month and week buckets are clipped at the selected window's edges. Each bucket compares to an immediately preceding interval of the same number of UTC days. Passing a chart point's `from`/`to` to drill-down reproduces its cohort exactly. Six months uses a calendar-month subtraction with month-end clamping, rather than assuming 180 days.

## Cohorts and coverage

| Cohort | Definition |
| --- | --- |
| Active | At least one observed authenticated activity day in the selected period. |
| New | Identity created in the selected period, whether active or inactive. |
| Retained | Active in both the selected period and its equally long preceding period. |
| Reactivated | Active now, inactive in the preceding period, with earlier observed activity. |
| Churned | Active in the preceding period with no observed activity now. This is authenticated inactivity, not confirmed customer churn. |
| First active | First observed activity now for an identity created after collection began but before this period. |
| Unknown | Active now without earlier observations, but created before collection began. Historical activity is unknown. |
| All | Currently existing nonanonymous identities, independent of selected dates. |

New includes inactive registrations, so it does not partition the active cohort. Cohorts retain historical deleted IDs; all includes only current identities. Identity counts are distinct within each bucket; daily totals must not be added to infer distinct weekly/monthly users.

Migration `006-analytics.sql` establishes the collection timestamp and imports surviving identities' actual creation dates. It does not infer past activity from current sessions or retained audit rows, and cannot reconstruct identities deleted before installation. Coverage explicitly distinguishes complete, partial and unknown periods. Metric `value` is the observed count; `complete:false` means absent historical collection can hide facts. In-progress current periods are labeled separately. Reactivated counts remain incomplete when active identities have unknown prior history.

Chart `values` are `null` for unknown or incomplete history, rather than fake zero. `observed` holds actual collected values for a distinct partial-data rendering. Hide unknown points; identify partial points clearly. Organization `traffic` and per-point sign-in fields are `null`: user sign-in attempts are not automatically attributed to an organization. User sign-in/failure traffic comes from canonical completion events and survives audit deletion. Pending MFA does not count as completed sign-in.

The public TypeScript contract is in `lib/control/analytics-types.ts`. Analytics facts have no automatic age-based pruning; audit retention is controlled separately.
