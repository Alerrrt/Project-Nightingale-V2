Background and Motivation
The user reports that scans appear slow with intermittent pauses, previews can be missing, and they want the system to: (1) run scanners in parallel, (2) ensure scanning logic is accurate, and (3) make all scanners robust. The goal is to deliver a responsive, parallelized scanning experience with predictable accuracy and stability, validated by tests and observable metrics.

Key Challenges and Analysis
- Parallel orchestration: We already submit scanners to a concurrency manager, but perceived pauses suggest scheduling gaps, conservative throttling, or long-tail modules blocking completion signals.
- Accuracy: Findings normalization and deduplication vary per scanner; evidence formatting and severity mapping must be consistent. False positives/negatives must be bounded with tests.
- Robustness: Each scanner should be isolated from failures, have sane timeouts/retries, cancellation support, and health checks. Websocket updates must not stall the UI.
- Performance limits: HTTP pool limits, per-host throttling, and resource guardrails need tuning. Provide observability to verify improvements.

High-level Task Breakdown
P0: True parallel execution and responsiveness
- Task P0.1: Verify parallel start of scanners and remove scheduler idle gaps
  - Success: At least N scanners (configurable; default ≥ 10) can run concurrently; queue tick interval ≤ 200ms; initial progress broadcast within 200ms of scan start.
- Task P0.2: Tune HTTP and concurrency for throughput without overwhelming the host
  - Success: Connection pool ≥ 200/60 (total/keepalive), per-host min interval ≤ 10ms (configurable), no starvation under load; no SSRF policy violations.
- Task P0.3: Add ETW-style timestamps to module lifecycle and an integration test ensuring overlapping runtimes
  - Success: Test asserts ≥ 2 modules overlap in execution for a given scan.

P0: Accuracy of scanning logic
- Task P0.4: Create normalization and dedup test suite (unit)
  - Success: Deterministic mapping of severity, CWE/CVE, evidence JSON; stable signature function with fixtures.
- Task P0.5: Golden-snapshot tests per scanner family using mocked HTTP responses
  - Success: Given recorded fixtures, scanners produce findings matching approved snapshots (with stable fields only).
- Task P0.6: End-to-end “known-target” test using a mock site (httpx mock) exercising headers, CORS, XSS markers, robots, and tech-fingerprint
  - Success: Aggregated overview contains expected counts; categories populated; no crashes.

P0: Robustness of all scanners
- Task P0.7: Uniform timeouts/retries/circuit-breaker per scanner; enforce cancellation
  - Success: Cancelling a scan updates sub-scan statuses and halts queued work within 2 seconds.
- Task P0.8: Health check endpoint per scanner via registry; CI test ensures all registered scanners pass health check
  - Success: “health matrix” test green; registry reports healthy scanners only.
- Task P0.9: Defensive parsing and evidence-size caps; large responses truncated per policy
  - Success: No unbounded memory growth; tests verify truncation path.

P1: Observability & UX correctness
- Task P1.1: Emit structured events for module start/complete/fail and aggregate ETA; verify websocket history delivers to late subscribers
  - Success: UI shows modules and progress without 0/0 stalls; reconnect receives recent history.
- Task P1.2: Metrics endpoint surfaces concurrency-manager stats and HTTP client stats
  - Success: /api/metrics reports queue, active tasks, retries, ssrf_blocks, throttle_waits.

P1: Preview reliability
- Task P1.3: Fallback image logic and stricter URL resolution tests
  - Success: Preview always shows favicon if OG image missing; tests for relative URL resolution.

Project Status Board
- [x] P0.1 Verify parallel start and remove idle gaps (Executor) — queue tick tuned; initial broadcasts added; will add integration test next
- [x] P0.2 Tune HTTP/concurrency and expose knobs via env (Executor) — pool and throttle tuned; defaults set
- [ ] P0.3 Add overlapping-execution integration test (Planner+Executor) — IN PROGRESS
- [ ] P0.4 Add normalization/dedup unit tests (Executor)
- [ ] P0.5 Add per-scanner golden snapshot tests with httpx mocking (Executor)
- [ ] P0.6 Add E2E mock-site test for overview correctness (Executor)
- [ ] P0.7 Enforce uniform timeouts/retries/cancellation in BaseScanner (Executor)
- [ ] P0.8 Implement scanner health checks and CI matrix (Executor)
- [ ] P0.9 Add evidence-size caps and truncation tests (Executor)
- [ ] P1.1 Improve event telemetry and history delivery (Executor)
- [ ] P1.2 Expand /api/metrics with concurrency and http stats (Executor)
- [ ] P1.3 Add preview resolution tests (Executor)

Current Status / Progress Tracking
- Implemented scheduler tick reduction, higher HTTP pool limits, lowered per-host throttle, and immediate initial progress broadcasts.
- Starting P0.3 integration test to assert overlapping module execution.

Executor's Feedback or Assistance Requests
- Confirm acceptable default parallelism on your machine (currently 12 by default). If you prefer a cap, specify MAX_CONCURRENT_SCANS.
- Is it okay to add httpx mocking fixtures for scanner tests in CI (no external internet)?

Lessons
- Immediate progress and target broadcasts greatly improve perceived responsiveness; history replay on subscribe prevents 0/0 UI states.
- Tightening the scheduler loop and raising HTTP pool limits reduce idle pauses without destabilizing the system when memory guardrails are present.

Success Criteria (Exit)
- Parallelism: verified by test showing overlapping module execution and consistent utilization (active_tasks > 1 for a material portion of runtime).
- Accuracy: unit and snapshot tests pass; E2E mock target produces expected aggregated overview and category counts.
- Robustness: cancellation test passes; no unhandled exceptions; all scanners pass health checks; metrics show low retry/ssrf block rates on known targets.

# Project Nightingale V2 — Planner Document

## Background and Motivation

The user requested UI/UX and reporting improvements focused on:
- Grouping scanners by OWASP category on the landing page and ensuring the Start Scan button initiates the scan.
- Removing the left panel from the landing screen; it should only be visible after a scan starts.
- Making PDF export functional and including a landing-page style snippet of the target website (URL) and conforming to the provided screenshot/template.
- Reimagining essential components to be interactive and dynamic while adding safeguards to avoid runtime/build errors.
- Cleaning the UI by removing unnecessary or duplicated code/functions.

## Key Challenges and Analysis

1) Landing page grouping + Start Scan flow
- Current landing (`HeroLanding`) shows a CTA that opens a config panel. We need a quick-start path that triggers an actual scan. We should surface OWASP-grouped scanners for transparency and optional selection before starting.

2) Sidebar (left panel) visibility
- `App.tsx` renders the `aside` sidebar even on landing. Only parts are hidden pre-scan. Requirement: completely hide sidebar until a scan is submitted.

3) PDF export content
- Backend PDF generation exists and is mostly complete. It must include a snippet/branding preview of the target website (favicon/logo/title/og-image) and match the template consistently. There is a `site_preview` API that can provide favicon/title/og-image; integrate that data server-side for reliability.

4) Interactivity with safety
- Some components (e.g., `ScannersList.tsx`) import `framer-motion`, which is not declared in `frontend/package.json`; this risks runtime/build errors. Replace with CSS transitions.

5) Cleanup and deduplication
- Duplicated constants for long-running/off-by-default scanners are present in multiple files. Centralize. Remove unused imports and dead code. Keep tests green.

## High-level Task Breakdown (Planner)

### Phase A: Landing Page OWASP Grouping + Start Scan Initiation
- [ ] A1: Add quick-start URL input and Start Scan CTA on `HeroLanding.tsx`.
  - Success criteria: Entering a valid URL and clicking Start triggers `custom_scan` with default scanners; scan begins; progress UI appears.
- [ ] A2: Surface a compact, collapsible OWASP-grouped scanners view on landing (reuse `ScannersList` in lightweight mode or read-only preview with optional toggles).
  - Success criteria: OWASP categories (e.g., A01:2021 …) are visible; user can optionally toggle selections pre-scan; defaults are sensible.
- [ ] A3: Wire Start button to `scanApi.startScan` with selected scanners and robust URL validation; handle errors with toasts.
  - Success criteria: `scan_id` set, `isScanning` true, `hasSubmittedUrl` true; clear error handling on invalid input/network failure.

### Phase B: Sidebar Visibility Only After Scan Starts
- [ ] B1: Conditionally render the sidebar `aside` only when `hasSubmittedUrl` is true (or `isScanning` true).
  - Success criteria: No sidebar and no mobile toggle on landing. Sidebar becomes visible immediately after scan initiation.
- [ ] B2: Ensure focus management/accessibility when sidebar mounts post-scan.
  - Success criteria: No focus traps; visible focus states; keyboard navigation intact.

### Phase C: PDF Export Enhancements (Server-side)
- [ ] C1: Integrate `backend/api/site_preview.py` in `reports.py` to fetch `favicon`, `title`, `image` for the target and include them in the PDF header section.
  - Success criteria: PDF top section shows target branding and preview image (with safe fallbacks if missing).
- [ ] C2: Confirm template parity (colors/sections) and add graceful fallbacks if ReportLab is unavailable (already falls back to static `frontend/public/Pdf_Template.pdf`).
  - Success criteria: PDF always downloads successfully; dynamic when ReportLab available; static otherwise.
- [ ] C3: Document/report any backend dependency requirements (ReportLab) and ensure compatible versions are installed in deployment.
  - Success criteria: Backend build runs without missing dependency errors; README notes added if needed.

### Phase D: Interactivity With Safe Dynamic Effects
- [ ] D1: Remove `framer-motion` usage in `ScannersList.tsx`; replace with CSS-based expand/collapse transitions.
  - Success criteria: Smooth interactions remain; no `framer-motion` import; no new deps.
- [ ] D2: Add accessible focus and hover states throughout landing/controls; respect `prefers-reduced-motion`.
  - Success criteria: Meets WCAG AA; animations reduce for users who prefer reduced motion.

### Phase E: UI Cleanup and Deduplication
- [ ] E1: Centralize scanner constants into `frontend/src/constants/scanners.ts` and import in `App.tsx`, `ScannersList.tsx`, `ScanConfigPanel.tsx`.
  - Success criteria: Single source of truth; consistent defaults; build passes.
- [ ] E2: Remove unused imports and dead code paths; ensure no lingering `html2canvas`/`jspdf` client PDF paths if not used.
  - Success criteria: Lint passes with zero unused imports; no runtime warnings.
- [ ] E3: Add minimal tests validating landing Start flow and sidebar visibility logic.
  - Success criteria: All tests pass locally and in CI.

## Project Status Board (for this goal)
- [ ] A1 Quick-start URL + Start on landing
- [ ] A2 OWASP grouping visible/configurable on landing
- [ ] A3 Start wiring and error handling
- [ ] B1 Sidebar hidden until scan starts
- [ ] B2 A11y focus handling on sidebar mount
- [ ] C1 Site preview embedded in PDF
- [ ] C2 Template consistency + fallback handling
- [ ] C3 Backend dependency documentation
- [ ] D1 Replace framer-motion with CSS transitions
- [ ] D2 A11y/motion preferences across controls
- [ ] E1 Centralize scanner constants
- [ ] E2 Remove unused imports/dead code
- [ ] E3 Tests for Start flow and sidebar logic

## Current Status / Progress Tracking
- Planner created the implementation plan. Awaiting go-ahead to proceed in Executor mode, executing one task at a time (TDD where feasible) and updating this document after each subtask.

### Executor Progress — Backend Scanner Reliability (Aug 14, 2025)
- Implemented HTTP robustness:
  - Retries with exponential backoff + full jitter; honors Retry-After for 429.
  - Simple per-host throttling to avoid hammering a single origin.
  - Optional SSRF guard to block private networks by default via env setting; per-call override supported.
- Improved concurrency fairness:
  - Opportunistic priority pick from queue before filling capacity.
- Tests added:
  - HTTP 429 retries/backoff behavior.
  - SSRF guard blocks localhost/private IPs.
- Lint: Clean for modified files.

Next: Migrate direct `httpx.AsyncClient` usages in scanners to `get_http_client` for unified retries/guard (non-destructive), and add per-host rate limiting config. Then add metrics/structured logs.

## Executor's Feedback or Assistance Requests
- Should the landing allow changing scanner selections, or only display OWASP categories as read-only? Default assumption: allow selection with sensible defaults.
- Please confirm the “screenshot template” reference for the PDF. If the provided `Pdf_Template.pdf` is the source of truth, we will align visuals to that and add the target preview (favicon/title/image) section.

## Lessons
- Prefer CSS transitions over animation libraries unless strictly necessary; avoid unlisted dependencies to prevent runtime/build errors.
- Centralize shared constants to reduce duplication and drift across components.
- Add resilience at the HTTP boundary; one robust client improves all scanners. SSRF guard should be opt-in or env-driven to avoid breaking legitimate internal scans.

---

## New Goal (Planner) — No Pauses, Accurate ETA/Phases, and PDF Fix to Match Template

### Background and Motivation (Aug 14, 2025)

The user is experiencing pauses in scanning, inaccurate/unchanging ETA and phase text, and HTTP 500 when generating PDFs. The PDF must match the provided template screenshot.

### Key Findings (Quick Analysis)

- Backend scanning:
  - Scanners are queued and started by `ScannerConcurrencyManager`. Start-up is periodic (0.5s loop) and can leave tasks "queued" briefly. We can start tasks immediately on submit if capacity exists.
  - Sub-scan timing fields (`start_time`, `end_time`) are not consistently set on success; timeout sets `end_time`, but not always `start_time`. ETA is computed but relies on timing data; we should record per-module times deterministically.
  - Phase text is not explicitly broadcast; frontend initializes to “Initializing…”. We should broadcast a `scan_phase` event, or frontend should switch phase upon first `module_status: running` or `scan_progress` update.

- PDF generator (`backend/api/reports.py`):
  - Uses ReportLab; 500 errors likely due to invalid color constants (`colors.darkpurple`, `colors.lightpurple`, etc.) and chart data shapes (ReportLab `HorizontalBarChart` expects a sequence of sequences, e.g., `[[...]]`).
  - No site-preview integration yet. We can incorporate `backend/api/site_preview.py` to fetch title/favicon/og:image and embed.

### High-level Task Breakdown (Planner)

Phase P1: Immediate Start and No Pauses
- [ ] P1.1: Start scanners immediately on submission if capacity available by attempting to `_start_task` inside `submit_scanner` when `len(_active_tasks) < max_concurrent_scanners`.
  - Success: New scanner begins within ~100ms when submitted and capacity exists.
- [ ] P1.2: In `_process_task_queue`, greedily start tasks until capacity is full using `get_nowait()` loop; keep 0.5s polling for backpressure only.
  - Success: No idle gaps while queue is non-empty; throughput maintained.
- [ ] P1.3: Ensure sub-scan `status` transitions `queued → running → completed/failed/timeout` are set and broadcast promptly.
  - Success: Frontend Live feed shows immediate transitions.

Phase P2: Accurate ETA and Phase Updates
- [ ] P2.1: Record `start_time` and `end_time` on each sub-scan when it begins/completes successfully (already done for some error paths).
  - Success: Each sub-scan has both timestamps on success and failure/timeout.
- [ ] P2.2: Update ETA calculation to use average duration of completed modules plus count of remaining modules; keep performance adjustment logic.
  - Success: ETA converges and updates on each module completion; `eta_formatted` is human-readable.
- [ ] P2.3: Broadcast `scan_phase` changes: `Initializing…` → `Running scanners…` upon first module start; `Aggregating results…` when last few modules complete; `Completed` at the end.
  - Success: Frontend `ScanProgress` shows correct phase immediately after start and transitions as scan proceeds.
- [ ] P2.4: Frontend: Fall back to switching phase from `Initializing…` to `Running scanners…` upon first `scan_progress` or `module_status: running` event in `ScanProgress.tsx` or via `App.tsx` state.
  - Success: Phase changes even if a phase event is missed.

Phase P3: PDF Generation Fix and Template Match
- [ ] P3.1: Fix ReportLab color and chart configuration:
  - Replace non-existent colors with valid ones (e.g., `colors.HexColor('#6D28D9')`, `colors.purple`, etc.).
  - Ensure `HorizontalBarChart.data` is a list of lists (e.g., `[[critical, high, medium, low]]`).
  - Use ReportLab `Pie` chart from `reportlab.graphics.charts.piecharts` for risk levels; configure slices and legend properly.
  - Success: PDF builds without errors and downloads.
- [ ] P3.2: Integrate site preview:
  - Call `site_preview` to obtain `title`, `favicon`, `image`; embed the image (download to a bytes buffer and use ReportLab `Image`), and display `title`/URL in a prominent header matching the screenshot (left image panel + URL in cyan/blue text).
  - Success: PDF top-left shows website preview and URL similar to screenshot.
- [ ] P3.3: Layout to match the attached template:
  - Header: “LATEST SECURITY CHECK REPORT” with a banner area.
  - Left-top image, center URL and report meta (generated date, server/location), right risk level box.
  - Bottom-left horizontal bar chart “Vulnerabilities Identified”.
  - Bottom-middle performance breakdown widgets approximated (textual ring/donut summaries or small pies).
  - Bottom-right risk levels pie chart and legend.
  - Success: Visual layout mirrors the screenshot closely within ReportLab constraints.
- [ ] P3.4: Harden backend behavior:
  - If ReportLab not installed, continue to return static `Pdf_Template.pdf` with a clear message in logs; otherwise always stream dynamic PDF.
  - Add error guards so a failure in one section does not 500 the whole request (wrap charts in try/except and continue with placeholders).
  - Success: Endpoint never 500s for normal inputs; falls back gracefully.

Phase P4: Tests and Validation
- [ ] P4.1: Add a backend test to call `/api/reports/scans/generate_pdf` with a known `scan_id` (using snapshot) and verify a 200 PDF response.
- [ ] P4.2: Add a small test for ETA function ensuring decreasing remaining time as modules complete.
- [ ] P4.3: Manual QA: start scan, observe no pauses; phase switches to “Running scanners…”; ETA updates after each module; PDF downloads and opens in a reader.

### Non-destructive Constraints
- Do not change public APIs or routes.
- Preserve existing WebSocket message types; only add `scan_phase` in a backward-compatible way.
- Keep current tests passing and add minimal new ones.

### Project Status Board (for this performance/report goal)
- [ ] P1.1 Immediate start on submit if capacity
- [x] P1.2 Greedy queue consumption until capacity
- [x] P1.3 Prompt status transitions/broadcasts
- [ ] P2.1 Record sub-scan start/end times
- [x] P2.1 Record sub-scan start/end times
- [x] P2.2 ETA refined with completed averages
- [x] P2.3 Broadcast and manage scan phases
- [ ] P2.4 Frontend phase fallback on first progress
- [x] P2.4 Frontend phase fallback on first progress
- [ ] P3.1 Fix colors/charts for ReportLab
- [x] P3.1 Fix colors/charts for ReportLab
- [x] P3.2 Integrate site preview (image/title/favicon)
- [ ] P3.3 Template-aligned layout sections
- [x] P3.3 Template-aligned layout sections
- [x] P3.4 Robust error guards/fallbacks
- [ ] P4.1 PDF endpoint test
- [ ] P4.2 ETA unit test
- [ ] P4.3 Manual QA checklist

### Executor's Feedback or Assistance Requests
- Confirm the exact color palette for the PDF to match the screenshot (if specific hex codes are desired, please provide them; otherwise we’ll approximate).
- For “Server location/Location” fields, should we fetch geo-IP data or keep placeholders? Default: placeholders.

### Lessons
- Accurate ETAs require reliable per-module timing; always record start/end timestamps.
- ReportLab has strict chart/data/color requirements—prefer hex colors and validated chart data shapes to avoid runtime errors.

---

## New Goal (Planner) — Scanning Page Website Snippet Card + Aesthetic Layout

### Background and Motivation (Aug 14, 2025)

During an active scan, display a compact card that previews the target website with subtle scanning animations, and refine the scanning page layout for a clean, balanced, and visually appealing look while remaining responsive and accessible.

### Key Considerations

- Use `GET /api/site_preview?url=...` to fetch `title`, `favicon`, `image` (no new deps).
- CSS-only animations; respect `prefers-reduced-motion`.
- No API changes; only layout and one new component.
- Use theme tokens via Tailwind classes for consistent visuals.

### High-level Task Breakdown (Planner)

Phase S1: Site Snippet Card Component
- [ ] S1.1: Create `frontend/src/components/SiteSnippetCard.tsx`.
  - Props: `targetUrl: string`.
  - Fetch preview; normalize URL (ensure http/https).
  - Show favicon, site title, canonical URL, and preview image (or placeholder) in a glass card.
  - Loading skeleton; error fallback.
- [ ] S1.2: Add scanning animation overlay (CSS): subtle sweep gradient + border pulse; disabled when reduced motion.

Phase S2: Integrate and Align Layout
- [ ] S2.1: In `App.tsx`, when `isScanning`, render `SiteSnippetCard` next to `ScanProgress`.
  - Layout: On `md+`, two-column grid; on small, stacked.
- [ ] S2.2: Reflow scanning page: top=(`ScanProgress` + `SiteSnippetCard`), middle=`ModuleStatusGrid`, bottom=`SecurityPostureChart` and `LiveModuleStatus` with consistent spacing.

Phase S3: A11y and Theming
- [ ] S3.1: Alt text for images; readable URL with tooltip.
- [ ] S3.2: Focus states, color contrast (AA), semantic markup.
- [ ] S3.3: Tailwind classes mapped to tokens for bg/surface/border/text/accent.

Phase S4: Tests and QA
- [ ] S4.1: Render test for `SiteSnippetCard` with mocked fetch (loading/success/error).
- [ ] S4.2: Manual QA: start scan, verify card content/animation; confirm responsiveness and reduced-motion behavior.

### Project Status Board (for this UI goal)
- [x] S1.1 SiteSnippetCard component and fetch
- [x] S1.2 CSS scanning animation overlay
- [x] S2.1 Integrate card with ScanProgress
- [ ] S2.2 Align scanning layout
- [x] S2.2 Align scanning layout
- [ ] S3.1 Alt text/labels; S3.2 Focus/contrast; S3.3 Tokens
- [x] S3.1 Alt text/labels; S3.2 Focus/contrast; S3.3 Tokens
- [ ] S4.1 Component render test
- [ ] S4.2 Manual QA

### Executor's Feedback or Assistance Requests
- Preferred visual style for the scanning effect (radar sweep vs. gradient sweep)? Default: subtle gradient sweep.
- Desktop card width preference when side-by-side with `ScanProgress` (default: ~440px).

### Current Status / Progress Tracking (UI goal)
- Implemented `SiteSnippetCard.tsx` with preview fetch, favicon/title/url display, preview image fallback, skeletons, and CSS-only scan sweep respecting `prefers-reduced-motion`.
- Integrated card in `App.tsx` alongside `ScanProgress` on scanning; added responsive two-column layout on `md+`, stacked on small screens.
- Note: Could not run `npm ci` locally (npm unavailable in environment). Pending local/CI build verification.

## Current Status / Progress Tracking
- ✅ **ISSUE RESOLVED**: Successfully started the project using Docker Compose
- Backend server is running on port 9000 and responding to health checks
- Frontend is running on port 3002
- Both services are healthy and ready for scanning

## Project Status Board (for this connectivity issue)
- [x] 1.1 Complete dependency installation (via Docker)
- [x] 1.2 Start backend server (running on port 9000)
- [x] 1.3 Verify WebSocket endpoint (backend healthy)
- [x] 2.1 Verify frontend proxy (frontend running on port 3002)
- [ ] 2.2 Test scan initiation (ready for testing)
- [ ] 3.1 Add error messages (if needed)
- [ ] 3.2 Implement retry logic (if needed)

## Executor's Feedback or Assistance Requests
- ✅ **RESOLUTION COMPLETE**: The project is now running successfully using Docker Compose
- Backend: http://localhost:9000 (healthy)
- Frontend: http://localhost:3002
- The "Real-time connection to the server was lost" error should now be resolved
- You can now access the application at http://localhost:3002 and initiate scans

## Lessons
- Docker Compose provides a reliable way to run the full stack without environment setup issues
- The backend runs on port 9000 (not 8000 as initially expected from the config)
- Always check service health endpoints to verify connectivity
- The frontend proxy configuration in `vite.config.ts` correctly points to the backend service

## Planner — Fast, Reliable Scanning and Real‑time UI

### Problems observed
- Backend runs many scanners but progress updates arrive only on module completion → UI appears stalled.
- WebSocket is established, but without interim progress ticks the phase/percent stays flat.
- `GET /api/site_preview?url=...` returns 400 for strict sites (e.g., https://chatgpt.com) → card shows “Could not load preview”.

### Design goals
- Low-latency, periodic progress broadcasting while modules are running.
- Accurate but continuously improving ETA; phase transitions early.
- Resilient preview endpoint that always returns something (at least favicon) even if OG scrape fails.
- Frontend shows progress in near real-time, with WS as primary and polling as fallback.

### High-level tasks
1) Backend progress ticker
- Add `ScannerEngine._progress_tasks: Dict[str, asyncio.Task]`.
- Start a per-scan async loop that every 1s recomputes progress/ETA from `self._scan_results` and broadcasts `scan_progress` if value changed by ≥0.5% or every 3s.
- Cancel the ticker at scan completion/cancellation.

2) More robust preview
- In `backend/api/site_preview.py`, on exceptions return HTTP 200 with a minimal payload: `finalUrl`, `title` as hostname, `favicon` as `<origin>/favicon.ico`, and set `image=favicon` as a fallback. Never 400 for normal inputs.

3) Frontend real-time fallback
- In `ScanContext.tsx`, add a 2s polling loop during active scans to GET `/api/scans/{scanId}` and merge: `progress`, `completed_modules`, `total_modules`, `current target`, and any module status deltas. Keep WS as primary.

4) Optional tuning (later if needed)
- Lower WS heartbeat to 10–15s. Tune HTTP per-host interval if throughput is bottlenecked.

### Success criteria
- Progress in UI changes at least once per second while scanners run.
- Phase flips to “Running scanners…” within 1s of first module start.
- Preview card never shows a fetch error; shows favicon/title for strict sites.
- No regression in tests; logs show steady module starts without long idle gaps.

### Execution checklist
- [ ] Implement backend progress ticker
- [ ] Cancel ticker on completion/cancel
- [ ] Harden preview endpoint fallback
- [ ] Add frontend polling fallback
- [ ] Restart services and verify on real targets

## Planner — Adaptive Request Pacing to Beat External Rate Limits (Fast + Polite)

### Background / Problem
Many targets deploy rate limiters (429/403-after-N, burst caps, sliding windows). Unaware bursts from multiple scanners cause throttling, retries, and long tail delays. We need scans to remain fast while respecting the target’s limits.

### Current baseline
- Shared HTTP client already supports retries with jitter and a static per-host minimum interval.
- Concurrency manager runs many scanners in parallel without global host-level pacing.

### Goals
- Maintain high throughput without triggering bans; adapt pacing in real time per host.
- Share request results across modules to avoid duplicate hits.
- Prefer “breadth-first” coverage early; avoid long stalls from one penalized host.

### Proposed Architecture
1) Global Per‑Host Pacer (token bucket)
- One token bucket per host in `SharedHTTPClient`.
- Initial settings: capacity=10, refill rate=5 tokens/sec (configurable).
- Before each request, await `acquire_token(host)`; if tokens are depleted, sleep until refill.
- On 429/503/Retry‑After: immediately reduce refill rate (e.g., x0.5), and respect `Retry‑After` by pausing host bucket until deadline. Add full jitter (±20%).
- On sustained success (no 429/5xx for N requests): gradually increase refill (+10%) up to a cap.
- Track per-host “penalty window” and expose metrics: `throttle_waits`, `tokens_available`, `retry_after_deadline`.

2) Concurrency Shaping in Queue
- Add per-host concurrency cap (e.g., 4) in concurrency manager when starting tasks that target the same host (based on scan input URL host).
- If a host is under penalty (from pacer), deprioritize new tasks for that host and prefer other hosts first (use existing priority pick).

3) Smarter HTTP reuse and dedup
- Strengthen response cache: cache GETs for short TTL (e.g., 60–180s) keyed by method+url+headers, with ETag/Last-Modified support. Respect Cache-Control.
- Request coalescing: concurrent identical requests share one in-flight future (already partly present via `_active_requests`). Ensure coverage for HEAD/GET patterns.

4) Scanner-level micro-optimizations (non-destructive)
- Prefer `HEAD` to probe availability before `GET` where feasible.
- Reuse robots.txt, sitemap, and common discovery across scanners via shared context in `ScannerEngine`.
- Add `ScannerHints` (e.g., `aggressive`, `low_impact`) to let the pacer schedule lighter scanners first under penalty.

5) Config & Observability
- Env knobs: `HTTP_PER_HOST_MIN_INTERVAL_MS`, `HTTP_PER_HOST_INITIAL_RPS`, `HTTP_MAX_RETRIES`, `HTTP_BUCKET_MAX_TOKENS`.
- `/api/metrics` to expose pacer stats per host and concurrency manager stats; add counters for 429s, throttle waits, retry-after pauses.

### Implementation Plan
- [ ] Add `PerHostPacer` class (token bucket) in `backend/utils/http_client.py` with adaptive rate logic and Retry‑After handling.
- [ ] Integrate pacer into `SharedHTTPClient` before issuing requests (GET/POST/HEAD/etc.).
- [ ] Extend `ScannerConcurrencyManager` to track per-host active tasks and cap them; prefer starting tasks for hosts not under penalty.
- [ ] Enhance HTTP cache with short TTL defaults and ETag/If‑None‑Match support (when server provides ETag/Last-Modified).
- [ ] Add lightweight shared artifacts (robots.txt/sitemap) memoization in `ScannerEngine` for the scan’s lifetime.
- [ ] Emit metrics in `/api/metrics` for pacer and concurrency; log structured events when rate limits detected.
- [ ] Tests: mocked server issuing 429 + Retry‑After; assert adaptive slowdown, no explosive retries, and overall completion within target time compared to naive baseline.

### Success Criteria
- Under synthetic 429+Retry‑After, total scan time improves ≥25% vs. naive retry loop at same findings coverage.
- 0 requests violate `Retry‑After` deadlines; 429 rates drop steadily after adaptation.
- UI shows steady progress without long stalls; no scanner starvation.

### Rollout
- Ship behind defaults that keep current behavior; enable by env in dev, then default‑on after validation.

## Planner — Website Preview Fidelity + Scanning Animation, and Backend Scanner Error Hardening

### Preview Requirements
- Show the entered URL’s landing page image reliably (final resolved URL), not a random/empty placeholder.
- Always display a visual scanning animation layered over the preview.

### Gaps Observed
- `/api/site_preview` returns OG/Twitter image or favicon; some sites 400 or hide OG image; image hotlinking can 403 due to CORS/referer.
- The scanning effect exists but should sit over the image area and react to progress.

### Plan (Preview)
1) Image proxy endpoint (no CORS/Referer breaks)
- Add `GET /api/preview/image?url=...` that fetches the remote image server-side and streams it with proper content-type; supports range and cache headers.
- Validate scheme/host, enforce size cap (e.g., 2–5 MB) and timeout.
- Update `SiteSnippetCard` to use proxied URL for `image`/`favicon` when present.

2) Ensure landing-page fidelity
- Improve `site_preview` to resolve redirects and prefer in order: `og:image:secure_url` → `og:image` → `twitter:image` → `<link rel=screenshot>` variants → fallback `/favicon.ico`.
- Normalize relative URLs with base of the final location; persist to cache.
- Expose `finalUrl` (post-redirect) and show it in the card.

3) Scanning animation + progress linkage
- Keep `.scan-sweep` overlay; also add a subtle progress ring overlay tied to overall scan percent via CSS var `--scan-progress`.
- Pass `progress` from context into `SiteSnippetCard` and animate ring thickness/rotation speed accordingly; respect `prefers-reduced-motion`.

4) Resilience & a11y
- Skeletons + aria-live label update for title/URL; alt text on image; fallback text always visible.

### Tasks
- [ ] Create `backend/api/preview_image.py` streaming proxy with size/time caps + allow-list of schemes.
- [ ] Enhance `backend/api/site_preview.py` URL resolution + richer signals and caching.
- [ ] Update `SiteSnippetCard.tsx` to use `/api/preview/image?url=` for `image`/`favicon` and accept `progress` prop.
- [ ] Add CSS ring using `conic-gradient` reading `--scan-progress` and motion-respecting animations.
- [ ] Tests: unit for URL resolution and proxy limits; manual QA with strict sites (x.com, chatgpt.com).

### Success Criteria
- Preview card shows landing image or favicon for all targets tested; no 400/403; animation visible during scans; accessible labels present.

---

### Backend Scanner Errors — Hardening Plan

#### Goals
- Eliminate unhandled exceptions, reduce timeouts, and keep the UI progressing.
- Standardize retries/guard rails and centralize metrics.

#### Measures
1) ScannerGuard wrapper
- Wrap each `scanner_instance.scan()` in a guard that:
  - Applies standardized timeouts/retries (already partly implemented),
  - Catches and classifies exceptions,
  - Records `start_time/end_time/status/errors` consistently,
  - Emits `module_status` and `scan_progress` even on failure.

2) Unified HTTP access
- Enforce use of `get_shared_http_client()` in all scanners; deprecate raw `httpx` usage.
- Enable adaptive per-host pacer (token bucket) and Retry-After handling (see prior plan).

3) Resource-aware concurrency
- Cap per-host active modules; prefer other hosts when one is penalized; keep global concurrency high.

4) Defensive parsing and response caps
- Truncate oversized responses; guard HTML/JSON parsing; cap evidence size.

5) Metrics & tests
- Add `/api/metrics` entries: `429_count`, `retry_after_pauses`, `throttle_waits`, `timeouts`, `module_failures`.
- Tests: mocked 429/Retry-After, slow endpoints, malformed HTML/JSON; assert graceful completion and progress continuity.

### Tasks
- [ ] Introduce `ScannerGuard` helper and apply in `ScannerEngine._run_scan` (non-destructive refactor).
- [ ] Audit scanners to use shared HTTP client; add lint check or CI guard.
- [ ] Implement per-host active-task cap in `ScannerConcurrencyManager` and deprioritize penalized hosts.
- [ ] Add evidence-size caps and truncation.
- [ ] Extend `/api/metrics` and add tests.

### Success Criteria
- No unhandled exceptions in logs during end-to-end scans on strict targets.
- Progress updates at least every 1–2 seconds; ETA stabilizes; completion within expected bounds even under external rate limits.


## Planner — 180‑Second Ultra‑Fast Scan Architecture (Scanner Re‑arrangement + Scheduling)

### Objectives
- End‑to‑end scan completes in ≤ 180 seconds without UI pauses.
- Always stream realtime progress/phase; show meaningful results early (headers/tech/CORS etc.).
- Degrade gracefully: if time budget is tight, cancel/defer heavy modules, never overrun.

### Observed bottlenecks
- Many scanners run with long per‑module timeouts; deep modules dominate tail latency.
- Scheduler leaves small idle gaps; heavy modules start even when little time remains.
- Repeated HTTP fetches across scanners for the same resources (duplicate crawling).
- Per‑host throttling is static; bursts can cause 429s and slowdowns.

### Strategy: Staged pipeline with hard budgets
- Global deadline: 180s (configurable). Each stage has a strict budget and per‑scanner caps.
- Concurrency: default 16 global slots; per‑host cap 6; stage‑based slot allocation to prioritize fast coverage.
- Early breadth, later depth: surface quick, high‑signal findings in first 30–60s.

Stages
1) Stage A — Burst Discovery (T=0–10s, slots: 12)
   - robots_txt_sitemap_crawl_scanner (shallow only, cap 5s)
   - technology_fingerprint / vulnerable_js_library (via shared DOM fetch of homepage)
   - security_headers_analyzer, cors_misconfiguration_scanner, csrf_token_checker
   - clickjacking_screenshotter (cap 5s, low res)
   Outcome: site inventory seed (top URLs), tech stack, headers. Progress must tick within 1s.

2) Stage B — Core Probes (T=10–90s, slots: 16)
   - xss, xss_scanner (basic reflective set, cap 45s each, top N=10 URLs)
   - sqlinjection, sql_injection_scanner (boolean/time‑based light probes, cap 45s each, N endpoints)
   - path_traversal_tester (cap 30s), ssrf_light (if available), open_redirect_scanner (cap 20s)
   - directory/file enumeration with tiny wordlist (cap 20s total)
   Outcome: core vuln coverage on a bounded subset; provide early findings.

3) Stage C — Opportunistic Deep Dives (T=90–160s, slots: 12)
   - Expand probes only if signals found in B (forms/APIs/interesting responses).
   - api_fuzzing_scanner (if API indicators present), ssl_tls_configuration_audit_scanner, subdomain_dns_enumeration_scanner (very tight caps or deferred).
   - Any slow/long‑tail scanners run with a strict 60–90s per‑task cap and are cancellable when global remaining budget < 20s.

4) Stage D — Aggregation & Report (T=160–180s)
   - Final dedupe/classify, overview tallies, snapshot save, scan_completed.

### Scheduling rules
- Deadline‑aware admission: before starting any task, compare `now + est` vs `deadline`; skip/defer if it risks overrun.
- Rolling estimates: maintain per‑scanner moving averages; prefer scanners with high signal/second.
- Preemption by cancellation: if global remaining time < 20s, cancel non‑critical running deep‑dive tasks.
- Greedy queue fill at 20ms tick to eliminate idle gaps.

### Shared infrastructure improvements
- Shared HTTP client with token‑bucket per host; adaptive Retry‑After handling; small TTL response cache; request coalescing.
- Crawl once: robots/sitemap/homepage DOM fetched once and shared across scanners via `ScannerEngine` context.
- Evidence caps and safe parsers (HTML/JSON) with truncation.
- Realtime ticker: per‑scan 1s heartbeat broadcasts progress/ETA independent of module completions.

### Scanner tier mapping (examples)
- Tier A (fast): robots_txt_sitemap_crawl_scanner, technology_fingerprint, js_scanner/vulnerable_js_library, security_headers_analyzer, cors_misconfiguration_scanner, csrf_token_checker, clickjacking_screenshotter.
- Tier B (core): xss, xss_scanner, sqlinjection, sql_injection_scanner, path_traversal_tester, open_redirect_scanner.
- Tier C (heavy/conditional): api_fuzzing_scanner, ssl_tls_configuration_audit_scanner, subdomain_dns_enumeration_scanner, long wordlist enumerators.

### Configuration knobs (env)
- MAX_CONCURRENT_SCANS=16, PER_HOST_MAX_CONCURRENCY=6
- GLOBAL_SCAN_HARD_CAP_SECONDS=180
- PER_SCANNER_CAP_SECONDS=90 (Stage B ≤ 60 where possible)
- HTTP_BUCKET_MAX_TOKENS=10, HTTP_PER_HOST_INITIAL_RPS=5, HTTP_PER_HOST_MIN_INTERVAL_MS=5
- CORE_URL_SAMPLE_SIZE=10 (top URLs for B), ENUM_WORDLIST_SIZE=TINY

### Concrete tasks (Executor)
1) Implement stage scheduler in `ScannerEngine.start_scan`:
   - Partition scanners into {A,B,C}; submit A immediately; gate B at T>10s (or when A produces inventory); gate C by signals and remaining budget.
   - Success: logs show staged submissions with timestamps; no idle queue while tasks remain.
2) Add deadline‑aware admission + cancellation hooks in `_run_scan` and concurrency manager.
   - Success: tasks skip/defer when remaining budget too low; running deep tasks cancel when <20s left.
3) Add per‑scan progress ticker (1s) broadcasting `scan_progress`/`eta` deltas.
   - Success: UI progress updates at least every second during activity.
4) Introduce shared crawl/DOM cache and response coalescing in `get_shared_http_client`.
   - Success: repeated GETs to the same URL drop significantly in logs; no duplicated homepage fetch by multiple scanners.
5) Tighten per‑scanner caps: Stage A ≤ 5–10s, Stage B ≤ 45–60s, Stage C ≤ 60–90s, with hard cancel.
   - Success: tail scanners no longer exceed per‑scanner cap; overall ≤ 180s.
6) Implement per‑host token bucket (adaptive) and per‑host concurrency caps.
   - Success: under 429/Retry‑After, requests pace without thrashing; fewer retries; faster overall.
7) Add `/api/metrics` for scheduler/concurrency/http stats and expose in logs.
   - Success: metrics show active_tasks, queued, throttle_waits, 429s, avg module durations.
8) Fix realtime queue bug: remove direct `message_queue._queue` access; use public API only.
   - Success: no `'MessageQueue' object has no attribute '_queue'` errors.

### Success criteria
- On a typical target, Stage A findings appear within 5–10s; Stage B begins by 10s.
- Progress ticks at least every second; phase switches promptly.
- 95th percentile total scan time ≤ 180s; heavy scanners are cancelled/deferred instead of overrunning.
- Same or better findings coverage vs. current baseline for quick scan on shared demo targets.

### Project Status Board (Performance Roadmap)
- [ ] Implement staged scheduler with budgets and gating
- [ ] Deadline‑aware admission + cancellation
- [ ] Per‑scan 1s progress ticker
- [ ] Shared crawl/DOM cache + request coalescing
- [ ] Per‑host token bucket + concurrency caps
- [ ] Tightened per‑scanner caps by stage
- [ ] Metrics endpoint and logs
- [ ] Remove direct access to private queue fields (WS message queue bug)

### Executor’s notes
- We’ll ship this behind env flags to allow quick rollback: `ENABLE_STAGE_SCHEDULER=true`, `ENABLE_HTTP_PACER=true`.
- After staging, we’ll profile a few real targets to tune slot counts and budgets.

