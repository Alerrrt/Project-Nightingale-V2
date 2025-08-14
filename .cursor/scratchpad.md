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


