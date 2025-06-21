export interface StartScanParams {
  target: string;
  scan_type?: string;
  options?: Record<string, unknown>;
}

export async function startScan(params: StartScanParams) {
  // Backend expects { target, scan_type, options }
  const res = await fetch('/api/scans/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target: params.target,
      scan_type: params.scan_type || 'full_scan',
      options: params.options || {},
    }),
  });
  if (!res.ok) throw new Error('Failed to start scan');
  return res.json(); // { scan_id, status }
}

export async function stopScan(scanId: string) {
  // Backend expects POST /api/scans/{scan_id}/cancel
  const res = await fetch(`/api/scans/${scanId}/cancel`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to stop scan');
  return res.json();
}

export async function fetchScanStatus(scanId: string) {
  const res = await fetch(`/api/scans/${scanId}`);
  if (!res.ok) throw new Error('Failed to fetch scan status');
  return res.json();
}

export async function fetchVulnerabilities(scanId: string) {
  // Backend: GET /api/scans/{scan_id}/results
  const res = await fetch(`/api/scans/${scanId}/results`);
  if (!res.ok) throw new Error('Failed to fetch vulnerabilities');
  return res.json();
}

export async function fetchScanHistory() {
  // Backend: GET /api/scans/history
  const res = await fetch('/api/scans/history');
  if (!res.ok) throw new Error('Failed to fetch scan history');
  return res.json();
}

export async function fetchScannersList() {
  // Backend: GET /api/scans/scanners
  const res = await fetch('/api/scans/scanners');
  if (!res.ok) throw new Error('Failed to fetch scanners list');
  return res.json();
}