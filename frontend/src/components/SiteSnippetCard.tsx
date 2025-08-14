import React, { useEffect, useMemo, useState } from 'react';

interface SitePreviewData {
  finalUrl?: string;
  title?: string;
  description?: string;
  image?: string;
  favicon?: string;
}

interface SiteSnippetCardProps {
  targetUrl: string | undefined;
}

const normalizeUrl = (url: string): string => {
  if (!url) return '';
  const trimmed = url.trim();
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
};

const SiteSnippetCard: React.FC<SiteSnippetCardProps> = ({ targetUrl }) => {
  const [data, setData] = useState<SitePreviewData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const normalizedUrl = useMemo(() => (targetUrl ? normalizeUrl(targetUrl) : ''), [targetUrl]);

  useEffect(() => {
    let cancelled = false;
    async function fetchPreview() {
      if (!normalizedUrl) {
        setData(null);
        setLoading(false);
        return;
      }
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`/api/site_preview?url=${encodeURIComponent(normalizedUrl)}`);
        if (!res.ok) throw new Error('Failed to load site preview');
        const json: SitePreviewData = await res.json();
        if (!cancelled) {
          setData(json);
          setLoading(false);
        }
      } catch (e) {
        if (!cancelled) {
          setError('Could not load preview');
          setLoading(false);
        }
      }
    }
    fetchPreview();
    return () => {
      cancelled = true;
    };
  }, [normalizedUrl]);

  const displayTitle = data?.title || 'Website Preview';
  const displayUrl = data?.finalUrl || normalizedUrl || '';
  const favicon = data?.favicon;
  const image = data?.image;

  return (
    <div className="relative bg-surface/70 backdrop-blur-md border border-border rounded-xl p-4 overflow-hidden group shadow-sm focus-ring" tabIndex={0} aria-label="Target website preview">
      {/* Scanning sweep overlay */}
      <div className="pointer-events-none absolute inset-0 opacity-40 group-hover:opacity-60 scan-sweep" aria-hidden="true" />

      <div className="flex items-start gap-3 mb-3">
        <div className="h-8 w-8 rounded-md overflow-hidden border border-border flex items-center justify-center bg-background">
          {loading ? (
            <div className="h-5 w-5 rounded-full skeleton" />
          ) : favicon ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img src={favicon} alt="Site favicon" className="h-5 w-5 object-contain" />
          ) : (
            <div className="h-5 w-5 rounded-full bg-primary/60" />
          )}
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-semibold truncate" title={displayTitle} aria-live="polite">
            {loading ? <span className="inline-block h-4 w-40 skeleton rounded" /> : displayTitle}
          </div>
          <div className="text-xs text-textSecondary truncate" title={displayUrl}>
            {loading ? <span className="inline-block h-3 w-56 mt-1 skeleton rounded" /> : displayUrl}
          </div>
        </div>
      </div>

      <div className="relative aspect-video w-full rounded-lg overflow-hidden border border-border">
        {loading ? (
          <div className="w-full h-full skeleton" />
        ) : image ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img src={image} alt="Open Graph preview of the target website" className="w-full h-full object-cover" />
        ) : (
          <div className="w-full h-full bg-background flex items-center justify-center text-textSecondary text-xs">
            Preview not available
          </div>
        )}

        {/* Pulsing scanning border */}
        <div className="absolute inset-0 rounded-lg ring-1 ring-primary/30 animate-pulse" aria-hidden="true" />
      </div>

      {error && (
        <div className="mt-3 text-xs text-error">{error}</div>
      )}
    </div>
  );
};

export default SiteSnippetCard;


