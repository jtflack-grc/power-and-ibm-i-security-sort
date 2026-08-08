/** Stable external reference URLs — prefer durable destinations over flaky hosts. */

export function cveRecordUrl(cveId: string): string {
  return `https://www.cve.org/CVERecord?id=${encodeURIComponent(cveId)}`;
}

export function nvdDetailUrl(cveId: string): string {
  return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`;
}

export function ibmSupportSearchUrl(cveId: string): string {
  return `https://www.ibm.com/support/pages/search?q=${encodeURIComponent(cveId)}`;
}

/**
 * IBM SEO slug bulletin URLs often land on a support-search dead end.
 * Prefer /support/pages/node/<id>; otherwise fall back to CVE search.
 */
export function normalizeIbmBulletinUrl(
  url: string | null | undefined,
  cveId: string
): string {
  if (!url) return ibmSupportSearchUrl(cveId);
  try {
    const u = new URL(url);
    if (!u.hostname.endsWith("ibm.com")) return ibmSupportSearchUrl(cveId);
    const node = u.pathname.match(/\/support\/pages\/node\/(\d+)/i);
    if (node) return `https://www.ibm.com/support/pages/node/${node[1]}`;
    if (/security-bulletin/i.test(u.pathname) && !/\/node\//i.test(u.pathname)) {
      return ibmSupportSearchUrl(cveId);
    }
    return url;
  } catch {
    return ibmSupportSearchUrl(cveId);
  }
}
