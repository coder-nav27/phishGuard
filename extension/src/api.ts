const BACKEND_URL = 'http://localhost:8000/api'

export interface ScanResult {
  url: string
  score: number
  level: 'safe' | 'suspicious' | 'malicious' | 'unknown'
  ml_probability: number
  explanation: string[]
  indicators: Array<{ type: string; severity: string; description: string }>
}

// Per-URL cache with 60s TTL — prevents hammering the API on every navigation
const cache = new Map<string, { result: ScanResult; ts: number }>()
const CACHE_TTL = 60_000

export async function scanUrl(url: string): Promise<ScanResult | null> {
  const cached = cache.get(url)
  if (cached && Date.now() - cached.ts < CACHE_TTL) {
    return cached.result
  }

  try {
    const resp = await fetch(`${BACKEND_URL}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, source: 'extension' }),
    })
    if (!resp.ok) return null
    const result: ScanResult = await resp.json()
    cache.set(url, { result, ts: Date.now() })
    return result
  } catch {
    return null
  }
}
