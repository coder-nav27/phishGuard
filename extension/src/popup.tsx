import React, { useEffect, useState } from 'react'
import ReactDOM from 'react-dom/client'
import type { ScanResult } from './api'

type Level = ScanResult['level']

const LEVEL_STYLE: Record<Level | 'pending', { color: string; label: string }> = {
  safe:       { color: '#3fb950', label: 'SAFE'       },
  suspicious: { color: '#d29922', label: 'SUSPICIOUS' },
  malicious:  { color: '#f85149', label: 'MALICIOUS'  },
  unknown:    { color: '#8b949e', label: 'UNKNOWN'     },
  pending:    { color: '#58a6ff', label: 'SCANNING…'  },
}

const SEV_COLOR: Record<string, string> = {
  critical: '#f85149',
  high:     '#d29922',
  medium:   '#e3b341',
  low:      '#3fb950',
}

function isScannable(url: string): boolean {
  return url.startsWith('http://') || url.startsWith('https://')
}

function Popup() {
  const [result, setResult]     = useState<ScanResult | null>(null)
  const [pending, setPending]   = useState(false)
  const [tabId, setTabId]       = useState<number | null>(null)
  const [tabUrl, setTabUrl]     = useState<string>('')
  const [rescanning, setRescanning] = useState(false)

  useEffect(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      const tab = tabs[0]
      if (!tab?.id) return
      setTabId(tab.id)
      setTabUrl(tab.url ?? '')
      chrome.storage.local.get(`scan_${tab.id}`, data => {
        const stored = data[`scan_${tab.id}`]
        if (!stored) return
        if (stored.pending) {
          setPending(true)
          // Poll storage until the background worker writes the real result
          const interval = setInterval(() => {
            chrome.storage.local.get(`scan_${tab.id}`, d => {
              const updated = d[`scan_${tab.id}`]
              if (updated && !updated.pending) {
                clearInterval(interval)
                setPending(false)
                setResult(updated)
              }
            })
          }, 500)
        } else {
          setResult(stored)
        }
      })
    })
  }, [])

  async function handleRescan() {
    if (!tabId || !tabUrl || rescanning || !isScannable(tabUrl)) return
    setRescanning(true)
    setResult(null)
    // Call API directly, bypassing the in-memory cache in api.ts
    try {
      const resp = await fetch('http://localhost:8000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: tabUrl, source: 'extension' }),
      })
      const fresh = resp.ok ? await resp.json() : null
      await chrome.storage.local.set({ [`scan_${tabId}`]: fresh ?? undefined })
      setResult(fresh)
    } catch {
      setResult(null)
    }
    setRescanning(false)
  }

  const displayLevel: Level | 'pending' = rescanning || pending ? 'pending' : result?.level ?? 'unknown'
  const style = LEVEL_STYLE[displayLevel] ?? LEVEL_STYLE.unknown
  const score = result ? (result.score * 100).toFixed(0) : '—'

  return (
    <div style={{ width: 340, padding: 16, background: '#0d1117', color: '#c9d1d9', fontFamily: 'monospace', fontSize: 13 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14, paddingBottom: 10, borderBottom: '1px solid #21262d' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 18 }}>🛡</span>
          <span style={{ color: '#58a6ff', fontWeight: 700, letterSpacing: 2 }}>PHISHGUARD</span>
        </div>
        <button
          onClick={handleRescan}
          disabled={rescanning || pending}
          title="Force rescan"
          style={{
            background: 'none', border: '1px solid #30363d', color: rescanning || pending ? '#30363d' : '#8b949e',
            cursor: rescanning || pending ? 'default' : 'pointer', padding: '2px 8px',
            borderRadius: 4, fontSize: 11, fontFamily: 'monospace',
          }}
        >
          {rescanning ? 'scanning…' : '↺ rescan'}
        </button>
      </div>

      {/* Status badge */}
      <div style={{ color: style.color, fontSize: 17, fontWeight: 700, marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
        {displayLevel === 'pending' ? (
          <span style={{ opacity: 0.8 }}>⏳ {style.label}</span>
        ) : (
          <span>{style.label}</span>
        )}
      </div>

      {/* URL */}
      <div style={{ color: '#8b949e', fontSize: 11, marginBottom: 10, wordBreak: 'break-all', lineHeight: 1.4 }}>
        {tabUrl.slice(0, 120)}{tabUrl.length > 120 ? '…' : ''}
      </div>

      {result && !pending && !rescanning ? (
        <>
          {/* Scores row */}
          <div style={{ display: 'flex', gap: 20, marginBottom: 12, fontSize: 12 }}>
            <div>
              <div style={{ color: '#8b949e' }}>Risk Score</div>
              <div style={{ color: style.color, fontWeight: 700, fontSize: 22 }}>{score}%</div>
            </div>
            <div>
              <div style={{ color: '#8b949e' }}>ML Prob</div>
              <div style={{ color: '#c9d1d9', fontWeight: 700, fontSize: 22 }}>
                {(result.ml_probability * 100).toFixed(0)}%
              </div>
            </div>
            <div>
              <div style={{ color: '#8b949e' }}>Flags</div>
              <div style={{ color: '#c9d1d9', fontWeight: 700, fontSize: 22 }}>
                {result.indicators.length}
              </div>
            </div>
          </div>

          {/* Indicators */}
          {result.indicators.length > 0 && (
            <div style={{ marginBottom: 10 }}>
              <div style={{ color: '#8b949e', fontSize: 10, marginBottom: 4, textTransform: 'uppercase', letterSpacing: 1 }}>Indicators</div>
              {result.indicators.map((ind, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 6, marginBottom: 4 }}>
                  <span style={{ color: SEV_COLOR[ind.severity] ?? '#8b949e', fontSize: 10, flexShrink: 0, marginTop: 1 }}>●</span>
                  <span style={{ color: '#c9d1d9', fontSize: 11, lineHeight: 1.4 }}>{ind.description}</span>
                </div>
              ))}
            </div>
          )}

          {/* Explanation bullets */}
          {result.explanation.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              <div style={{ color: '#8b949e', fontSize: 10, marginBottom: 4, textTransform: 'uppercase', letterSpacing: 1 }}>Analysis</div>
              <ul style={{ margin: 0, paddingLeft: 14, color: '#8b949e', fontSize: 11, lineHeight: 1.6 }}>
                {result.explanation.slice(0, 4).map((e, i) => <li key={i}>{e}</li>)}
              </ul>
            </div>
          )}
        </>
      ) : !pending && !rescanning ? (
        <div style={{ color: '#8b949e', fontSize: 12, lineHeight: 1.6 }}>
          {!isScannable(tabUrl)
            ? <>This page cannot be scanned.<br />Navigate to an http/https URL.</>
            : <>No scan result for the current tab.<br />Navigate to a page to trigger an automatic scan,<br />or click ↺ rescan above.</>
          }
        </div>
      ) : null}

      <div style={{ marginTop: 14, paddingTop: 10, borderTop: '1px solid #21262d', color: '#30363d', fontSize: 10, textAlign: 'right' }}>
        PhishGuard v1.0.0
      </div>
    </div>
  )
}

ReactDOM.createRoot(document.getElementById('root')!).render(<Popup />)
