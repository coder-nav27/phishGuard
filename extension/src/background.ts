import { scanUrl } from './api'

type BadgeLevel = 'safe' | 'suspicious' | 'malicious' | 'unknown' | 'pending'

const BADGE_COLORS: Record<BadgeLevel, string> = {
  pending:    '#58a6ff',
  safe:       '#3fb950',
  suspicious: '#d29922',
  malicious:  '#f85149',
  unknown:    '#8b949e',
}

const BADGE_TEXT: Record<BadgeLevel, string> = {
  pending:    '...',
  safe:       'OK',
  suspicious: '!!',
  malicious:  'BAD',
  unknown:    '?',
}

function setBadge(tabId: number, level: BadgeLevel): void {
  chrome.action.setBadgeText({ tabId, text: BADGE_TEXT[level] })
  chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[level] })
}

chrome.webNavigation.onCompleted.addListener(async ({ tabId, url, frameId }) => {
  // Only process top-level navigations to http(s) pages
  if (frameId !== 0 || !url.startsWith('http')) return

  setBadge(tabId, 'pending')
  // Signal popup that a scan is in progress for this tab
  await chrome.storage.local.set({ [`scan_${tabId}`]: { pending: true, url } })

  const result = await scanUrl(url)

  if (!result) {
    setBadge(tabId, 'unknown')
    await chrome.storage.local.remove(`scan_${tabId}`)
    return
  }

  setBadge(tabId, result.level as BadgeLevel)

  // Persist so popup can read it without re-scanning
  await chrome.storage.local.set({ [`scan_${tabId}`]: result })

  if (result.level === 'malicious') {
    chrome.notifications.create(`phishguard_${tabId}_${Date.now()}`, {
      type:    'basic',
      iconUrl: 'icons/icon48.png',
      title:   '⚠ PhishGuard — Malicious URL Detected',
      message: `Risk: ${(result.score * 100).toFixed(0)}%\n${url.slice(0, 80)}`,
      priority: 2,
    })

    // Signal content script to show in-page banner
    chrome.tabs.sendMessage(tabId, { level: result.level, score: result.score }).catch(() => {
      // Content script may not be ready — ignore
    })
  }
})

// Clean up storage when tab closes
chrome.tabs.onRemoved.addListener(tabId => {
  chrome.storage.local.remove(`scan_${tabId}`)
})
