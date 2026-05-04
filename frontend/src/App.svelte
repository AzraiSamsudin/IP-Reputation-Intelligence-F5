<script>
  import { onMount, onDestroy } from 'svelte'
  import ResultTable from './lib/ResultTable.svelte'
  import HistoryPanel from './lib/HistoryPanel.svelte'
  import RateMeter from './lib/RateMeter.svelte'

  // ── State ──────────────────────────────────────────────────────────────────
  let mode = 'single'        // 'single' | 'batch'
  let inputValue = ''        // single IP input
  let batchInput = ''        // batch textarea
  let results = []           // current results array
  let history = []           // past searches (persisted in localStorage)
  let loading = false
  let error = null
  let rateLimits = { single: null, batch: null }
  let showHistory = false
  let ratePollInterval

  // ── Lifecycle ──────────────────────────────────────────────────────────────
  onMount(async () => {
    try {
      const saved = localStorage.getItem('iprep_history')
      if (saved) history = JSON.parse(saved)
    } catch {}

    await fetchRateStatus()
    ratePollInterval = setInterval(fetchRateStatus, 5000)
  })

  onDestroy(() => clearInterval(ratePollInterval))

  // ── Helpers ────────────────────────────────────────────────────────────────
  async function fetchRateStatus() {
    try {
      const r = await fetch('/api/rate-status')
      rateLimits = await r.json()
    } catch {}
  }

  function saveHistory() {
    localStorage.setItem('iprep_history', JSON.stringify(history.slice(0, 200)))
  }

  function addToHistory(entries) {
    const ts = new Date().toISOString()
    const items = entries.map(e => ({
      // existing fields
      ip: e.query,
      country: e.country || '—',
      countryCode: e.countryCode || '',
      categories: e.f5rep?.categories || [],
      ts,
      // add these full fields:
      city: e.city || '',
      regionName: e.regionName || '',
      lat: e.lat ?? '',
      lon: e.lon ?? '',
      isp: e.isp || '',
      org: e.org || '',
      as: e.as || '',
      timezone: e.timezone || '',
      zip: e.zip || '',
      flags: e.f5rep?.flags || '',
      threatLevel: threatLabel(e.f5rep?.categories),
    }))
    history = [...items, ...history].slice(0, 200)
    saveHistory()
  }

  function clearHistory() {
    history = []
    saveHistory()
  }

  function restoreFromHistory(item) {
    inputValue = item.ip
    mode = 'single'
    doLookup()
  }
  function threatLabel(categories) {
    if (!categories || (categories.length === 1 && categories[0] === 'Unknown')) return 'Clean'
    const cats = categories.join(' ').toLowerCase()
    if (cats.includes('botnet') || cats.includes('windows exploits') || cats.includes('mobile threats')) return 'Critical'
    if (cats.includes('tor proxy') || cats.includes('web attacks') || cats.includes('phishing')) return 'High'
    if (cats.includes('spam') || cats.includes('scanners')) return 'Medium'
    if (cats.includes('proxy')) return 'Low'
    return 'Clean'
  }

  // ── Lookup ─────────────────────────────────────────────────────────────────

  // FastAPI wraps errors as { detail: { error, message, wait_seconds } }
  function unwrap(data) {
    return data?.detail ?? data
  }

  async function doLookup() {
    error = null
    results = []
    loading = true

    try {
      if (mode === 'single') {
        const resp = await fetch('/api/lookup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: inputValue.trim() }),
        })
        const raw = await resp.json()
        const data = unwrap(raw)

        if (!resp.ok) {
          error = data.wait_seconds
            ? `Rate limited — please wait ${data.wait_seconds}s before trying again.`
            : (data.message || 'Request failed.')
          return
        }

        results = [raw]
        if (raw._rate) rateLimits.single = raw._rate
        addToHistory(results)

      } else {
        // Batch mode
        const ips = batchInput
          .split(/[\n,]+/)
          .map(s => s.trim())
          .filter(s => s.length > 0)

        if (ips.length === 0) { error = 'Enter at least one IP.'; return }
        if (ips.length > 100) { error = 'Maximum 100 IPs per batch.'; return }

        const resp = await fetch('/api/batch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ips }),
        })
        const raw = await resp.json()
        const data = unwrap(raw)

        if (!resp.ok) {
          error = data.wait_seconds
            ? `Rate limited — please wait ${data.wait_seconds}s before trying again.`
            : (data.message || 'Request failed.')
          return
        }

        results = raw.results || []
        if (raw._rate) rateLimits.batch = raw._rate
        addToHistory(results)
      }
    } catch (e) {
      error = `Request failed: ${e.message}`
    } finally {
      loading = false
      await fetchRateStatus()
    }
  }

  function handleKeydown(e) {
    if (e.key === 'Enter' && !loading) doLookup()
  }

  function handleBatchPaste(e) {
    e.preventDefault()
    const text = e.clipboardData.getData('text')
    batchInput = text
      .split(/[\s,;]+/)
      .map(s => s.trim())
      .filter(s => s.length > 0)
      .join('\n')
  }
</script>

<!-- ── Layout ──────────────────────────────────────────────────────────────── -->
<div class="app" class:history-open={showHistory}>

  <!-- Sidebar -->
  <aside class="sidebar" class:open={showHistory}>
    <div class="sidebar-header">
      <span class="sidebar-title">Search History</span>
      <button class="icon-btn" on:click={() => showHistory = false} title="Close">✕</button>
    </div>
    <HistoryPanel {history} on:restore={e => restoreFromHistory(e.detail)} on:clear={clearHistory} />
  </aside>

  <!-- Main -->
  <main class="main">

    <!-- Top bar -->
    <header class="topbar">
      <div class="brand">
        <span class="brand-icon">⬡</span>
        <span class="brand-name">IPRep</span>
      </div>
      <div class="topbar-right">
        <RateMeter {rateLimits} {mode} />
        <button class="history-btn" on:click={() => showHistory = !showHistory}>
          <span class="history-icon">⊞</span>
          History
          {#if history.length > 0}
            <span class="badge">{history.length}</span>
          {/if}
        </button>
      </div>
    </header>

    <!-- Hero -->
    <section class="hero">
      <h1 class="hero-title">IP Reputation<br/><span class="accent">Intelligence</span></h1>
      <p class="hero-sub">Cross-reference geolocation with F5 threat intelligence in real-time.</p>
    </section>

    <!-- Mode Toggle -->
    <div class="mode-toggle-wrap">
      <div class="mode-toggle">
        <button
          class="mode-btn"
          class:active={mode === 'single'}
          on:click={() => { mode = 'single'; error = null; results = [] }}
        >
          <span class="mode-icon">◎</span> Single
        </button>
        <button
          class="mode-btn"
          class:active={mode === 'batch'}
          on:click={() => { mode = 'batch'; error = null; results = [] }}
        >
          <span class="mode-icon">⊞</span> Batch
        </button>
        <div class="mode-slider" style="left: {mode === 'single' ? '4px' : 'calc(50% + 0px)'}"></div>
      </div>
      <span class="mode-hint">
        {#if mode === 'single'}Single IP lookup via ip-api.com + F5 reputation{:else}Up to 100 IPs — newline or comma separated{/if}
      </span>
    </div>

    <!-- Input -->
    <div class="input-section">
      {#if mode === 'single'}
        <div class="input-row">
          <div class="input-wrap">
            <span class="input-prefix">›_</span>
            <input
              class="ip-input"
              type="text"
              bind:value={inputValue}
              placeholder="8.8.8.8  (leave blank for your IP)"
              on:keydown={handleKeydown}
              spellcheck="false"
              autocomplete="off"
            />
          </div>
          <button class="lookup-btn" on:click={doLookup} disabled={loading}>
            {#if loading}<span class="spinner"></span>{:else}Lookup{/if}
          </button>
        </div>
      {:else}
        <div class="batch-wrap">
          <textarea
            class="batch-input"
            bind:value={batchInput}
            placeholder="One Unique IP per Row or Comma separated"
            rows="6"
            spellcheck="false"
            on:paste={handleBatchPaste}
          ></textarea>
          <button class="lookup-btn batch-lookup-btn" on:click={doLookup} disabled={loading}>
            {#if loading}<span class="spinner"></span> Fetching…{:else}⊞ Batch Lookup{/if}
          </button>
        </div>
      {/if}
    </div>

    <!-- Error -->
    {#if error}
      <div class="error-banner">
        <span class="error-icon">⚠</span> {error}
      </div>
    {/if}

    <!-- Results -->
    {#if results.length > 0}
      <div class="results-section">
        <ResultTable {results} on:clear={() => results = []} />
      </div>
    {/if}

    {#if !loading && results.length === 0 && !error}
      <div class="empty-state">
        <div class="empty-grid">
          {#each Array(9) as _, i}
            <div class="empty-cell" style="animation-delay: {i * 80}ms"></div>
          {/each}
        </div>
        <p>Enter an IP address above to begin</p>
      </div>
    {/if}

  </main>
</div>

<style>
  :global(*, *::before, *::after) { box-sizing: border-box; margin: 0; padding: 0; }
  :global(body) {
    background: #0a0c10;
    color: #e2e8f0;
    font-family: 'Syne', sans-serif;
    min-height: 100vh;
    overflow-x: hidden;
  }

  :global(:root) {
    --bg:        #0a0c10;
    --surface:   #111318;
    --surface2:  #181c24;
    --border:    #1e2330;
    --border2:   #2a3045;
    --text:      #e2e8f0;
    --muted:     #64748b;
    --accent:    #00e5ff;
    --accent2:   #7c3aed;
    --danger:    #f43f5e;
    --success:   #10b981;
    --warn:      #f59e0b;
    --mono:      'JetBrains Mono', monospace;
    --sans:      'Inter', sans-serif;
    --radius:    12px;
    --radius-sm: 8px;
  }

  .app {
    display: flex;
    min-height: 100vh;
    position: relative;
  }

  .sidebar {
    position: fixed;
    top: 0; right: 0;
    height: 100vh;
    width: 340px;
    background: var(--surface);
    border-left: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    transform: translateX(100%);
    transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    z-index: 100;
    box-shadow: -20px 0 60px rgba(0,0,0,0.4);
  }
  .sidebar.open { transform: translateX(0); }

  .sidebar-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 20px 24px;
    border-bottom: 1px solid var(--border);
  }
  .sidebar-title {
    font-size: 13px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--muted);
  }
  .icon-btn {
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 16px;
    padding: 4px 8px;
    border-radius: 6px;
    transition: color 0.15s, background 0.15s;
  }
  .icon-btn:hover { color: var(--text); background: var(--border); }

  .main {
    flex: 1;
    max-width: 960px;
    margin: 0 auto;
    padding: 0 24px 60px;
    width: 100%;
  }

  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 20px 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 48px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .brand-icon {
    font-size: 22px;
    color: var(--accent);
    line-height: 1;
  }
  .brand-name {
    font-size: 20px;
    font-weight: 800;
    letter-spacing: -0.5px;
    color: var(--text);
  }
  .topbar-right {
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .history-btn {
    display: flex;
    align-items: center;
    gap: 8px;
    background: var(--surface2);
    border: 1px solid var(--border2);
    color: var(--muted);
    padding: 8px 16px;
    border-radius: var(--radius-sm);
    font-family: var(--sans);
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
  }
  .history-btn:hover { color: var(--text); border-color: var(--accent); }
  .history-icon { font-size: 14px; }
  .badge {
    background: var(--accent2);
    color: white;
    font-size: 11px;
    font-weight: 700;
    padding: 1px 6px;
    border-radius: 10px;
    font-family: var(--mono);
  }

  .hero { margin-bottom: 40px; }
  .hero-title {
    font-size: clamp(36px, 5vw, 56px);
    font-weight: 800;
    line-height: 1.1;
    letter-spacing: -1px;
    margin-bottom: 12px;
  }
  .accent { color: var(--accent); }
  .hero-sub {
    font-size: 15px;
    color: var(--muted);
    font-weight: 400;
  }

  .mode-toggle-wrap {
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    gap: 20px;
  }
  .mode-toggle {
    display: flex;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 4px;
    position: relative;
    width: 220px;
  }
  .mode-btn {
    flex: 1;
    background: none;
    border: none;
    color: var(--muted);
    font-family: var(--sans);
    font-size: 14px;
    font-weight: 600;
    padding: 8px 12px;
    border-radius: 7px;
    cursor: pointer;
    transition: color 0.2s;
    position: relative;
    z-index: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
  }
  .mode-btn.active { color: var(--bg); }
  .mode-slider {
    position: absolute;
    top: 4px; bottom: 4px;
    width: calc(50% - 4px);
    background: var(--accent);
    border-radius: 6px;
    transition: left 0.25s cubic-bezier(0.16, 1, 0.3, 1);
  }
  .mode-hint {
    font-size: 12px;
    color: var(--muted);
    font-family: var(--mono);
  }

  .input-section { margin-bottom: 20px; }
  .input-row {
    display: flex;
    gap: 12px;
    align-items: stretch;
  }
  .input-wrap {
    flex: 1;
    display: flex;
    align-items: center;
    background: var(--surface);
    border: 1px solid var(--border2);
    border-radius: var(--radius);
    padding: 0 16px;
    gap: 10px;
    transition: border-color 0.2s;
  }
  .input-wrap:focus-within { border-color: var(--accent); }
  .input-prefix {
    font-family: var(--mono);
    font-size: 16px;
    color: var(--accent);
    user-select: none;
    opacity: 0.7;
  }
  .ip-input {
    flex: 1;
    background: none;
    border: none;
    outline: none;
    color: var(--text);
    font-family: var(--mono);
    font-size: 16px;
    padding: 16px 0;
  }
  .ip-input::placeholder { color: var(--muted); }

  .lookup-btn {
    background: var(--accent);
    color: var(--bg);
    border: none;
    padding: 0 28px;
    border-radius: var(--radius);
    font-family: var(--sans);
    font-size: 15px;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    gap: 8px;
    white-space: nowrap;
  }
  .lookup-btn:hover:not(:disabled) { filter: brightness(1.1); transform: translateY(-1px); }
  .lookup-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }

  .batch-wrap {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .batch-input {
    background: var(--surface);
    border: 1px solid var(--border2);
    border-radius: var(--radius);
    color: var(--text);
    font-family: var(--mono);
    font-size: 14px;
    padding: 16px;
    resize: vertical;
    outline: none;
    transition: border-color 0.2s;
    line-height: 1.6;
  }
  .batch-input:focus { border-color: var(--accent); }
  .batch-input::placeholder { color: var(--muted); }
  .batch-lookup-btn { align-self: flex-start; padding: 14px 28px; }

  .error-banner {
    display: flex;
    align-items: center;
    gap: 10px;
    background: rgba(244, 63, 94, 0.1);
    border: 1px solid rgba(244, 63, 94, 0.3);
    color: var(--danger);
    padding: 14px 18px;
    border-radius: var(--radius-sm);
    font-size: 14px;
    margin-bottom: 20px;
    font-family: var(--mono);
  }
  .error-icon { font-size: 16px; }

  .results-section { animation: fadeUp 0.3s ease; }
  .results-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 14px;
  }
  .results-count {
    font-size: 13px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--muted);
    font-family: var(--mono);
  }
  .clear-btn {
    background: none;
    border: 1px solid var(--border2);
    color: var(--muted);
    font-family: var(--sans);
    font-size: 12px;
    padding: 4px 12px;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.15s;
  }
  .clear-btn:hover { color: var(--danger); border-color: var(--danger); }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 24px;
    padding: 60px 0;
    color: var(--muted);
    font-size: 14px;
    font-family: var(--mono);
  }
  .empty-grid {
    display: grid;
    grid-template-columns: repeat(3, 32px);
    gap: 8px;
  }
  .empty-cell {
    width: 32px; height: 32px;
    border: 1px solid var(--border);
    border-radius: 6px;
    animation: pulse 2s ease-in-out infinite;
  }

  .spinner {
    width: 16px; height: 16px;
    border: 2px solid rgba(10,12,16,0.3);
    border-top-color: var(--bg);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
    display: inline-block;
  }

  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(10px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  @keyframes pulse {
    0%, 100% { opacity: 0.2; }
    50%       { opacity: 0.5; }
  }
</style>
