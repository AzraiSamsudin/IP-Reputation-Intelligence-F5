<script>
  export let results = []

  import { createEventDispatcher } from 'svelte'
  const dispatch = createEventDispatcher()

  // ── Filter state ───────────────────────────────────────────
  let filterCountry  = ''
  let filterThreat   = ''
  let filterCategory = ''

  // Derived unique values for dropdowns
  $: countries    = [...new Set(results.map(r => r.country).filter(Boolean))].sort()
  $: allCategories = [...new Set(
    results.flatMap(r => r.f5rep?.categories || []).filter(c => c !== 'Unknown')
  )].sort()

  const THREAT_LEVELS = ['clean', 'low', 'medium', 'high', 'critical']

  // ── Filtered rows ──────────────────────────────────────────
  $: filtered = results.filter(r => {
    const lvl  = threatColor(r.f5rep?.categories)
    const cats = r.f5rep?.categories || []

    if (filterCountry  && r.country !== filterCountry)           return false
    if (filterThreat   && lvl !== filterThreat)                  return false
    if (filterCategory && !cats.includes(filterCategory))        return false
    return true
  })

  $: hasFilters = filterCountry || filterThreat || filterCategory

  function clearFilters() {
    filterCountry = ''; filterThreat = ''; filterCategory = ''
  }

  // ── Helpers ────────────────────────────────────────────────
  function threatColor(categories) {
    if (!categories || categories.length === 0) return 'clean'
    const cats = categories.join(' ').toLowerCase()
    if (cats.includes('unknown') && categories.length === 1) return 'clean'
    if (cats.includes('botnet') || cats.includes('windows exploits') || cats.includes('mobile threats')) return 'critical'
    if (cats.includes('tor proxy') || cats.includes('web attacks') || cats.includes('phishing')) return 'high'
    if (cats.includes('spam') || cats.includes('scanners')) return 'medium'
    if (cats.includes('proxy')) return 'low'
    return 'medium'
  }

  function threatLabel(categories) {
    if (!categories || (categories.length === 1 && categories[0] === 'Unknown')) return 'Clean'
    const l = threatColor(categories)
    return l.charAt(0).toUpperCase() + l.slice(1)
  }

  function flagEmoji(cc) {
    if (!cc || cc.length !== 2) return ''
    return cc.toUpperCase().split('').map(c => String.fromCodePoint(127397 + c.charCodeAt(0))).join('')
  }

  // ── CSV Export ─────────────────────────────────────────────
  function exportCSV() {
    const headers = ['IP', 'Country', 'CountryCode', 'City', 'Region', 'Lat', 'Lon', 'ISP', 'Org', 'AS', 'Timezone', 'Zip', 'ThreatLevel', 'Categories', 'F5Flags']
    const rows = filtered.map(r => [
      r.query       || '',
      r.country     || '',
      r.countryCode || '',
      r.city        || '',
      r.regionName  || '',
      r.lat         ?? '',
      r.lon         ?? '',
      r.isp         || '',
      r.org         || '',
      r.as          || '',
      r.timezone    || '',
      r.zip         || '',
      threatLabel(r.f5rep?.categories),
      (r.f5rep?.categories || []).join(' | '),
      r.f5rep?.flags || '',
    ].map(v => `"${String(v).replace(/"/g, '""')}"`))

    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `iprep_export_${new Date().toISOString().slice(0,19).replace(/[:.]/g,'-')}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }
</script>

<!-- ── Filter bar ──────────────────────────────────────────── -->
<!-- ── Unified Toolbar / Filter bar ────────────────────────── -->
<div class="filter-bar">
  <div class="filter-left">
    <span class="results-title">
      {filtered.length} {filtered.length !== 1 ? 'Results' : 'Result'}
    </span>
    {#if filtered.length !== results.length}
      <span class="filter-hint">(filtered from {results.length})</span>
    {/if}

    <div class="divider"></div>

    <select class="filter-select" bind:value={filterThreat}>
      <option value="">All threats</option>
      {#each THREAT_LEVELS as lvl}
        <option value={lvl}>{lvl.charAt(0).toUpperCase() + lvl.slice(1)}</option>
      {/each}
    </select>

    <select class="filter-select" bind:value={filterCountry}>
      <option value="">All countries</option>
      {#each countries as c}
        <option value={c}>{c}</option>
      {/each}
    </select>

    <select class="filter-select" bind:value={filterCategory}>
      <option value="">All categories</option>
      {#each allCategories as c}
        <option value={c}>{c}</option>
      {/each}
    </select>

    {#if hasFilters}
      <button class="clear-filters-btn" on:click={clearFilters}>✕ Clear Filters</button>
    {/if}
  </div>

  <div class="filter-right">
    <button class="export-btn" on:click={exportCSV} disabled={filtered.length === 0}>
      ↓ Export CSV
    </button>
    <button class="clear-all-btn" on:click={() => dispatch('clear')}>
      Clear Search
    </button>
  </div>
</div>

<!-- ── Table ───────────────────────────────────────────────── -->
<div class="table-wrapper">
  <table class="result-table">
    <colgroup>
      <col style="width:140px">
      <col style="width:180px">
      <col style="width:200px">
      <col style="width:150px">
      <col style="width:130px">
      <col style="width:200px">
      <col style="width:80px">
    </colgroup>
    <thead>
      <tr>
        <th>IP Address</th>
        <th>Location</th>
        <th>ISP / Org</th>
        <th>Timezone</th>
        <th>F5 Threat Level</th>
        <th>Categories</th>
        <th>Flags</th>
      </tr>
    </thead>
    <tbody>
      {#if filtered.length === 0}
        <tr>
          <td colspan="7" class="no-results">No results match the current filters.</td>
        </tr>
      {:else}
        {#each filtered as row, i}
          {@const level = threatColor(row.f5rep?.categories)}
          <tr class="result-row" class:status-fail={row.status === 'fail'} style="animation-delay:{i*35}ms">

            <td>
              <span class="ip-addr">{row.query || '—'}</span>
              {#if row.status === 'fail'}<span class="fail-badge">invalid</span>{/if}
            </td>

            <td>
              {#if row.status !== 'fail'}
                <div class="loc-inner">
                  <span class="flag">{flagEmoji(row.countryCode)}</span>
                  <div class="loc-text">
                    <span class="city">{row.city || '—'}</span>
                    <span class="country-line">{row.country || '—'} ({row.countryCode || '?'})</span>
                    {#if row.lat && row.lon}<span class="coords">{row.lat}, {row.lon}</span>{/if}
                  </div>
                </div>
              {:else}<span class="muted">—</span>{/if}
            </td>

            <td>
              {#if row.status !== 'fail'}
                <span class="isp-name">{row.isp || '—'}</span>
                {#if row.org && row.org !== row.isp}<span class="org-name">{row.org}</span>{/if}
                {#if row.as}<span class="as-num">{row.as}</span>{/if}
              {:else}<span class="muted">—</span>{/if}
            </td>

            <td>
              <span class="tz-val">{row.timezone || '—'}</span>
              {#if row.zip}<span class="zip-val">{row.zip}</span>{/if}
            </td>

            <td>
              <span class="threat-badge threat-{level}">
                {#if level === 'critical'}⬛{:else if level === 'high'}🔴{:else if level === 'medium'}🟡{:else if level === 'low'}🔵{:else}✅{/if}
                {threatLabel(row.f5rep?.categories)}
              </span>
            </td>

            <td>
              {#if row.f5rep?.categories?.length && !(row.f5rep.categories.length === 1 && row.f5rep.categories[0] === 'Unknown')}
                <div class="tags">
                  {#each row.f5rep.categories as cat}
                    <span class="tag tag-{threatColor([cat])}">{cat}</span>
                  {/each}
                </div>
              {:else}<span class="muted">—</span>{/if}
            </td>

            <td><span class="flags-val">{row.f5rep?.flags || '—'}</span></td>
          </tr>
        {/each}
      {/if}
    </tbody>
  </table>
</div>

<style>
 /* ── Filter bar ─────────────────────────────────────────── */
  .filter-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 12px 16px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-bottom: none;
    border-radius: var(--radius) var(--radius) 0 0;
    flex-wrap: wrap;
  }
  
  .filter-left, .filter-right {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }

  .results-title {
    font-size: 13px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text);
    font-family: var(--mono);
  }

  .filter-hint {
    font-size: 11px;
    color: var(--muted);
    font-family: var(--mono);
  }

  .divider {
    width: 1px;
    height: 16px;
    background: var(--border);
    margin: 0 4px;
  }

  .filter-select {
    background: var(--surface);
    border: 1px solid var(--border2);
    color: var(--text);
    font-family: var(--mono);
    font-size: 12px;
    padding: 5px 10px;
    border-radius: 6px;
    outline: none;
    cursor: pointer;
    transition: border-color 0.2s;
  }
  .filter-select:focus { border-color: var(--accent); }
  .filter-select option { background: var(--surface); }

  .clear-filters-btn {
    background: none;
    border: 1px solid rgba(244,63,94,0.3);
    color: var(--danger);
    font-size: 11px;
    font-family: var(--mono);
    padding: 4px 10px;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.15s;
  }
  .clear-filters-btn:hover { background: rgba(244,63,94,0.1); }

  .export-btn {
    background: var(--surface);
    border: 1px solid var(--border2);
    color: var(--accent);
    font-family: var(--mono);
    font-size: 12px;
    font-weight: 600;
    padding: 6px 14px;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s;
    white-space: nowrap;
  }
  .export-btn:hover:not(:disabled) { background: rgba(0,229,255,0.08); border-color: var(--accent); }
  .export-btn:disabled { opacity: 0.35; cursor: not-allowed; }

  .clear-all-btn {
    background: none;
    border: 1px solid var(--border2);
    color: var(--muted);
    font-family: var(--sans);
    font-size: 12px;
    font-weight: 600;
    padding: 6px 14px;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s;
    white-space: nowrap;
  }
  .clear-all-btn:hover { 
    color: var(--danger); 
    border-color: rgba(244,63,94,0.4); 
    background: rgba(244,63,94,0.05);
  }

  /* ── Table ──────────────────────────────────────────────── */
  .table-wrapper {
    overflow-x: auto;
    border-radius: 0 0 var(--radius) var(--radius);
    border: 1px solid var(--border);
    background: var(--surface);
  }

  .result-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    table-layout: fixed;
  }

  thead tr { border-bottom: 1px solid var(--border2); }

  th {
    text-align: left;
    padding: 14px 16px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--muted);
    white-space: nowrap;
    overflow: hidden;
    font-family: var(--sans);
  }

  .result-row {
    border-bottom: 1px solid var(--border);
    animation: rowSlide 0.3s ease both;
    transition: background 0.15s;
  }
  .result-row:last-child { border-bottom: none; }
  .result-row:hover { background: var(--surface2); }
  .result-row.status-fail { opacity: 0.5; }

  td { padding: 14px 16px; vertical-align: top; overflow: hidden; }

  .no-results {
    text-align: center;
    color: var(--muted);
    font-family: var(--mono);
    font-size: 13px;
    padding: 32px 16px !important;
  }

  .ip-addr {
    font-family: var(--mono);
    font-size: 14px;
    font-weight: 500;
    color: var(--accent);
    display: block;
    word-break: break-all;
  }
  .fail-badge {
    font-size: 10px;
    background: rgba(244,63,94,0.15);
    color: var(--danger);
    border: 1px solid rgba(244,63,94,0.3);
    padding: 1px 6px;
    border-radius: 4px;
    font-family: var(--mono);
    margin-top: 4px;
    display: inline-block;
  }

  .loc-inner { display: flex; gap: 7px; align-items: flex-start; }
  .flag { font-size: 17px; line-height: 1.2; flex-shrink: 0; }
  .loc-text { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .city { font-weight: 600; color: var(--text); display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .country-line { color: var(--muted); font-size: 12px; display: block; }
  .coords { font-family: var(--mono); font-size: 11px; color: var(--muted); opacity: 0.6; display: block; }

  .isp-name { font-weight: 500; color: var(--text); display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .org-name { font-size: 12px; color: var(--muted); display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .as-num { font-family: var(--mono); font-size: 11px; color: var(--muted); opacity: 0.5; display: block; }

  .tz-val { font-family: var(--mono); font-size: 13px; color: var(--text); display: block; }
  .zip-val { font-size: 11px; color: var(--muted); font-family: var(--mono); display: block; }

  .threat-badge {
    display: inline-flex; align-items: center; gap: 5px;
    font-size: 12px; font-weight: 700; padding: 4px 10px;
    border-radius: 6px; white-space: nowrap; font-family: var(--sans);
  }
  .threat-clean    { background: rgba(16,185,129,0.1);  color: #10b981; border: 1px solid rgba(16,185,129,0.2); }
  .threat-low      { background: rgba(99,102,241,0.1);  color: #818cf8; border: 1px solid rgba(99,102,241,0.2); }
  .threat-medium   { background: rgba(245,158,11,0.1);  color: #f59e0b; border: 1px solid rgba(245,158,11,0.2); }
  .threat-high     { background: rgba(239,68,68,0.1);   color: #f87171; border: 1px solid rgba(239,68,68,0.2); }
  .threat-critical { background: rgba(244,63,94,0.15);  color: #fb7185; border: 1px solid rgba(244,63,94,0.3); }

  .tags { display: flex; flex-wrap: wrap; gap: 4px; }
  .tag { font-size: 11px; padding: 2px 8px; border-radius: 4px; font-family: var(--mono); font-weight: 500; white-space: nowrap; }
  .tag-clean    { background: rgba(16,185,129,0.1);  color: #10b981; }
  .tag-low      { background: rgba(99,102,241,0.1);  color: #818cf8; }
  .tag-medium   { background: rgba(245,158,11,0.1);  color: #f59e0b; }
  .tag-high     { background: rgba(239,68,68,0.1);   color: #f87171; }
  .tag-critical { background: rgba(244,63,94,0.15);  color: #fb7185; }

  .flags-val { font-family: var(--mono); font-size: 13px; color: var(--muted); opacity: 0.8; }
  .muted { color: var(--muted); }

  @keyframes rowSlide {
    from { opacity: 0; transform: translateX(-8px); }
    to   { opacity: 1; transform: translateX(0); }
  }
</style>
