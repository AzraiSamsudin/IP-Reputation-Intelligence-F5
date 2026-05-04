<script>
  import { createEventDispatcher } from 'svelte'
  export let history = []
  const dispatch = createEventDispatcher()

  let filterThreat   = ''
  let filterCountry  = ''
  let filterCategory = ''

  $: countries     = [...new Set(history.map(h => h.country).filter(Boolean))].sort()
  $: allCategories = [...new Set(history.flatMap(h => h.categories || []).filter(c => c !== 'Unknown'))].sort()

  $: filtered = history.filter(h => {
    const l = lvl(h.categories)
    if (filterThreat   && l !== filterThreat)                    return false
    if (filterCountry  && h.country !== filterCountry)           return false
    if (filterCategory && !(h.categories || []).includes(filterCategory)) return false
    return true
  })

  $: hasFilters = filterThreat || filterCountry || filterCategory
  function clearFilters() { filterThreat = ''; filterCountry = ''; filterCategory = '' }

  function formatTime(iso) {
    try {
      const d = new Date(iso), now = new Date(), diff = now - d
      if (diff < 60000) return 'just now'
      if (diff < 3600000) return `${Math.floor(diff/60000)}m ago`
      if (diff < 86400000) return `${Math.floor(diff/3600000)}h ago`
      return d.toLocaleDateString()
    } catch { return '' }
  }

  function lvl(cats) {
    if (!cats || (cats.length === 1 && cats[0] === 'Unknown')) return 'clean'
    const c = cats.join(' ').toLowerCase()
    if (c.includes('botnet') || c.includes('windows exploits')) return 'critical'
    if (c.includes('tor') || c.includes('web attacks') || c.includes('phishing')) return 'high'
    if (c.includes('spam') || c.includes('scanners')) return 'medium'
    if (c.includes('proxy')) return 'low'
    return 'medium'
  }

  function exportHistoryCSV() {
    const headers = ['IP','Country','CountryCode','City','Region','Lat','Lon','ISP','Org','AS','Timezone','Zip','ThreatLevel','Categories','F5Flags','Timestamp']
    const rows = filtered.map(h => [
      h.ip, h.country || '', h.countryCode || '',
      h.city || '', h.regionName || '',
      h.lat ?? '', h.lon ?? '',
      h.isp || '', h.org || '', h.as || '',
      h.timezone || '', h.zip || '',
      h.threatLevel || '',
      (h.categories || []).join(' | '),
      h.flags || '',
      h.ts,
    ].map(v => `"${String(v).replace(/"/g,'""')}"`))

    const csv  = [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url
    a.download = `iprep_history_${new Date().toISOString().slice(0,10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const THREAT_LEVELS = ['clean','low','medium','high','critical']
</script>

<div class="panel">

  <!-- Filter controls -->
  <div class="filters">
    <select class="fsel" bind:value={filterThreat}>
      <option value="">All threats</option>
      {#each THREAT_LEVELS as t}
        <option value={t}>{t.charAt(0).toUpperCase()+t.slice(1)}</option>
      {/each}
    </select>

    <select class="fsel" bind:value={filterCountry}>
      <option value="">All countries</option>
      {#each countries as c}<option value={c}>{c}</option>{/each}
    </select>

    <select class="fsel" bind:value={filterCategory}>
      <option value="">All categories</option>
      {#each allCategories as c}<option value={c}>{c}</option>{/each}
    </select>

    {#if hasFilters}
      <button class="clear-f" on:click={clearFilters}>✕</button>
    {/if}
  </div>

  <!-- Actions row -->
  <div class="actions">
    <span class="count">{filtered.length} / {history.length} entries</span>
    <div class="action-btns">
      <button class="export-hist" on:click={exportHistoryCSV} disabled={filtered.length === 0}>↓ CSV</button>
      <button class="clear-all" on:click={() => dispatch('clear')}>Clear all</button>
    </div>
  </div>

  {#if history.length === 0}
    <div class="empty">
      <span class="empty-icon">◎</span>
      <p>No searches yet</p>
    </div>
  {:else if filtered.length === 0}
    <div class="empty">
      <p>No matches for current filters</p>
    </div>
  {:else}
    <div class="list">
      {#each filtered as item}
        {@const l = lvl(item.categories)}
        <button class="item" on:click={() => dispatch('restore', item)}>
          <div class="item-left">
            <span class="item-ip">{item.ip}</span>
            <span class="item-loc">{item.country || '—'}</span>
            {#if item.categories?.length && !(item.categories.length === 1 && item.categories[0] === 'Unknown')}
              <div class="item-cats">
                {#each item.categories.slice(0,2) as cat}
                  <span class="mini-tag">{cat}</span>
                {/each}
                {#if item.categories.length > 2}
                  <span class="mini-tag">+{item.categories.length - 2}</span>
                {/if}
              </div>
            {/if}
          </div>
          <div class="item-right">
            <span class="item-time">{formatTime(item.ts)}</span>
            <span class="dot dot-{l}"></span>
          </div>
        </button>
      {/each}
    </div>
  {/if}
</div>

<style>
  .panel { flex: 1; display: flex; flex-direction: column; overflow: hidden; }

  /* Filters */
  .filters {
    display: flex; flex-wrap: wrap; gap: 6px;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    background: var(--surface2);
  }
  .fsel {
    flex: 1; min-width: 0;
    background: var(--surface);
    border: 1px solid var(--border2);
    color: var(--text);
    font-family: var(--mono);
    font-size: 11px;
    padding: 5px 8px;
    border-radius: 5px;
    outline: none;
    cursor: pointer;
  }
  .fsel:focus { border-color: var(--accent); }
  .fsel option { background: var(--surface); }
  .clear-f {
    background: none;
    border: 1px solid rgba(244,63,94,0.3);
    color: var(--danger);
    font-size: 11px; padding: 4px 8px;
    border-radius: 5px; cursor: pointer;
  }
  .clear-f:hover { background: rgba(244,63,94,0.1); }

  /* Actions */
  .actions {
    display: flex; align-items: center; justify-content: space-between;
    padding: 8px 16px;
    border-bottom: 1px solid var(--border);
  }
  .count { font-size: 11px; color: var(--muted); font-family: var(--mono); }
  .action-btns { display: flex; gap: 8px; align-items: center; }
  .export-hist {
    background: none;
    border: 1px solid rgba(0,229,255,0.25);
    color: var(--accent);
    font-size: 11px; font-family: var(--mono);
    padding: 3px 10px; border-radius: 5px; cursor: pointer;
    transition: all 0.15s;
  }
  .export-hist:hover:not(:disabled) { background: rgba(0,229,255,0.08); }
  .export-hist:disabled { opacity: 0.35; cursor: not-allowed; }
  .clear-all {
    background: none; border: none;
    color: var(--muted); font-size: 11px;
    cursor: pointer; padding: 3px 8px;
    border-radius: 4px; font-family: var(--sans);
    transition: color 0.15s;
  }
  .clear-all:hover { color: var(--danger); }

  /* Empty */
  .empty {
    flex: 1; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    gap: 10px; color: rgba(100,116,139,0.5);
    font-size: 12px; font-family: var(--mono);
    padding: 40px 16px;
  }
  .empty-icon { font-size: 28px; opacity: 0.3; }

  /* List */
  .list { flex: 1; overflow-y: auto; padding: 4px 0; }
  .list::-webkit-scrollbar { width: 3px; }
  .list::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }

  .item {
    width: 100%; background: none; border: none;
    padding: 10px 16px; display: flex;
    align-items: flex-start; justify-content: space-between;
    cursor: pointer; transition: background 0.15s; text-align: left;
    gap: 8px;
  }
  .item:hover { background: var(--surface2); }

  .item-left { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
  .item-ip { font-family: var(--mono); font-size: 12.5px; font-weight: 500; color: var(--accent); }
  .item-loc { font-size: 11px; color: var(--muted); }

  .item-cats { display: flex; flex-wrap: wrap; gap: 3px; margin-top: 2px; }
  .mini-tag {
    font-size: 10px; padding: 1px 5px;
    border-radius: 3px; font-family: var(--mono);
    background: rgba(244,63,94,0.1);
    color: rgba(244,63,94,0.8);
    border: 1px solid rgba(244,63,94,0.2);
  }

  .item-right { display: flex; flex-direction: column; align-items: flex-end; gap: 6px; flex-shrink: 0; padding-top: 2px; }
  .item-time { font-size: 10px; color: var(--muted); font-family: var(--mono); opacity: 0.6; white-space: nowrap; }

  .dot { width: 7px; height: 7px; border-radius: 50%; }
  .dot-clean    { background: #10b981; }
  .dot-low      { background: #818cf8; }
  .dot-medium   { background: #f59e0b; box-shadow: 0 0 5px rgba(245,158,11,0.4); }
  .dot-high     { background: #f87171; box-shadow: 0 0 5px rgba(239,68,68,0.4); }
  .dot-critical { background: #fb7185; box-shadow: 0 0 5px rgba(244,63,94,0.5); animation: blink 1.2s ease infinite; }

  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
</style>
