<script>
  export let rateLimits = { single: null, batch: null }
  export let mode = 'single'

  $: current = mode === 'single' ? rateLimits.single : rateLimits.batch
  $: pct = current ? Math.round((current.requests_in_window / current.safe_limit) * 100) : 0
  $: statusColor = current?.paused ? 'danger' : pct > 80 ? 'warn' : 'ok'
</script>

<div class="rate-meter" title="{mode} mode rate limit status">
  <div class="meter-label">
    {#if current?.paused}
      <span class="status-dot dot-danger"></span>
      <span class="label-text warn-text">Paused {current.paused_until}s</span>
    {:else if current}
      <span class="status-dot dot-{statusColor}"></span>
      <span class="label-text">{current.remaining ?? '?'} reqs left</span>
    {:else}
      <span class="status-dot dot-idle"></span>
      <span class="label-text">—</span>
    {/if}
  </div>
  <div class="bar-track">
    <div class="bar-fill bar-{statusColor}" style="width: {Math.min(pct, 100)}%"></div>
  </div>
</div>

<style>
  .rate-meter {
    display: flex; align-items: center; gap: 10px;
    font-size: 12px; font-family: var(--mono);
  }
  .meter-label {
    display: flex; align-items: center; gap: 6px; min-width: 110px;
  }
  .status-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
  .dot-ok     { background: #10b981; box-shadow: 0 0 6px rgba(16,185,129,0.5); }
  .dot-warn   { background: #f59e0b; box-shadow: 0 0 6px rgba(245,158,11,0.5); }
  .dot-danger { background: #f43f5e; box-shadow: 0 0 6px rgba(244,63,94,0.5); animation: blink 1s ease infinite; }
  .dot-idle   { background: var(--muted); }
  .label-text { color: var(--muted); }
  .warn-text  { color: var(--warn); }
  .bar-track  { width: 80px; height: 4px; background: var(--border2); border-radius: 2px; overflow: hidden; }
  .bar-fill   { height: 100%; border-radius: 2px; transition: width 0.5s ease, background 0.3s; }
  .bar-ok     { background: #10b981; }
  .bar-warn   { background: #f59e0b; }
  .bar-danger { background: #f43f5e; }
  @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
</style>
