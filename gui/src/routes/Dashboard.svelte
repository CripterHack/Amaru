<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  import { ask } from '@tauri-apps/api/dialog';
  import { listen } from '@tauri-apps/api/event';
  import { formatDate, formatTimeElapsed } from '../lib/utils';
  import { manageListeners } from '../lib/tauriEvents';
  import type { ProtectionStatus, ThreatStatistics, ThreatEntry, ScanRecord, ScanProgress } from '../lib/stores/statusStore';
  import { notify } from '../lib/components/Notifications.svelte';

  export let protectionStatus: ProtectionStatus | null;
  let loading = true;
  let error = '';
  let resources: { cpu_usage: number; memory_usage: number } | null = null;
  let statistics: ThreatStatistics | null = null;
  let recentThreats: ThreatEntry[] = [];
  let history: ScanRecord[] = [];
  let scanning = false;
  let toggling = false;
  let isLoadingActivityLog = true;
  type Activity = { id: string; type: string; message: string; date: string; status: string };
  let activityLog: Activity[] = [];
  const protectionFeatures = [
    { id: 'realtime', name: 'Real-time Protection', icon: 'shield-check' },
    { id: 'web', name: 'Web Protection', icon: 'globe' },
    { id: 'email', name: 'Email Protection', icon: 'mail' },
    { id: 'ransomware', name: 'Ransomware Protection', icon: 'lock' },
    { id: 'behavior', name: 'Behavior Monitoring', icon: 'activity' },
    { id: 'vulnerability', name: 'Vulnerability Scanner', icon: 'alert-circle' }
  ];
  $: enabled = protectionStatus?.enabled ?? false;

  async function loadData() {
    try {
      const [stats, records, activities] = await Promise.all([
        invoke<ThreatStatistics>('get_threat_statistics'), invoke<ScanRecord[]>('get_scan_history'),
        invoke<Activity[]>('get_activity_log')
      ]);
      statistics = stats; recentThreats = stats.recent_threats;
      history = records; activityLog = activities; error = '';
    } catch (err) { error = String(err); }
    finally { loading = false; isLoadingActivityLog = false; }
  }

  async function refreshResources() {
    try { resources = await invoke('get_system_resources'); }
    catch { resources = null; }
  }

  async function startScan() {
    if (scanning) return;
    scanning = true;
    try { await invoke('start_quick_scan'); }
    catch (err) { scanning = false; notify('Scan failed', String(err), 'error'); }
  }

  async function toggleFeature(id: string) {
    if (toggling || !protectionStatus || id !== 'realtime') return;
    const enable = !enabled;
    toggling = true;
    try {
      await invoke('toggle_protection_feature', { featureId: id, enable });
      enabled = enable;
    } catch (err) { notify('Action failed', String(err), 'error'); }
    finally { toggling = false; }
  }

  async function quarantine(threat: ThreatEntry) {
    if (!threat.session_id || !await ask(`Move ${threat.path} to desktop quarantine?`, { title: 'Confirm quarantine', type: 'warning' })) return;
    try {
      await invoke('quarantine_detection', { sessionId: threat.session_id, threatId: threat.id });
      await loadData();
    } catch (err) { notify('Quarantine failed', String(err), 'error'); }
  }

  onMount(() => {
    let active = true;
    let generation = 0;
    const subscriptions = [
      listen<ScanProgress>('scan-progress', () => { generation++; scanning = true; }),
      listen<ScanRecord>('scan-completed', () => { generation++; scanning = false; void loadData(); }),
      listen<ThreatEntry>('threat-detected', ({ payload }) => {
        recentThreats = [payload, ...recentThreats.slice(0, 9)];
      })
    ];
    const stop = manageListeners(subscriptions);
    void Promise.all(subscriptions).then(async () => {
      const before = generation;
      const progress = await invoke<ScanProgress | null>('get_scan_progress');
      if (active && before === generation) scanning = !!progress;
    }).catch(err => error = String(err));
    void loadData(); void refreshResources();
    const timer = setInterval(refreshResources, 5000);
    return () => { active = false; clearInterval(timer); stop(); };
  });
</script>

<div class="container mx-auto px-4 py-8">
  <h1 class="text-3xl font-bold mb-8">Dashboard</h1>
  
  <!-- System Status Overview -->
  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
    <!-- Protection Status -->
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <div class="flex justify-between items-start mb-4">
        <div>
          <h2 class="text-xl font-semibold">Protection Status</h2>
          <p class="text-gray-500 dark:text-gray-400 text-sm mt-1">Your system protection overview</p>
        </div>
        {#if protectionStatus === null}
          <span class="text-sm text-gray-500">Protection status unavailable</span>
        {:else}
          <span class={`px-3 py-1 rounded-full text-sm font-medium ${enabled ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300' : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'}`}>
            {enabled ? 'Protected' : 'At Risk'}
          </span>
        {/if}
      </div>
      
      <div class="mt-4">
        <div class="space-y-2">
          <div class="flex justify-between">
            <span class="text-gray-600 dark:text-gray-400">Last Scan:</span>
            <span class="font-medium">{history[0] ? formatDate(history[0].completed_at) : '—'}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-600 dark:text-gray-400">Threats detected:</span>
            <span class="font-medium">{statistics?.total_detected ?? '—'}</span>
          </div>
        </div>
        
        <button 
          class="mt-6 w-full py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-md transition-colors"
          on:click={startScan}
          disabled={scanning}
        >
          {scanning ? 'Scanning...' : 'Run Quick Scan'}
        </button>
      </div>
    </div>
    
    <!-- System Resources -->
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h2 class="text-xl font-semibold mb-4">System Resources</h2>
      
      <div class="space-y-6">
        <!-- CPU Usage -->
        <div>
          <div class="flex justify-between mb-1">
            <span class="text-gray-600 dark:text-gray-400 text-sm">CPU Usage</span>
            <span class="text-gray-600 dark:text-gray-400 text-sm">{resources ? Math.round(resources.cpu_usage) + '%' : '—'}</span>
          </div>
          <div class="w-full bg-gray-200 rounded-full h-2.5 dark:bg-gray-700">
            <div class="bg-blue-600 h-2.5 rounded-full" style={`width: ${resources?.cpu_usage ?? 0}%`}></div>
          </div>
        </div>
        
        <!-- Memory Usage -->
        <div>
          <div class="flex justify-between mb-1">
            <span class="text-gray-600 dark:text-gray-400 text-sm">Memory Usage</span>
            <span class="text-gray-600 dark:text-gray-400 text-sm">{resources ? Math.round(resources.memory_usage) + '%' : '—'}</span>
          </div>
          <div class="w-full bg-gray-200 rounded-full h-2.5 dark:bg-gray-700">
            <div class="bg-purple-600 h-2.5 rounded-full" style={`width: ${resources?.memory_usage ?? 0}%`}></div>
          </div>
        </div>
        
      </div>
    </div>

    <!-- Protection Features -->
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h2 class="text-xl font-semibold mb-4">Protection Features</h2>
      
      <div class="space-y-3">
        {#each protectionFeatures as feature}
          <div class="flex items-center justify-between py-2 border-b border-gray-100 dark:border-gray-700 last:border-0">
            <div class="flex items-center space-x-3">
              <div class={`p-1.5 rounded-full ${(feature.id === 'realtime' && enabled) ? 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'}`}>
                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  {#if feature.icon === 'shield-check'}
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  {:else if feature.icon === 'globe'}
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  {:else if feature.icon === 'mail'}
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                  {:else if feature.icon === 'lock'}
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  {:else if feature.icon === 'activity'}
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                  {:else if feature.icon === 'alert-circle'}
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  {/if}
                </svg>
              </div>
              <span class={`${(feature.id === 'realtime' && enabled) ? 'font-medium' : 'text-gray-500 dark:text-gray-400'}`}>
                {feature.name}{feature.id === 'realtime' ? '' : ' (unavailable)'}
              </span>
            </div>
            <label class="relative inline-flex items-center cursor-pointer">
              <input 
                type="checkbox" 
                class="sr-only peer" 
                aria-label={feature.name}{feature.id === 'realtime' ? '' : ' (unavailable)'}
                checked={(feature.id === 'realtime' && enabled)}
                disabled={toggling || feature.id !== 'realtime' || !protectionStatus}
                on:click|preventDefault={() => toggleFeature(feature.id)}
              >
              <div class="w-9 h-5 bg-gray-200 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
            </label>
          </div>
        {/each}
      </div>
    </div>
  </div>
  
  <!-- Second Row -->
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <!-- Recent Threats -->
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h2 class="text-xl font-semibold mb-4">Recent Threats</h2>
      
      {#if loading}
        <div role="status" aria-label="Loading recent threats" class="flex justify-center items-center py-8">
          <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
        </div>
      {:else if error}
        <p role="alert">{error}</p>
      {:else if recentThreats.length === 0}
        <div class="text-center py-6">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-12 w-12 mx-auto text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <p class="mt-2 text-gray-500 dark:text-gray-400">No threats detected</p>
        </div>
      {:else}
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead>
              <tr>
                <th scope="col" class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider">Threat</th>
                <th scope="col" class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider">Path</th>
                <th scope="col" class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider">Date</th>
                <th scope="col" class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider">Status</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
              {#each recentThreats as threat}
                <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                  <td class="px-4 py-3 whitespace-nowrap">
                    <div class="text-sm font-medium text-red-600 dark:text-red-400">{threat.name}</div>
                  </td>
                  <td class="px-4 py-3">
                    <div class="text-sm text-gray-500 dark:text-gray-400 truncate max-w-[200px]" title={threat.path}>
                      {threat.path}
                    </div>
                  </td>
                  <td class="px-4 py-3 whitespace-nowrap">
                    <div class="text-sm text-gray-500 dark:text-gray-400">{formatTimeElapsed(threat.detected_at)}</div>
                  </td>
                  <td class="px-4 py-3 whitespace-nowrap">
                    <span class={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${threat.in_quarantine ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'}`}>
                      {threat.in_quarantine ? 'Quarantined' : 'Detected'}
                    </span>
                    {#if !scanning && threat.session_id && !threat.in_quarantine}
                      <button class="ml-2 text-blue-600" on:click={() => quarantine(threat)}>Quarantine</button>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        
        <div class="mt-4 text-right">
          <a href="#/quarantine" class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 text-sm">
            View all in quarantine →
          </a>
        </div>
      {/if}
    </div>
    
    <!-- Activity Log -->
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h2 class="text-xl font-semibold mb-4">Activity Log</h2>
      
      {#if isLoadingActivityLog}
        <div class="flex justify-center items-center py-8">
          <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
        </div>
      {:else if activityLog.length === 0}
        <div class="text-center py-6">
          <svg xmlns="http://www.w3.org/2000/svg" class="h-12 w-12 mx-auto text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
          </svg>
          <p class="mt-2 text-gray-500 dark:text-gray-400">No activity recorded</p>
        </div>
      {:else}
        <div class="space-y-4">
          {#each activityLog as activity}
            <div class="flex space-x-3">
              <div class={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center
                ${activity.status === 'success' ? 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400' : 
                  activity.status === 'warning' ? 'bg-yellow-100 text-yellow-600 dark:bg-yellow-900/30 dark:text-yellow-400' : 
                  activity.status === 'error' ? 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400' : 
                  'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400'}`}>
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  {#if activity.type === 'scan'}
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  {:else if activity.type === 'update'}
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  {:else if activity.type === 'threat'}
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  {:else if activity.type === 'system'}
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                  {/if}
                </svg>
              </div>
              <div class="min-w-0 flex-1">
                <div class="text-sm font-medium">{activity.message}</div>
                <div class="mt-1 text-xs text-gray-500 dark:text-gray-400">{formatDate(activity.date)}</div>
              </div>
            </div>
          {/each}
        </div>
      {/if}
      
      <div class="mt-4 text-right">
        <a href="#/scan" class="text-blue-600 text-sm">View full history →</a>
      </div>
    </div>
  </div>
</div> 