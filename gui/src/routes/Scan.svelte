<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  import { notify } from '../lib/components/Notifications.svelte';
  
  // Scan states
  import { listen } from '@tauri-apps/api/event';
  import { open } from '@tauri-apps/api/dialog';
  import { manageListeners } from '../lib/tauriEvents';
  import type { ScanProgress, ScanRecord } from '../lib/stores/statusStore';

  let progress: ScanProgress | null = null;
  let starting = false;
  let cancelling = false;
  let history: ScanRecord[] = [];
  let loadError = '';
  const scanTypes = [
    { id: 'quick', label: 'Quick scan', description: 'Scan your Downloads, Desktop and Documents folders.', icon: 'bolt' },
    { id: 'full', label: 'Full scan', description: 'Scan regular files on the Windows system drive.', icon: 'shield' },
    { id: 'custom', label: 'Custom scan', description: 'Choose a folder to scan.', icon: 'tune' },
    { id: 'scheduled', label: 'Scheduled scan', description: 'View scheduled scan configuration.', icon: 'schedule' }
  ];

  async function refreshHistory() {
    try {
      history = await invoke<ScanRecord[]>('get_scan_history');
      loadError = '';
    } catch (error) { loadError = String(error); }
  }

  onMount(() => {
    let revision = 0;
    let active = true;
    const registrations = [
      listen<ScanProgress>('scan-progress', ({ payload }) => { revision++; progress = payload; }),
      listen<ScanRecord>('scan-completed', () => {
        revision++; progress = null; starting = false; cancelling = false;
        void refreshHistory();
      })
    ];
    const stop = manageListeners(registrations);
    void Promise.all(registrations).then(async () => {
      const before = revision;
      const current = await invoke<ScanProgress | null>('get_scan_progress');
      if (active && revision === before) progress = current;
    }).catch(error => loadError = String(error));
    void refreshHistory();
    return () => { active = false; stop(); };
  });

  async function startScan(type: string) {
    if (progress || starting) return;
    if (type === 'scheduled') { window.location.hash = '#/scan-config'; return; }
    starting = true;
    try {
      if (type === 'custom') {
        const path = await open({ directory: true, multiple: false });
        if (typeof path !== 'string') return;
        await invoke('start_custom_scan', { path });
      } else {
        await invoke(type === 'quick' ? 'start_quick_scan' : 'start_full_scan');
      }
      progress = await invoke<ScanProgress | null>('get_scan_progress');
    } catch (error) {
      notify('Scan error', String(error), 'error');
    } finally { starting = false; }
  }

  async function cancelScan() {
    cancelling = true;
    try { await invoke('cancel_scan'); }
    catch (error) { cancelling = false; notify('Cancellation failed', String(error), 'error'); }
  }

  // Format time
  function formatTime(seconds: number) {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  }
</script>

<div class="container mx-auto px-4 py-8">
  <h1 class="text-3xl font-bold mb-8">Scan</h1>
  
  {#if progress}
    <!-- Scan Progress -->
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6 mb-8">
      <div class="flex justify-between items-center mb-4">
        <h2 class="text-xl font-semibold">Scan in Progress</h2>
        <button 
          on:click={cancelScan} disabled={cancelling} 
          class="px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-md"
        >
          {cancelling ? 'Cancelling…' : 'Cancel scan'}
        </button>
      </div>
      
      <div class="w-full mb-6">
        <p class="truncate text-sm">{progress.currentFile}</p>
      </div>
      
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
        <div class="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
          <p class="text-sm text-gray-500 dark:text-gray-400">Scanned</p>
          <p class="text-2xl font-bold">{progress.filesScanned}</p>
        </div>
        
        <div class="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
          <p class="text-sm text-gray-500 dark:text-gray-400">Threats</p>
          <p class="text-2xl font-bold">{progress.threatsFound}</p>
        </div>
        
        <div class="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
          <p class="text-sm text-gray-500 dark:text-gray-400">Elapsed</p>
          <p class="text-2xl font-bold">{formatTime(Math.floor(progress.elapsedMs / 1000))}</p>
        </div>
        
        <div class="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
          <p class="text-sm text-gray-500 dark:text-gray-400">Speed</p>
          <p class="text-2xl font-bold">{Math.round(progress.filesScanned * 1000 / Math.max(1, progress.elapsedMs))}/s</p>
        </div>
      </div>
    </div>
  {:else}
    <!-- Scan Types -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
      {#each scanTypes as scan}
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow hover:shadow-lg transition-shadow p-6">
          <div class="flex justify-between items-start mb-4">
            <div>
              <h2 class="text-xl font-semibold">{scan.label}</h2>
              <p class="text-gray-600 dark:text-gray-400 text-sm mt-1">{scan.description}</p>
            </div>
            <div class="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-full text-blue-600 dark:text-blue-300">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                {#if scan.icon === 'bolt'}
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
                {:else if scan.icon === 'shield'}
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                {:else if scan.icon === 'tune'}
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
                {:else if scan.icon === 'schedule'}
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                {/if}
              </svg>
            </div>
          </div>
          
          <button 
            disabled={starting} on:click={() => startScan(scan.id)}
            class="w-full mt-4 bg-blue-500 hover:bg-blue-600 text-white py-2 rounded-md transition-colors"
          >
            Start {scan.label}
          </button>
        </div>
      {/each}
    </div>
  {/if}
  
  <!-- Last Scan Results -->
  <div class="mt-8">
    <h2 class="text-xl font-semibold mb-4">Last Scan Results</h2>
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
       {#if loadError}
        <p role="alert">{loadError}</p>
      {:else if history.length === 0}
        <p>No recent scan results available</p>
      {:else}
        <ul>
          {#each history as record (record.id)}
            <li class="py-2">{record.scan_type} · {record.status} · {new Date(record.completed_at).toLocaleString()} ·
              {record.files_scanned} scanned · {record.threats_found} findings ·
              {record.files_failed ?? 0} failed · {record.files_skipped ?? 0} skipped
              {#if record.last_error}<p class="text-sm">{record.last_error}</p>{/if}
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  </div>
</div> 