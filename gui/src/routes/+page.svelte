<script lang="ts">
  import { antivirusStore } from '$lib/stores/antivirus';
  import { onMount } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import ScanView from './Scan.svelte';
  import ScanConfigView from './ScanConfig.svelte';
  import ProtectionView from '$components/widgets/SystemStatus.svelte';
  import QuarantineView from './Quarantine.svelte';
  import SettingsView from './Settings.svelte';
  import { manageListeners } from '$lib/tauriEvents';
  import type { ProtectionStatus, ThreatEntry, ScanRecord, ThreatStatistics } from '$lib/stores/statusStore';
  import Sidebar from '$components/Sidebar.svelte';
  import Header from '$components/Header.svelte';
  import NotificationCenter from '$components/NotificationCenter.svelte';
  import type { Notification } from '$lib/types';
  import { invoke } from '@tauri-apps/api/tauri';
  import { protectionStatus, scanHistory, threatStats } from '$lib/stores/statusStore';
  import { formatBytes, formatDuration, formatDate } from '$lib/utils';
  
  // UI Components
  import StatusCard from '$lib/components/StatusCard.svelte';
  import ScanHistoryList from '$lib/components/ScanHistoryList.svelte';
  import ThreatCard from '$lib/components/ThreatCard.svelte';
  import ActionButton from '$lib/components/ActionButton.svelte';

  let currentView = 'dashboard';
  let systemStatus = 'Protection status unavailable';
  let loading = true;
  let scanInProgress = false;
  let scanProgress = 0;
  let scanTarget = '';
  let lastScanDate: Date | null = null;

  onMount(() => {
    const stopEvents = manageListeners([
      listen<Notification>('notification', event => antivirusStore.addNotification(event.payload)),
      listen<ThreatEntry>('threat-detected', ({ payload }) => {
        threatStats.update(current => ({
          ...current,
          recent_threats: [payload, ...current.recent_threats].slice(0, 5)
        }));
      }),
      listen<{ progress: number; currentFile: string }>('scan-progress', ({ payload }) => {
        scanInProgress = true;
        scanProgress = payload.progress;
        scanTarget = payload.currentFile;
      }),
      listen<ScanRecord>('scan-completed', ({ payload }) => {
        scanInProgress = false;
        scanProgress = 0;
        lastScanDate = new Date(payload.completed_at);
        scanHistory.update(history => [payload, ...history].slice(0, 10));
      }),
      listen<{ enabled: boolean; monitoredPaths: string[] }>('protection-status-changed', ({ payload }) => {
        protectionStatus.update(status => ({
          ...status, enabled: payload.enabled, monitored_paths: payload.monitoredPaths
        }));
        systemStatus = payload.enabled ? 'Protected' : 'At Risk';
      })
    ]);
    void loadStatus();
    return stopEvents;
  });

  async function loadStatus() {
    // Get initial status
    try {
      const status = await invoke<ProtectionStatus>('get_protection_status');
      protectionStatus.set(status);
      systemStatus = status.enabled ? 'Protected' : 'At Risk';
      
      const history = await invoke<ScanRecord[]>('get_scan_history');
      scanHistory.set(history);
      
      const stats = await invoke<ThreatStatistics>('get_threat_statistics');
      threatStats.set(stats);
      
      if (history.length > 0) {
        lastScanDate = new Date(history[0].completed_at);
      }
    } catch (error) {
      console.error('Failed to get initial status:', error);
    } finally {
      loading = false;
    }

  }

  async function startQuickScan() {
    try {
      scanInProgress = true;
      await invoke('start_quick_scan');
    } catch (error) {
      console.error('Failed to start quick scan:', error);
      scanInProgress = false;
    }
  }
  
  async function startFullScan() {
    try {
      scanInProgress = true;
      await invoke('start_full_scan');
    } catch (error) {
      console.error('Failed to start full scan:', error);
      scanInProgress = false;
    }
  }
  
  async function toggleProtection() {
    try {
      const currentStatus = $protectionStatus.enabled;
      await invoke(currentStatus ? 'disable_protection' : 'enable_protection');
    } catch (error) {
      console.error('Failed to toggle protection:', error);
    }
  }
</script>

<div class="min-h-screen bg-gray-100 dark:bg-gray-900">
  <Header route={currentView} protectionStatus={$protectionStatus} />
  
  <div class="flex">
    <Sidebar route={currentView} navigate={view => currentView = view} protectionStatus={$protectionStatus} on:toggleProtection={toggleProtection} />
    
    <main class="flex-1 p-6">
      {#if currentView === 'dashboard'}
        <div class="container mx-auto px-4 py-8">
          <h1 class="text-3xl font-bold mb-6">Dashboard</h1>
          
          {#if loading}
            <div class="flex justify-center items-center h-64">
              <div class="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
            </div>
          {:else}
            <!-- Status Overview -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
              <StatusCard 
                title="System Status" 
                status={systemStatus} 
                statusType={$protectionStatus.enabled ? 'success' : 'danger'} 
                icon="shield"
              />
              
              <StatusCard 
                title="Real-time Protection" 
                status={$protectionStatus.enabled ? 'Enabled' : 'Disabled'} 
                statusType={$protectionStatus.enabled ? 'success' : 'danger'}
                icon="activity"
                action={toggleProtection}
                actionText={$protectionStatus.enabled ? 'Disable' : 'Enable'}
              />
              
              <StatusCard 
                title="Last Scan" 
                status={lastScanDate ? formatDate(lastScanDate) : 'Never'} 
                statusType="info"
                icon="clock"
              />
            </div>
            
            <!-- Quick Actions -->
            <div class="bg-white rounded-lg shadow-md p-6 mb-8">
              <h2 class="text-xl font-semibold mb-4">Quick Actions</h2>
              <div class="flex flex-wrap gap-4">
                <ActionButton 
                  text="Quick Scan" 
                  icon="search" 
                  onClick={startQuickScan} 
                  disabled={scanInProgress}
                  primary={true}
                />
                
                <ActionButton 
                  text="Full Scan" 
                  icon="hard-drive" 
                  onClick={startFullScan} 
                  disabled={scanInProgress}
                />
                
                <ActionButton 
                  text="Update Signatures" 
                  icon="download" 
                  onClick={() => invoke('update_signatures')}
                  disabled={scanInProgress}
                />
                
                <ActionButton 
                  text="Quarantine" 
                  icon="archive" 
                  onClick={() => window.location.href = '/quarantine'}
                />
              </div>
              
              {#if scanInProgress}
                <div class="mt-6">
                  <p class="mb-2 text-sm text-gray-600">Scanning: {scanTarget}</p>
                  <div class="w-full bg-gray-200 rounded-full h-2.5">
                    <div class="bg-blue-600 h-2.5 rounded-full" style="width: {scanProgress}%"></div>
                  </div>
                  <div class="flex justify-between mt-1">
                    <span class="text-xs text-gray-500">{scanProgress}% Complete</span>
                    <button class="text-xs text-red-500 hover:text-red-700" on:click={() => invoke('cancel_scan')}>
                      Cancel
                    </button>
                  </div>
                </div>
              {/if}
            </div>
            
            <!-- Two Column Layout for History and Threats -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <!-- Scan History -->
              <div class="bg-white rounded-lg shadow-md p-6">
                <h2 class="text-xl font-semibold mb-4">Recent Scans</h2>
                <ScanHistoryList history={$scanHistory} />
              </div>
              
              <!-- Recent Threats -->
              <div class="bg-white rounded-lg shadow-md p-6">
                <h2 class="text-xl font-semibold mb-4">Recent Threats</h2>
                
                {#if $threatStats.recent_threats.length === 0}
                  <div class="text-center py-8 text-gray-500">
                    <p>No threats detected</p>
                    <p class="text-sm mt-2">Your system is clean!</p>
                  </div>
                {:else}
                  <div class="space-y-4">
                    {#each $threatStats.recent_threats as threat}
                      <ThreatCard {threat} />
                    {/each}
                  </div>
                {/if}
                
                <div class="mt-6 p-4 bg-gray-50 rounded-lg">
                  <h3 class="text-lg font-medium mb-2">Threat Statistics</h3>
                  <div class="grid grid-cols-2 gap-4">
                    <div>
                      <p class="text-sm text-gray-500">Total Detected</p>
                      <p class="text-xl font-bold">{$threatStats.total_detected}</p>
                    </div>
                    <div>
                      <p class="text-sm text-gray-500">In Quarantine</p>
                      <p class="text-xl font-bold">{$threatStats.in_quarantine}</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          {/if}
        </div>
      {:else if currentView === 'scan'}
        <ScanView />
      {:else if currentView === 'scan-config'}
        <ScanConfigView />
      {:else if currentView === 'protection'}
        <ProtectionView />
      {:else if currentView === 'quarantine'}
        <QuarantineView />
      {:else if currentView === 'settings'}
        <SettingsView />
      {/if}
    </main>

    <NotificationCenter />
  </div>
</div>

<style lang="postcss">
  :global(html) {
    @apply antialiased;
  }
  
  :global(body) {
    @apply bg-gray-100 dark:bg-gray-900 text-gray-900 dark:text-gray-100;
  }
</style>
