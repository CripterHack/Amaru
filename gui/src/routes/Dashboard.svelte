<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  import { listen } from '@tauri-apps/api/event';
  import { formatDate, formatBytes, formatDuration, formatTimeElapsed } from '../lib/utils';
  import { 
    protectionStatus as protectionStore, 
    threatStats,
    statusStore,
    type ProtectionStatus,
    type ScanRecord,
    type ThreatStatistics,
    type ThreatEntry
  } from '../lib/stores/statusStore';
  import Chart from '../lib/components/Chart.svelte';
  import StatCard from '../lib/components/StatCard.svelte';
  import { notify } from '../lib/components/Notifications.svelte';
  
  // Props
  export let protectionStatus: ProtectionStatus;
  
  // State
  let statistics: ThreatStatistics | null = null;
  let loading = true;
  let error: string | null = null;
  let systemResources = {
    cpu: 0,
    memory: 0,
    lastUpdated: new Date()
  };
  
  // Event unsubscribe functions
  let unsubscribeResourceUpdate: (() => void) | undefined;
  let unsubscribeScanProgress: (() => void) | undefined;
  let unsubscribeScanCompleted: (() => void) | undefined;
  let unsubscribeThreatsUpdate: (() => void) | undefined;
  let unsubscribeActivityLog: (() => void) | undefined;
  
  let scanHistory: ScanRecord[] = [];
  let isLoadingScanHistory = true;
  
  // Recent threats - will be populated from API
  let recentThreats: ThreatEntry[] = [];
  
  // Activity log
  interface ActivityEntry {
    id: string;
    type: 'scan' | 'update' | 'threat' | 'system';
    message: string;
    date: string;
    status: 'success' | 'warning' | 'error' | 'info';
  }
  
  let activityLog: ActivityEntry[] = [];
  let isLoadingActivityLog = true;
  
  // Reactive declarations
  $: systemStatus = {
    is_protected: protectionStatus?.enabled || false,
    last_scan: 'Never',
    threats_detected: 0,
    realtime_protection: protectionStatus?.enabled || false,
    database_updated: protectionStatus?.last_updated || 'Never',
    system_load: 0
  };
  
  let scanProgress = 0;
  let scanning = false;
  let scanStats = {
    filesScanned: 0,
    threatsFound: 0,
    scanSpeed: 0
  };
  
  // Protection features
  let protectionFeatures = [
    { id: 'realtime', name: 'Real-time Protection', enabled: true, icon: 'shield-check' },
    { id: 'web', name: 'Web Protection', enabled: true, icon: 'globe' },
    { id: 'email', name: 'Email Protection', enabled: true, icon: 'mail' },
    { id: 'ransomware', name: 'Ransomware Protection', enabled: true, icon: 'lock' },
    { id: 'behavior', name: 'Behavior Monitoring', enabled: false, icon: 'activity' },
    { id: 'vulnerability', name: 'Vulnerability Scanner', enabled: false, icon: 'alert-circle' }
  ];
  
  // CPU Usage simulation
  let cpuUsage = 0;
  let memoryUsage = 0;
  
  // Load statistics
  async function loadThreatStatistics() {
    try {
      loading = true;
      const stats = await invoke('get_threat_statistics') as ThreatStatistics;
      statistics = stats;
      recentThreats = stats.recent_threats || [];
      loading = false;
      $threatStats = stats;
    } catch (err: unknown) {
      loading = false;
      error = err instanceof Error ? err.message : String(err);
      console.error('Failed to load threat statistics:', err);
    }
  }
  
  // Update signatures
  async function updateSignatures() {
    try {
      await invoke('update_signatures');
    } catch (err: unknown) {
      error = err instanceof Error ? err.message : String(err);
      console.error('Failed to update signatures:', err);
    }
  }
  
  // Get real-time resource usage
  async function getResourceUsage() {
    try {
      const resources = await invoke('get_system_resources') as {
        cpu_usage: number;
        memory_usage: number;
      };
      systemResources.cpu = resources.cpu_usage || 0;
      systemResources.memory = resources.memory_usage || 0;
      systemResources.lastUpdated = new Date();
    } catch (err: unknown) {
      console.error('Failed to get resource usage:', err);
    }
  }
  
  // Store protection status in the store
  $: {
    if (protectionStatus) {
      protectionStore.set(protectionStatus);
      
      // Update system status based on protection status
      systemStatus = {
        ...systemStatus,
        is_protected: protectionStatus.enabled,
        realtime_protection: protectionStatus.enabled,
        database_updated: protectionStatus.last_updated || 'Never'
      };
      
      // Also update the status store
      $statusStore = {
        ...$statusStore,
        is_protected: protectionStatus.enabled,
        realtime_protection: protectionStatus.enabled,
        database_updated: protectionStatus.last_updated || 'Never'
      };
    }
  }
  
  // Load scan history
  async function loadScanHistory() {
    try {
      isLoadingScanHistory = true;
      const history = await invoke('get_scan_history') as ScanRecord[];
      scanHistory = history;
      isLoadingScanHistory = false;
    } catch (err: unknown) {
      isLoadingScanHistory = false;
      error = err instanceof Error ? err.message : String(err);
      console.error('Failed to load scan history:', err);
    }
  }
  
  // Load activity log
  async function loadActivityLog() {
    try {
      isLoadingActivityLog = true;
      const logs = await invoke('get_activity_log') as ActivityEntry[];
      activityLog = logs;
      isLoadingActivityLog = false;
    } catch (err: unknown) {
      isLoadingActivityLog = false;
      error = err instanceof Error ? err.message : String(err);
      console.error('Failed to load activity log:', err);
    }
  }
  
  // Handle activity log updates
  async function setupActivityLogUpdates() {
    return listen('activity-log-update', (event) => {
      const newActivity = event.payload as ActivityEntry;
      
      // Add to activity log at the beginning of the array
      activityLog = [newActivity, ...activityLog.slice(0, 19)]; // Keep only the 20 most recent entries
    });
  }
  
  // Start a quick scan
  const startScan = async () => {
    try {
      scanning = true;
      scanProgress = 0;
      scanStats = {
        filesScanned: 0,
        threatsFound: 0,
        scanSpeed: 0
      };
      
      notify('Scan started', 'The system scan has been initiated', 'info');
      
      // Start the actual scan
      await invoke('start_quick_scan');
      
      // The scan progress will be reported through events from the backend
      // The event handlers are set up in the onMount function
    } catch (err: unknown) {
      scanning = false;
      error = err instanceof Error ? err.message : String(err);
      console.error('Failed to start scan:', err);
      notify('Scan failed', `Failed to start scan: ${error}`, 'error');
    }
  };
  
  // Toggle real-time protection
  const toggleProtection = async () => {
    try {
      const newStatus = !systemStatus.realtime_protection;
      
      // Call backend to toggle protection
      await invoke('toggle_protection', { enable: newStatus });
      
      // Update local state
      systemStatus.realtime_protection = newStatus;
      systemStatus.is_protected = newStatus;
      
      // Update store
      $statusStore.is_protected = newStatus;
      $statusStore.realtime_protection = newStatus;
      
      // Update protection status store
      protectionStore.update(status => ({
        ...status,
        enabled: newStatus
      }));
      
      notify(
        newStatus ? 'Protection enabled' : 'Protection disabled', 
        `Real-time protection has been ${newStatus ? 'enabled' : 'disabled'}`,
        newStatus ? 'success' : 'warning'
      );
    } catch (err: unknown) {
      error = err instanceof Error ? err.message : String(err);
      console.error('Failed to toggle protection:', err);
      notify('Action failed', `Failed to ${systemStatus.realtime_protection ? 'disable' : 'enable'} protection: ${error}`, 'error');
    }
  };
  
  // Toggle protection feature
  async function toggleFeature(id: string) {
    try {
      const feature = protectionFeatures.find(f => f.id === id);
      if (!feature) return;
      
      const newEnabled = !feature.enabled;
      
      // Call backend to toggle feature
      await invoke('toggle_protection_feature', { featureId: id, enable: newEnabled });
      
      // Update local state
      protectionFeatures = protectionFeatures.map(f => 
        f.id === id ? { ...f, enabled: newEnabled } : f
      );
      
      notify(
        `${feature.name} ${newEnabled ? 'Enabled' : 'Disabled'}`,
        `${feature.name} has been ${newEnabled ? 'enabled' : 'disabled'}`,
        newEnabled ? 'success' : 'warning'
      );
    } catch (err: unknown) {
      error = err instanceof Error ? err.message : String(err);
      console.error(`Failed to toggle feature ${id}:`, err);
      const feature = protectionFeatures.find(f => f.id === id);
      if (feature) {
        notify('Action failed', `Failed to toggle ${feature.name}: ${error}`, 'error');
      }
    }
  }
  
  // Update stats periodically
  function startStatUpdates() {
    const interval = setInterval(() => {
      cpuUsage = Math.min(Math.max(cpuUsage + (Math.random() * 5 - 1.5), 0), 100);
      memoryUsage = Math.min(Math.max(memoryUsage + (Math.random() * 5 - 1.5), 0), 100);
    }, 2000);
    
    return () => clearInterval(interval);
  }
  
  // Resource monitoring
  async function setupResourceMonitoring() {
    return listen('system-resources-update', (event) => {
      const resources = event.payload as { cpu: number, memory: number, lastUpdated: string };
      systemResources.cpu = resources.cpu;
      systemResources.memory = resources.memory;
      systemResources.lastUpdated = new Date();
      
      // Update system status store
      statusStore.update(status => ({
        ...status,
        system_load: resources.cpu
      }));
    });
  }
  
  // Handle scan progress events
  async function setupScanEvents() {
    // Handle scan progress updates
    const scanProgressUnsubscribe = await listen('scan-progress', (event) => {
      const data = event.payload as { progress: number, currentFile: string };
      scanProgress = data.progress;
      scanStats.filesScanned = Math.max(scanStats.filesScanned, scanProgress * 10);
      scanStats.scanSpeed = Math.floor(Math.random() * 100) + 50; // TODO: Get actual scan speed from backend
    });
    
    // Handle scan completion
    const scanCompletedUnsubscribe = await listen('scan-completed', (event) => {
      const result = event.payload as ScanRecord;
      scanning = false;
      scanProgress = 100;
      scanStats.threatsFound = result.threats_found;
      systemStatus.last_scan = formatDate(result.completed_at);
      systemStatus.threats_detected += result.threats_found;
      
      // Update status store
      statusStore.update(status => ({
        ...status,
        last_scan: formatDate(result.completed_at),
        threats_detected: status.threats_detected + result.threats_found
      }));
      
      notify(
        'Scan completed', 
        `Scan completed with ${result.threats_found} threats detected`, 
        result.threats_found > 0 ? 'warning' : 'success'
      );
      
      // Refresh scan history
      loadScanHistory();
    });
    
    return {
      scanProgressUnsubscribe,
      scanCompletedUnsubscribe
    };
  }
  
  // Handle threat updates
  async function setupThreatUpdates() {
    return listen('threat-detected', (event) => {
      const newThreat = event.payload as ThreatEntry;
      
      // Add to recent threats at the beginning of the array
      recentThreats = [newThreat, ...recentThreats.slice(0, 9)];
      
      // Update statistics
      if (statistics) {
        statistics.total_detected += 1;
        statistics.recent_threats = recentThreats;
      }
    });
  }
  
  // Initialize
  onMount(() => {
    // Async setup
    const setup = async () => {
      await loadThreatStatistics();
      getResourceUsage();
      loadScanHistory();
      loadActivityLog();
      
      // Setup real-time update listeners
      const resourceInterval = setInterval(getResourceUsage, 5000);
      
      // Setup system resource monitoring
      unsubscribeResourceUpdate = await setupResourceMonitoring();
      
      // Setup scan event handlers
      const scanEvents = await setupScanEvents();
      unsubscribeScanProgress = scanEvents.scanProgressUnsubscribe;
      unsubscribeScanCompleted = scanEvents.scanCompletedUnsubscribe;
      
      // Setup threat update handler
      unsubscribeThreatsUpdate = await setupThreatUpdates();
      
      // Setup activity log updates
      unsubscribeActivityLog = await setupActivityLogUpdates();
      
      // Initialize CPU and memory usage
      try {
        const resources = await invoke('get_system_resources') as { cpu: number, memory: number };
        systemResources.cpu = resources.cpu;
        systemResources.memory = resources.memory;
        systemResources.lastUpdated = new Date();
      } catch (err) {
        console.error('Failed to get system resources:', err);
      }
      
      // Store interval for cleanup
      return resourceInterval;
    };

    // Start setup and store the promise with interval for cleanup
    const setupPromise = setup();
    
    // Cleanup function
    return () => {
      // Clear the interval when component is destroyed
      setupPromise.then(interval => {
        clearInterval(interval);
      });
      
      if (unsubscribeResourceUpdate) {
        unsubscribeResourceUpdate();
      }
      
      if (unsubscribeScanProgress) {
        unsubscribeScanProgress();
      }
      
      if (unsubscribeScanCompleted) {
        unsubscribeScanCompleted();
      }
      
      if (unsubscribeThreatsUpdate) {
        unsubscribeThreatsUpdate();
      }
      
      if (unsubscribeActivityLog) {
        unsubscribeActivityLog();
      }
    };
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
        <span class={`px-3 py-1 rounded-full text-sm font-medium ${systemStatus.realtime_protection ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300' : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'}`}>
          {systemStatus.realtime_protection ? 'Protected' : 'At Risk'}
        </span>
      </div>
      
      <div class="mt-4">
        <div class="relative pt-1">
          <div class="flex mb-2 items-center justify-between">
            <div>
              <span class="text-xs font-semibold inline-block py-1 px-2 uppercase rounded-full text-blue-600 bg-blue-200 dark:bg-blue-900/50 dark:text-blue-300">
                System Score
              </span>
            </div>
            <div class="text-right">
              <span class="text-xs font-semibold inline-block">
                {systemStatus.system_load.toFixed(0)}/100
              </span>
            </div>
          </div>
          <div class="overflow-hidden h-2 mb-4 text-xs flex rounded bg-gray-200 dark:bg-gray-700">
            <div
              style={`width: ${systemStatus.system_load}%`}
              class={`shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center 
                ${systemStatus.system_load > 80 ? 'bg-green-500' : systemStatus.system_load > 50 ? 'bg-yellow-500' : 'bg-red-500'}`}
            ></div>
          </div>
        </div>
        
        <div class="space-y-2">
          <div class="flex justify-between">
            <span class="text-gray-600 dark:text-gray-400">Last Scan:</span>
            <span class="font-medium">{systemStatus.last_scan}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-600 dark:text-gray-400">Threats detected:</span>
            <span class="font-medium">{systemStatus.threats_detected}</span>
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
            <span class="text-gray-600 dark:text-gray-400 text-sm">{Math.round(cpuUsage)}%</span>
          </div>
          <div class="w-full bg-gray-200 rounded-full h-2.5 dark:bg-gray-700">
            <div class="bg-blue-600 h-2.5 rounded-full" style={`width: ${cpuUsage}%`}></div>
          </div>
        </div>
        
        <!-- Memory Usage -->
        <div>
          <div class="flex justify-between mb-1">
            <span class="text-gray-600 dark:text-gray-400 text-sm">Memory Usage</span>
            <span class="text-gray-600 dark:text-gray-400 text-sm">{Math.round(memoryUsage)}%</span>
          </div>
          <div class="w-full bg-gray-200 rounded-full h-2.5 dark:bg-gray-700">
            <div class="bg-purple-600 h-2.5 rounded-full" style={`width: ${memoryUsage}%`}></div>
          </div>
        </div>
        
        <!-- Disk Usage -->
        <div>
          <div class="flex justify-between mb-1">
            <span class="text-gray-600 dark:text-gray-400 text-sm">Disk Usage (C:)</span>
            <span class="text-gray-600 dark:text-gray-400 text-sm">68%</span>
          </div>
          <div class="w-full bg-gray-200 rounded-full h-2.5 dark:bg-gray-700">
            <div class="bg-amber-500 h-2.5 rounded-full" style="width: 68%"></div>
          </div>
        </div>
      </div>
      
      <div class="mt-6 p-4 bg-blue-50 dark:bg-blue-900/30 rounded-md">
        <div class="flex">
          <div class="flex-shrink-0">
            <svg class="h-5 w-5 text-blue-600 dark:text-blue-300" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
            </svg>
          </div>
          <div class="ml-3">
            <p class="text-sm text-blue-800 dark:text-blue-300">
              Amaru is using minimal system resources while providing maximum protection.
            </p>
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
              <div class={`p-1.5 rounded-full ${feature.enabled ? 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'}`}>
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
              <span class={`${feature.enabled ? 'font-medium' : 'text-gray-500 dark:text-gray-400'}`}>
                {feature.name}
              </span>
            </div>
            <label class="relative inline-flex items-center cursor-pointer">
              <input 
                type="checkbox" 
                class="sr-only peer" 
                checked={feature.enabled} 
                on:change={() => toggleFeature(feature.id)}
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
        <div class="flex justify-center items-center py-8">
          <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
        </div>
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
                      {threat.in_quarantine ? 'Quarantined' : 'Resolved'}
                    </span>
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
        <button class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 text-sm">
          View full history →
        </button>
      </div>
    </div>
  </div>
</div> 