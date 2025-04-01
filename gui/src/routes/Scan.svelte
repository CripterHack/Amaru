<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  import { notify } from '../lib/components/Notifications.svelte';
  
  // Scan states
  let scanning = false;
  let scanProgress = 0;
  let scanResults = {
    scanned: 0,
    threats: 0,
    elapsed: 0,
    speed: 0
  };
  
  // Scan types
  const scanTypes = [
    { id: 'quick', label: 'Quick Scan', description: 'Checks the most vulnerable areas of your system', time: '2-5 minutes', icon: 'bolt' },
    { id: 'full', label: 'Full Scan', description: 'Thoroughly checks your entire system', time: '30-60 minutes', icon: 'shield' },
    { id: 'custom', label: 'Custom Scan', description: 'Scan specific locations of your choice', time: 'Varies', icon: 'tune' },
    { id: 'scheduled', label: 'Scheduled Scan', description: 'Manage your scheduled scans', time: 'Configured', icon: 'schedule' }
  ];
  
  // Start scan
  async function startScan(type: string) {
    if (scanning) return;
    
    scanning = true;
    scanProgress = 0;
    scanResults = { scanned: 0, threats: 0, elapsed: 0, speed: 0 };
    
    try {
      notify('Scan Started', `${type.charAt(0).toUpperCase() + type.slice(1)} scan has been initiated`, 'info');
      
      // In a real app, we would invoke the Tauri backend
      // await invoke('start_scan', { type });
      
      // For demo, we'll simulate a scan
      const interval = setInterval(() => {
        scanProgress += 1;
        scanResults.scanned += Math.floor(Math.random() * 50) + 10;
        scanResults.speed = Math.floor(Math.random() * 100) + 50;
        scanResults.elapsed += 1;
        
        if (Math.random() > 0.95) {
          scanResults.threats += 1;
          notify('Threat Found', 'A potential threat was detected', 'warning');
        }
        
        if (scanProgress >= 100) {
          clearInterval(interval);
          scanning = false;
          notify('Scan Completed', `Scan complete: ${scanResults.threats} threats found`, 
            scanResults.threats > 0 ? 'warning' : 'success');
        }
      }, type === 'quick' ? 100 : type === 'full' ? 200 : 150);
    } catch (error) {
      console.error('Failed to start scan:', error);
      scanning = false;
      notify('Scan Error', `Failed to start scan: ${error}`, 'error');
    }
  }
  
  // Cancel scan
  function cancelScan() {
    // In a real app, we would invoke the Tauri backend
    // await invoke('cancel_scan');
    scanning = false;
    notify('Scan Cancelled', 'The current scan has been cancelled', 'info');
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
  
  {#if scanning}
    <!-- Scan Progress -->
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6 mb-8">
      <div class="flex justify-between items-center mb-4">
        <h2 class="text-xl font-semibold">Scan in Progress</h2>
        <button 
          on:click={cancelScan} 
          class="px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-md"
        >
          Cancel
        </button>
      </div>
      
      <div class="w-full bg-gray-200 rounded-full h-2.5 mb-6 dark:bg-gray-700">
        <div class="bg-blue-600 h-2.5 rounded-full" style="width: {scanProgress}%"></div>
      </div>
      
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
        <div class="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
          <p class="text-sm text-gray-500 dark:text-gray-400">Scanned</p>
          <p class="text-2xl font-bold">{scanResults.scanned}</p>
        </div>
        
        <div class="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
          <p class="text-sm text-gray-500 dark:text-gray-400">Threats</p>
          <p class="text-2xl font-bold">{scanResults.threats}</p>
        </div>
        
        <div class="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
          <p class="text-sm text-gray-500 dark:text-gray-400">Elapsed</p>
          <p class="text-2xl font-bold">{formatTime(scanResults.elapsed)}</p>
        </div>
        
        <div class="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
          <p class="text-sm text-gray-500 dark:text-gray-400">Speed</p>
          <p class="text-2xl font-bold">{scanResults.speed}/s</p>
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
              <p class="text-gray-500 dark:text-gray-500 text-xs mt-2">Estimated time: {scan.time}</p>
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
            on:click={() => startScan(scan.id)}
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
      <p class="text-gray-500 dark:text-gray-400">No recent scan results available</p>
    </div>
  </div>
</div> 