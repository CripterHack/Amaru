<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  import { theme } from '../lib/stores/theme';
  import { notify } from '../lib/components/Notifications.svelte';
  
  // Settings state
  type Settings = {
    protection: {
      realtimeEnabled: boolean;
      startOnBoot: boolean;
      scanCompressed: boolean;
      scanEmail: boolean;
      exclusions: string[];
    };
    scanning: {
      scanDepth: number;
      heuristicLevel: 'low' | 'medium' | 'high';
      useStaticAnalysis: boolean;
      useBehaviorAnalysis: boolean;
    };
    updates: {
      autoUpdate: boolean;
      updateFrequency: 'daily' | 'weekly' | 'monthly';
      betaUpdates: boolean;
    };
    notifications: {
      showNotifications: boolean;
      notifyOnThreats: boolean;
      notifyOnScanComplete: boolean;
      notifyOnUpdate: boolean;
    };
    advanced: {
      logLevel: 'error' | 'warn' | 'info' | 'debug';
      maxLogSize: number;
      quarantineLocation: string;
    };
    appearance: {
      theme: 'light' | 'dark' | 'system';
      animations: boolean;
      compactMode: boolean;
    };
  };
  
  let settings: Settings = {
    protection: {
      realtimeEnabled: true,
      startOnBoot: true,
      scanCompressed: true,
      scanEmail: true,
      exclusions: []
    },
    scanning: {
      scanDepth: 3,
      heuristicLevel: 'medium',
      useStaticAnalysis: true,
      useBehaviorAnalysis: true
    },
    updates: {
      autoUpdate: true,
      updateFrequency: 'daily',
      betaUpdates: false
    },
    notifications: {
      showNotifications: true,
      notifyOnThreats: true,
      notifyOnScanComplete: true,
      notifyOnUpdate: true
    },
    advanced: {
      logLevel: 'info',
      maxLogSize: 100,
      quarantineLocation: ''
    },
    appearance: {
      theme: 'system',
      animations: true,
      compactMode: false
    }
  };
  
  let newExclusion = '';
  let saving = false;
  let saveSuccess = false;
  let saveError = '';
  
  // Load settings
  async function loadSettings() {
    try {
      const result = await invoke('get_settings');
      settings = result as Settings;
    } catch (error) {
      console.error('Failed to load settings:', error);
    }
  }
  
  // Save settings
  async function saveSettings() {
    saving = true;
    saveSuccess = false;
    saveError = '';
    
    try {
      await invoke('save_settings', { settings });
      saveSuccess = true;
      
      // Reset success message after 3 seconds
      setTimeout(() => {
        saveSuccess = false;
      }, 3000);
    } catch (error) {
      console.error('Failed to save settings:', error);
      saveError = error as string;
    } finally {
      saving = false;
    }
  }
  
  // Add exclusion
  function addExclusion() {
    if (newExclusion && !settings.protection.exclusions.includes(newExclusion)) {
      settings.protection.exclusions = [...settings.protection.exclusions, newExclusion];
      newExclusion = '';
    }
  }
  
  // Remove exclusion
  function removeExclusion(exclusion: string) {
    settings.protection.exclusions = settings.protection.exclusions.filter(e => e !== exclusion);
  }
  
  // Reset settings to default
  function resetSettings() {
    if (confirm('Are you sure you want to reset all settings to default values?')) {
      loadSettings();
    }
  }
  
  // Theme change handler
  function handleThemeChange() {
    theme.set(settings.appearance.theme);
    
    if (settings.appearance.theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else if (settings.appearance.theme === 'light') {
      document.documentElement.classList.remove('dark');
    } else {
      // System theme
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      if (prefersDark) {
        document.documentElement.classList.add('dark');
      } else {
        document.documentElement.classList.remove('dark');
      }
    }
  }
  
  onMount(() => {
    loadSettings();
  });
</script>

<div class="p-6">
  <h1 class="text-2xl font-bold mb-6">Settings</h1>
  
  <div class="bg-white dark:bg-gray-800 rounded-lg shadow mb-6">
    <div class="p-4 border-b border-gray-200 dark:border-gray-700">
      <h2 class="text-xl font-semibold">Protection</h2>
    </div>
    <div class="p-4 space-y-4">
      <div class="flex items-center justify-between">
        <div>
          <h3 class="font-medium">Real-time Protection</h3>
          <p class="text-sm text-gray-500 dark:text-gray-400">Monitor and protect your system in real-time</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" bind:checked={settings.protection.realtimeEnabled} class="sr-only peer">
          <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
        </label>
      </div>
      
      <div class="flex items-center justify-between">
        <div>
          <h3 class="font-medium">Start on Boot</h3>
          <p class="text-sm text-gray-500 dark:text-gray-400">Automatically start protection when Windows starts</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" bind:checked={settings.protection.startOnBoot} class="sr-only peer">
          <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
        </label>
      </div>
      
      <div class="flex items-center justify-between">
        <div>
          <h3 class="font-medium">Scan Compressed Files</h3>
          <p class="text-sm text-gray-500 dark:text-gray-400">Scan inside archives and compressed files</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" bind:checked={settings.protection.scanCompressed} class="sr-only peer">
          <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
        </label>
      </div>
      
      <div class="flex items-center justify-between">
        <div>
          <h3 class="font-medium">Scan Email Attachments</h3>
          <p class="text-sm text-gray-500 dark:text-gray-400">Scan email attachments for threats</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" bind:checked={settings.protection.scanEmail} class="sr-only peer">
          <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
        </label>
      </div>
      
      <!-- Exclusions -->
      <div class="mt-6">
        <h3 class="font-medium mb-2">Exclusions</h3>
        <p class="text-sm text-gray-500 dark:text-gray-400 mb-4">Files, folders, and processes to exclude from scanning</p>
        
        <div class="flex">
          <input 
            type="text" 
            bind:value={newExclusion} 
            placeholder="Add path or process to exclude" 
            class="flex-1 px-4 py-2 border border-gray-300 rounded-l-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
          />
          <button 
            on:click={addExclusion}
            class="px-4 py-2 bg-blue-600 text-white rounded-r-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            Add
          </button>
        </div>
        
        <div class="mt-4 max-h-40 overflow-y-auto">
          {#if settings.protection.exclusions.length === 0}
            <p class="text-sm text-gray-500 dark:text-gray-400">No exclusions added</p>
          {:else}
            <ul class="space-y-2">
              {#each settings.protection.exclusions as exclusion}
                <li class="flex justify-between items-center p-2 bg-gray-50 dark:bg-gray-700 rounded">
                  <span class="text-sm truncate">{exclusion}</span>
                  <button 
                    on:click={() => removeExclusion(exclusion)}
                    class="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300"
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                  </button>
                </li>
              {/each}
            </ul>
          {/if}
        </div>
      </div>
    </div>
  </div>
  
  <!-- Scanning Settings -->
  <div class="bg-white dark:bg-gray-800 rounded-lg shadow mb-6">
    <div class="p-4 border-b border-gray-200 dark:border-gray-700">
      <h2 class="text-xl font-semibold">Scanning</h2>
    </div>
    <div class="p-4 space-y-4">
      <div>
        <label class="block font-medium mb-2">Scan Depth</label>
        <p class="text-sm text-gray-500 dark:text-gray-400 mb-2">How deep to scan into directories and archives</p>
        <select 
          bind:value={settings.scanning.scanDepth}
          class="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
        >
          <option value={1}>Low (Faster)</option>
          <option value={3}>Medium</option>
          <option value={5}>High (Thorough)</option>
        </select>
      </div>
      
      <div>
        <label class="block font-medium mb-2">Heuristic Level</label>
        <p class="text-sm text-gray-500 dark:text-gray-400 mb-2">Detects unknown threats based on behavior</p>
        <select 
          bind:value={settings.scanning.heuristicLevel}
          class="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
        >
          <option value="low">Low (Fewer false positives)</option>
          <option value="medium">Medium (Balanced)</option>
          <option value="high">High (Aggressive detection)</option>
        </select>
      </div>
      
      <div class="flex items-center justify-between">
        <div>
          <h3 class="font-medium">Use Static Analysis</h3>
          <p class="text-sm text-gray-500 dark:text-gray-400">Analyze file structures to detect threats</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" bind:checked={settings.scanning.useStaticAnalysis} class="sr-only peer">
          <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
        </label>
      </div>
      
      <div class="flex items-center justify-between">
        <div>
          <h3 class="font-medium">Use Behavior Analysis</h3>
          <p class="text-sm text-gray-500 dark:text-gray-400">Monitor behavior of suspicious files in a sandbox</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" bind:checked={settings.scanning.useBehaviorAnalysis} class="sr-only peer">
          <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
        </label>
      </div>
    </div>
  </div>
  
  <!-- Updates Settings -->
  <div class="bg-white dark:bg-gray-800 rounded-lg shadow mb-6">
    <div class="p-4 border-b border-gray-200 dark:border-gray-700">
      <h2 class="text-xl font-semibold">Updates</h2>
    </div>
    <div class="p-4 space-y-4">
      <div class="flex items-center justify-between">
        <div>
          <h3 class="font-medium">Automatic Updates</h3>
          <p class="text-sm text-gray-500 dark:text-gray-400">Automatically update signatures and application</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" bind:checked={settings.updates.autoUpdate} class="sr-only peer">
          <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
        </label>
      </div>
      
      <div>
        <label class="block font-medium mb-2">Update Frequency</label>
        <p class="text-sm text-gray-500 dark:text-gray-400 mb-2">How often to check for updates</p>
        <select 
          bind:value={settings.updates.updateFrequency}
          class="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
        >
          <option value="daily">Daily</option>
          <option value="weekly">Weekly</option>
          <option value="monthly">Monthly</option>
        </select>
      </div>
      
      <div class="flex items-center justify-between">
        <div>
          <h3 class="font-medium">Beta Updates</h3>
          <p class="text-sm text-gray-500 dark:text-gray-400">Receive beta updates with new features</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" bind:checked={settings.updates.betaUpdates} class="sr-only peer">
          <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
        </label>
      </div>
    </div>
  </div>
  
  <!-- Notifications Settings -->
  <div class="bg-white dark:bg-gray-800 rounded-lg shadow mb-6">
    <div class="p-4 border-b border-gray-200 dark:border-gray-700">
      <h2 class="text-xl font-semibold">Notifications</h2>
    </div>
    <div class="p-4 space-y-4">
      <div class="flex items-center justify-between">
        <div>
          <h3 class="font-medium">Show Notifications</h3>
          <p class="text-sm text-gray-500 dark:text-gray-400">Enable system notifications</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" bind:checked={settings.notifications.showNotifications} class="sr-only peer">
          <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
        </label>
      </div>
      
      <div class="flex items-center justify-between">
        <div>
          <h3 class="font-medium">Threat Detected</h3>
          <p class="text-sm text-gray-500 dark:text-gray-400">Notify when threats are detected</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" bind:checked={settings.notifications.notifyOnThreats} class="sr-only peer">
          <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
        </label>
      </div>
      
      <div class="flex items-center justify-between">
        <div>
          <h3 class="font-medium">Scan Complete</h3>
          <p class="text-sm text-gray-500 dark:text-gray-400">Notify when a scan finishes</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" bind:checked={settings.notifications.notifyOnScanComplete} class="sr-only peer">
          <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
        </label>
      </div>
      
      <div class="flex items-center justify-between">
        <div>
          <h3 class="font-medium">Updates Available</h3>
          <p class="text-sm text-gray-500 dark:text-gray-400">Notify when updates are available</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" bind:checked={settings.notifications.notifyOnUpdate} class="sr-only peer">
          <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
        </label>
      </div>
    </div>
  </div>
  
  <!-- Advanced Settings -->
  <div class="bg-white dark:bg-gray-800 rounded-lg shadow mb-6">
    <div class="p-4 border-b border-gray-200 dark:border-gray-700">
      <h2 class="text-xl font-semibold">Advanced Settings</h2>
    </div>
    <div class="p-4 space-y-4">
      <div>
        <label class="block font-medium mb-2">Log Level</label>
        <p class="text-sm text-gray-500 dark:text-gray-400 mb-2">Amount of detail to include in logs</p>
        <select 
          bind:value={settings.advanced.logLevel}
          class="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
        >
          <option value="error">Error (Minimal)</option>
          <option value="warn">Warning</option>
          <option value="info">Info (Recommended)</option>
          <option value="debug">Debug (Verbose)</option>
        </select>
      </div>
      
      <div>
        <label class="block font-medium mb-2">Max Log Size (MB)</label>
        <p class="text-sm text-gray-500 dark:text-gray-400 mb-2">Maximum size for log files before rotation</p>
        <input 
          type="number" 
          bind:value={settings.advanced.maxLogSize}
          min="10" 
          max="1000" 
          class="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
        />
      </div>
      
      <div>
        <label class="block font-medium mb-2">Quarantine Location</label>
        <p class="text-sm text-gray-500 dark:text-gray-400 mb-2">Custom location for quarantined files (leave empty for default)</p>
        <input 
          type="text" 
          bind:value={settings.advanced.quarantineLocation}
          placeholder="C:\Path\To\Quarantine" 
          class="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
        />
      </div>
    </div>
  </div>
  
  <!-- Action Buttons -->
  <div class="flex justify-between">
    <button 
      on:click={resetSettings}
      class="px-4 py-2 bg-gray-200 text-gray-800 rounded-md hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-500 dark:bg-gray-700 dark:text-white dark:hover:bg-gray-600"
    >
      Reset to Default
    </button>
    
    <div class="flex items-center space-x-4">
      {#if saveSuccess}
        <span class="text-green-600 dark:text-green-400">Settings saved successfully!</span>
      {/if}
      
      {#if saveError}
        <span class="text-red-600 dark:text-red-400">Error: {saveError}</span>
      {/if}
      
      <button 
        on:click={saveSettings}
        disabled={saving}
        class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {saving ? 'Saving...' : 'Save Settings'}
      </button>
    </div>
  </div>
</div> 