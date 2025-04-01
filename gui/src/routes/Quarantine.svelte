<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  import { notify } from '../lib/components/Notifications.svelte';
  
  // Quarantine state
  let loading = true;
  let error: string | null = null;
  let quarantineItems: QuarantineItem[] = [];
  let selectedItems: string[] = [];
  
  // Define type for quarantine items
  type QuarantineItem = {
    id: string;
    fileName: string;
    originalPath: string;
    threatType: string;
    detectionDate: string;
    fileSize: number;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
  };
  
  // Format file size
  function formatFileSize(bytes: number): string {
    if (bytes < 1024) return bytes + ' B';
    const units = ['KB', 'MB', 'GB', 'TB'];
    let value = bytes / 1024;
    let unitIndex = 0;
    
    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex++;
    }
    
    return value.toFixed(2) + ' ' + units[unitIndex];
  }
  
  // Toggle all items
  function toggleAll(event: Event) {
    const target = event.target as HTMLInputElement;
    if (target.checked) {
      selectedItems = quarantineItems.map(item => item.id);
    } else {
      selectedItems = [];
    }
  }
  
  // Toggle single item
  function toggleItem(id: string) {
    const index = selectedItems.indexOf(id);
    if (index === -1) {
      selectedItems = [...selectedItems, id];
    } else {
      selectedItems = selectedItems.filter(itemId => itemId !== id);
    }
  }
  
  // Get CSS class for risk level
  function getRiskLevelClass(level: string): string {
    switch (level) {
      case 'low': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300';
      case 'medium': return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300';
      case 'high': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300';
      case 'critical': return 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-300';
      default: return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300';
    }
  }
  
  // Restore selected items
  async function restoreSelected() {
    if (selectedItems.length === 0) return;
    
    try {
      // In a real app, we would invoke the Tauri backend
      // await invoke('restore_quarantined_items', { itemIds: selectedItems });
      
      // For demo, we'll simulate the restore
      quarantineItems = quarantineItems.filter(item => !selectedItems.includes(item.id));
      notify('Items Restored', `${selectedItems.length} item(s) have been restored`, 'success');
      selectedItems = [];
    } catch (error) {
      console.error('Failed to restore items:', error);
      notify('Restore Failed', `Failed to restore items: ${error}`, 'error');
    }
  }
  
  // Delete selected items
  async function deleteSelected() {
    if (selectedItems.length === 0) return;
    
    try {
      // In a real app, we would invoke the Tauri backend
      // await invoke('delete_quarantined_items', { itemIds: selectedItems });
      
      // For demo, we'll simulate the deletion
      quarantineItems = quarantineItems.filter(item => !selectedItems.includes(item.id));
      notify('Items Deleted', `${selectedItems.length} item(s) have been permanently deleted`, 'success');
      selectedItems = [];
    } catch (error) {
      console.error('Failed to delete items:', error);
      notify('Delete Failed', `Failed to delete items: ${error}`, 'error');
    }
  }
  
  // Load quarantine items
  async function loadQuarantineItems() {
    try {
      loading = true;
      
      // In a real app, we would invoke the Tauri backend
      // quarantineItems = await invoke('get_quarantined_items');
      
      // For demo, we'll use mock data
      setTimeout(() => {
        quarantineItems = [
          {
            id: '1',
            fileName: 'malicious-script.js',
            originalPath: 'C:\\Users\\User\\Downloads\\malicious-script.js',
            threatType: 'Trojan.JS.Downloader',
            detectionDate: '2023-05-15T14:30:00Z',
            fileSize: 45678,
            riskLevel: 'high'
          },
          {
            id: '2',
            fileName: 'fake-invoice.pdf.exe',
            originalPath: 'C:\\Users\\User\\Downloads\\Invoice-May2023.pdf.exe',
            threatType: 'Win32.Trojan.Ransomware',
            detectionDate: '2023-05-10T09:15:22Z',
            fileSize: 1456789,
            riskLevel: 'critical'
          },
          {
            id: '3',
            fileName: 'suspicious-macro.docm',
            originalPath: 'C:\\Users\\User\\Documents\\Report.docm',
            threatType: 'Macro.Downloader.Generic',
            detectionDate: '2023-05-08T11:45:30Z',
            fileSize: 245678,
            riskLevel: 'medium'
          },
          {
            id: '4',
            fileName: 'adware-bundle.exe',
            originalPath: 'C:\\Users\\User\\Downloads\\free-software-bundle.exe',
            threatType: 'Win32.Adware.BundleInstaller',
            detectionDate: '2023-05-01T16:20:45Z',
            fileSize: 3456789,
            riskLevel: 'low'
          }
        ];
        loading = false;
      }, 1000);
    } catch (err: unknown) {
      console.error('Failed to load quarantine items:', err);
      error = err instanceof Error ? err.message : String(err);
      loading = false;
    }
  }
  
  // Initialize
  onMount(() => {
    loadQuarantineItems();
  });
</script>

<div class="container mx-auto px-4 py-8">
  <h1 class="text-3xl font-bold mb-8">Quarantine</h1>
  
  <div class="bg-white dark:bg-gray-800 rounded-lg shadow mb-6 p-6">
    <div class="flex justify-between items-center mb-6">
      <div>
        <h2 class="text-xl font-semibold">Quarantined Items</h2>
        <p class="text-gray-500 dark:text-gray-400 text-sm mt-1">
          Files detected as malicious are stored in quarantine for safety
        </p>
      </div>
      
      <div class="flex gap-2">
        <button 
          on:click={restoreSelected}
          disabled={selectedItems.length === 0}
          class="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-md disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Restore Selected
        </button>
        
        <button 
          on:click={deleteSelected}
          disabled={selectedItems.length === 0}
          class="px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-md disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Delete Selected
        </button>
      </div>
    </div>
    
    {#if loading}
      <div class="flex items-center justify-center py-8">
        <div class="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-500"></div>
      </div>
    {:else if error}
      <div class="bg-red-50 dark:bg-red-900/30 text-red-800 dark:text-red-300 p-4 rounded-md">
        Error: {error}
      </div>
    {:else if quarantineItems.length === 0}
      <div class="text-center py-8">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 mx-auto text-gray-400 dark:text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <h3 class="text-lg font-medium mt-4">No Quarantined Items</h3>
        <p class="text-gray-500 dark:text-gray-400 mt-2">
          Your system is clean. All detected threats have been resolved.
        </p>
      </div>
    {:else}
      <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead>
            <tr>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">
                <label class="inline-flex items-center">
                  <input 
                    type="checkbox" 
                    on:change={toggleAll}
                    checked={selectedItems.length === quarantineItems.length && quarantineItems.length > 0}
                    class="rounded border-gray-300 text-blue-600 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600"
                  />
                </label>
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">File Name</th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">Threat Type</th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">Detection Date</th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">Size</th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">Risk Level</th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
            {#each quarantineItems as item}
              <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                <td class="px-6 py-4 whitespace-nowrap">
                  <input 
                    type="checkbox" 
                    checked={selectedItems.includes(item.id)}
                    on:change={() => toggleItem(item.id)}
                    class="rounded border-gray-300 text-blue-600 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600"
                  />
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <div class="text-sm font-medium">{item.fileName}</div>
                  <div class="text-xs text-gray-500 dark:text-gray-400 truncate max-w-xs">{item.originalPath}</div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <div class="text-sm">{item.threatType}</div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <div class="text-sm">{new Date(item.detectionDate).toLocaleString()}</div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm">
                  {formatFileSize(item.fileSize)}
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full {getRiskLevelClass(item.riskLevel)}">
                    {item.riskLevel.charAt(0).toUpperCase() + item.riskLevel.slice(1)}
                  </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 space-x-2">
                  <button 
                    on:click={() => {
                      selectedItems = [item.id];
                      restoreSelected();
                    }}
                    class="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300"
                  >
                    Restore
                  </button>
                  <button 
                    on:click={() => {
                      selectedItems = [item.id];
                      deleteSelected();
                    }}
                    class="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                  >
                    Delete
                  </button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
  
  <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
    <h2 class="text-xl font-semibold mb-4">Quarantine Information</h2>
    <p class="text-gray-700 dark:text-gray-300 mb-4">
      Files in quarantine have been isolated and can no longer harm your system. You can choose to:
    </p>
    <ul class="list-disc pl-5 space-y-2 text-gray-700 dark:text-gray-300">
      <li><strong>Restore</strong> - Return the file to its original location (only if you're confident it's safe)</li>
      <li><strong>Delete</strong> - Permanently remove the file from your system</li>
    </ul>
    <div class="mt-4 p-4 bg-blue-50 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 rounded-md">
      <p class="text-sm"><strong>Note:</strong> Quarantined items are automatically deleted after 30 days to free up space.</p>
    </div>
  </div>
</div> 