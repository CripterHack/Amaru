<script lang="ts">
  import { onMount } from 'svelte';
  import { ask } from '@tauri-apps/api/dialog';
  import { invoke } from '@tauri-apps/api/tauri';
  import { notify } from '../lib/components/Notifications.svelte';
  
  // Quarantine state
  let loading = true;
  let acting = false;
  let scope: 'desktop' | 'service' = 'desktop';
  let request = 0;
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
  
  async function applySelection(restore: boolean) {
    if (acting || !selectedItems.length) return;
    acting = true;
    const selected = [...selectedItems];
    const verb = restore ? 'Restore' : 'Permanently delete';
    try {
      if (!await ask(`${verb} ${selected.length} selected file(s) from ${scope} quarantine?`, { title: 'Confirm quarantine action', type: 'warning' })) return;
      for (const id of selected) {
        await invoke(restore ? 'restore_quarantined_file' : 'delete_quarantined_file', { id, scope });
        selectedItems = selectedItems.filter(item => item !== id);
      }
      notify('Quarantine updated', `${selected.length} item(s) processed`, 'success');
    } catch (error) {
      notify('Quarantine action failed', String(error), 'error');
    } finally {
      acting = false;
      await loadQuarantineItems();
    }
  }

  async function loadQuarantineItems() {
    const revision = ++request;
    loading = true;
    try {
      const items = await invoke<QuarantineItem[]>('get_quarantined_files', { scope });
      if (revision !== request) return;
      quarantineItems = items;
      error = null;
      selectedItems = selectedItems.filter(id => quarantineItems.some(item => item.id === id));
    } catch (err) { if (revision === request) { error = String(err); selectedItems = []; } }
    finally { if (revision === request) loading = false; }
  }

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
          Review and manage files isolated by the selected scanner.
        </p>
      </div>
      
      <div class="flex gap-2">
        <label>Quarantine source
          <select bind:value={scope} disabled={acting} on:change={() => { selectedItems = []; void loadQuarantineItems(); }}>
            <option value="desktop">Desktop</option>
            <option value="service">Windows service (administrator)</option>
          </select>
        </label>
        <button 
          on:click={() => applySelection(true)}
          disabled={acting || selectedItems.length === 0}
          class="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-md disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Restore Selected
        </button>
        
        <button 
          on:click={() => applySelection(false)}
          disabled={acting || selectedItems.length === 0}
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
          The selected quarantine contains no files.
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

                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 space-x-2">
                  <button 
                    on:click={() => {
                      selectedItems = [item.id];
                      void applySelection(true);
                    }}
                    class="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300"
                  >
                    Restore
                  </button>
                  <button 
                    on:click={() => {
                      selectedItems = [item.id];
                      void applySelection(false);
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

  </div>
</div> 