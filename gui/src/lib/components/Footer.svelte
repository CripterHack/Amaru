<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  
  let version = '1.0.0';
  let updateAvailable = false;
  
  onMount(async () => {
    try {
      // In a real app, we would get the version from the backend
      // const result = await invoke('get_app_version');
      // version = result;
      
      // Check for updates
      // const updateCheck = await invoke('check_for_updates');
      // updateAvailable = updateCheck.available;
    } catch (error) {
      console.error('Failed to get version info:', error);
    }
  });
</script>

<footer class="bg-white dark:bg-gray-800 py-2 px-6 border-t border-gray-200 dark:border-gray-700 text-sm text-gray-600 dark:text-gray-400">
  <div class="flex justify-between items-center">
    <div>
      Amaru Antivirus v{version}
      {#if updateAvailable}
        <span class="ml-2 text-blue-500">Update available</span>
      {/if}
    </div>
    
    <div class="flex items-center space-x-4">
      <a href="https://github.com/CripterHack/Amaru" target="_blank" rel="noopener noreferrer" class="hover:text-blue-500 transition-colors">
        GitHub
      </a>
      <a href="#/about" class="hover:text-blue-500 transition-colors">
        About
      </a>
      <a href="#/help" class="hover:text-blue-500 transition-colors">
        Help
      </a>
    </div>
  </div>
</footer> 