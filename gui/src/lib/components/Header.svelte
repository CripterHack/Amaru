<script lang="ts">
  import { theme } from '../stores/theme';
  
  // Props
  export let route: string;
  export let protectionStatus: any = null;
  
  // Get route title
  $: routeTitle = getRouteTitle(route);
  
  // Toggle dark mode
  function toggleDarkMode() {
    const newTheme = $theme === 'dark' ? 'light' : 'dark';
    theme.set(newTheme);
    
    if (newTheme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }
  
  // Get route title from route name
  function getRouteTitle(route: string): string {
    switch (route) {
      case 'dashboard': return 'Dashboard';
      case 'scan': return 'Scan';
      case 'quarantine': return 'Quarantine';
      case 'settings': return 'Settings';
      default: return 'Amaru Antivirus';
    }
  }
</script>

<header class="bg-white dark:bg-gray-800 shadow-md py-3 px-6 flex justify-between items-center">
  <h1 class="text-xl font-bold">{routeTitle}</h1>
  
  <div class="flex items-center space-x-4">
    <!-- Protection Status Indicator -->
    {#if protectionStatus}
      <div class="flex items-center">
        <div class={`w-3 h-3 rounded-full mr-2 ${protectionStatus.enabled ? 'bg-green-500' : 'bg-red-500'}`}></div>
        <span class="text-sm">{protectionStatus.enabled ? 'Protected' : 'Not Protected'}</span>
      </div>
    {/if}
    
    <!-- Theme Toggle -->
    <button
      on:click={toggleDarkMode}
      class="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700"
      aria-label="Toggle dark mode"
    >
      {#if $theme === 'dark'}
        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
        </svg>
      {:else}
        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
        </svg>
      {/if}
    </button>
  </div>
</header> 