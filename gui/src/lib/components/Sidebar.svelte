<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  
  // Props
  export let route = 'dashboard';
  export let navigate: (route: string) => void;
  export let protectionStatus: any = null;
  
  // Event dispatcher
  const dispatch = createEventDispatcher();
  
  // Toggle protection
  function toggleProtection() {
    dispatch('toggleProtection');
  }
</script>

<aside class="w-64 h-full bg-white dark:bg-gray-800 shadow-lg overflow-y-auto flex flex-col">
  <!-- Header -->
  <div class="p-6 border-b border-gray-200 dark:border-gray-700">
    <div class="flex items-center">
      <img src="/icon.png" alt="Amaru Logo" class="w-8 h-8 mr-3" />
      <h1 class="text-xl font-bold">Amaru Antivirus</h1>
    </div>
    
    <!-- Protection toggle switch -->
    {#if protectionStatus !== null}
      <div class="mt-4">
        <label class="inline-flex items-center cursor-pointer">
          <span class="mr-3 text-sm font-medium">Protection</span>
          <div class="relative">
            <input 
              type="checkbox" 
              class="sr-only peer" 
              checked={protectionStatus.enabled}
              on:change={toggleProtection}
            />
            <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
          </div>
        </label>
      </div>
    {/if}
  </div>
  
  <!-- Navigation -->
  <nav class="p-4 flex-1">
    <ul class="space-y-1">
      <!-- Dashboard -->
      <li>
        <button
          class={`w-full flex items-center py-2 px-4 rounded-lg transition-colors ${route === 'dashboard' ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-300' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}`}
          on:click={() => navigate('dashboard')}
        >
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
          </svg>
          Dashboard
        </button>
      </li>
      
      <!-- Scan -->
      <li>
        <button
          class={`w-full flex items-center py-2 px-4 rounded-lg transition-colors ${route === 'scan' ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-300' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}`}
          on:click={() => navigate('scan')}
        >
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          Scan
        </button>
      </li>
      
      <!-- Quarantine -->
      <li>
        <button
          class={`w-full flex items-center py-2 px-4 rounded-lg transition-colors ${route === 'quarantine' ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-300' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}`}
          on:click={() => navigate('quarantine')}
        >
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          Quarantine
        </button>
      </li>
      
      <!-- Settings -->
      <li>
        <button
          class={`w-full flex items-center py-2 px-4 rounded-lg transition-colors ${route === 'settings' ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-300' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}`}
          on:click={() => navigate('settings')}
        >
          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
          Settings
        </button>
      </li>
    </ul>
  </nav>
  
  <!-- Footer -->
  <div class="p-4 border-t border-gray-200 dark:border-gray-700">
    <div class="flex justify-between items-center text-sm text-gray-500 dark:text-gray-400">
      <button
        class="flex items-center hover:text-blue-500 transition-colors"
        on:click={() => window.open('https://github.com/CripterHack/Amaru/issues', '_blank')}
      >
        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        Support
      </button>
      
      <button
        class="flex items-center hover:text-blue-500 transition-colors"
        on:click={() => window.open('https://github.com/CripterHack/Amaru', '_blank')}
      >
        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        About
      </button>
    </div>
  </div>
</aside> 