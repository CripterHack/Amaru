<script lang="ts">
  import { onMount } from 'svelte';
  import { writable, type Writable } from 'svelte/store';
  import { invoke } from '@tauri-apps/api/tauri';
  import { manageListeners } from './lib/tauriEvents';
  import { listen } from '@tauri-apps/api/event';
  import type { ProtectionStatus } from './lib/stores/statusStore';
  import { applyThemePreference } from './lib/stores/theme';
  import { notify } from './lib/components/Notifications.svelte';
  
  // Components
  import Header from './lib/components/Header.svelte';
  import Sidebar from './lib/components/Sidebar.svelte';
  import Footer from './lib/components/Footer.svelte';
  import Notifications from './lib/components/Notifications.svelte';
  
  // Routes
  import Dashboard from './routes/Dashboard.svelte';
  import Scan from './routes/Scan.svelte';
  import ScanConfig from './routes/ScanConfig.svelte';
  import Quarantine from './routes/Quarantine.svelte';
  import Settings from './routes/Settings.svelte';
  import HelpPage from './routes/help/HelpPage.svelte';
  
  // State
  let route: Writable<string> = writable('dashboard');
  const protectionStatus = writable<ProtectionStatus | null>(null);
  let togglingProtection = false;

  // Event listeners
  function setupListeners() {
    return manageListeners([
      listen<{name:string; path:string}>('threat-detected', ({payload}) => notify('Threat detected', `${payload.name} in ${payload.path}`, 'warning')),
      listen<{status:string; threats_found:number}>('scan-completed', ({payload}) =>
        notify('Scan finished', `${payload.status}: ${payload.threats_found} finding(s)`, payload.status === 'completed' ? 'success' : 'warning')),
      listen<string>('scan-error', ({payload}) => notify('Scan error', payload, 'error')),
      listen<{ enabled: boolean; monitoredPaths: string[] }>('protection-status-changed', ({payload}) => {
        if ($protectionStatus) {
          $protectionStatus = { ...$protectionStatus, enabled: payload.enabled, monitored_paths: payload.monitoredPaths };
        } else { void loadProtectionStatus(); }
      })
    ]);
  }

  // Load initial protection status
  async function loadProtectionStatus() {
    try {
      // Get protection status from Tauri backend
      const status = await invoke<ProtectionStatus>('get_protection_status');
      protectionStatus.set(status);
    } catch (error) {
      console.error('Failed to get protection status:', error);
      notify(
        'Error', 
        `Failed to get protection status: ${error}`, 
        'error'
      );
    }
  }
  
  // Toggle protection
  async function toggleProtection() {
    if (!$protectionStatus || togglingProtection) return;
    const enable = !$protectionStatus.enabled;
    togglingProtection = true;
    try {
      await invoke('toggle_protection', { enable });
      $protectionStatus = { ...$protectionStatus, enabled: enable };
    } catch (error) {
      console.error('Failed to toggle protection:', error);
      notify(
        'Error', 
        `Failed to toggle protection: ${error}`, 
        'error'
      );
    } finally {
      togglingProtection = false;
    }
  }
  
  // Navigation
  function navigate(newRoute: string) {
    route.set(newRoute);
    // Update URL hash for bookmarking and navigation
    window.location.hash = `#/${newRoute}`;
  }
  
  // Initialize
  onMount(() => {
    const stopEvents = setupListeners();
    void loadProtectionStatus();

    // Handle hash-based routing
    const handleHashChange = () => {
      const hash = window.location.hash.slice(1) || '/';
      const routePath = hash.startsWith('/') ? hash.slice(1) : hash;
      route.set(routePath || 'dashboard');
    };
    
    // Initial route
    handleHashChange();
    
    // Listen for hash changes
    window.addEventListener('hashchange', handleHashChange);
    
    const stopTheme = applyThemePreference();

    return () => {
      stopEvents();
      window.removeEventListener('hashchange', handleHashChange);
      stopTheme();
    };
  });
</script>

<div class="h-screen flex flex-col bg-gray-100 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
  <Notifications />
  
  <Header 
    route={$route} 
    protectionStatus={$protectionStatus} 
  />
  
  <div class="flex flex-1 overflow-hidden">
    <Sidebar 
      route={$route} 
      navigate={navigate} 
      protectionStatus={$protectionStatus} 
      {togglingProtection}
      on:toggleProtection={toggleProtection}
    />
    
    <main class="flex-1 overflow-auto">
      {#if $route === 'dashboard'}
        <Dashboard protectionStatus={$protectionStatus} />
      {:else if $route === 'scan'}
        <Scan />
      {:else if $route === 'scan-config'}
        <ScanConfig />
      {:else if $route === 'quarantine'}
        <Quarantine />
      {:else if $route === 'settings'}
        <Settings />
      {:else if $route === 'help'}
        <HelpPage />
      {:else}
        <div class="container mx-auto p-8">
          <h1 class="text-2xl font-bold mb-4">Page Not Found</h1>
          <p>The page you're looking for doesn't exist.</p>
          <button 
            class="mt-4 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-md"
            on:click={() => navigate('dashboard')}
          >
            Go to Dashboard
          </button>
        </div>
      {/if}
    </main>
  </div>
  
  <Footer />
</div>

<style>
  :global(body) {
    margin: 0;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
  }
  
  :global(button) {
    cursor: pointer;
  }
</style> 