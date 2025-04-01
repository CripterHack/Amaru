<script lang="ts">
  import { onMount } from 'svelte';
  import { writable, type Writable } from 'svelte/store';
  import { invoke } from '@tauri-apps/api/tauri';
  import { listen } from '@tauri-apps/api/event';
  import { theme } from './lib/stores/theme';
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
  
  // State
  let route: Writable<string> = writable('dashboard');
  let scanning = false;
  let protectionStatus = writable({
    enabled: true,
    version: '1.0.0',
    monitored_paths: ['/home', '/usr', '/etc'],
    last_updated: new Date().toISOString(),
    scanning_enabled: false
  });
  
  // Event listeners
  async function setupListeners() {
    // Listen for threat detection events
    await listen('threat-detected', (event) => {
      const payload = event.payload as any;
      notify(
        'Threat Detected', 
        `Threat detected: ${payload.name} in ${payload.path}`, 
        'warning'
      );
    });
    
    // Listen for scan progress events
    await listen('scan-progress', (event) => {
      scanning = true;
    });
    
    // Listen for scan completed events
    await listen('scan-completed', (event) => {
      scanning = false;
      const payload = event.payload as any;
      notify(
        'Scan Completed', 
        `Scan completed: ${payload.threats_found} threats found`, 
        'success'
      );
    });
    
    // Listen for scan error events
    await listen('scan-error', (event) => {
      scanning = false;
      const payload = event.payload as any;
      notify(
        'Scan Error', 
        `Scan error: ${payload}`, 
        'error'
      );
    });
    
    // Listen for protection status changes
    await listen('protection-status-changed', (event) => {
      const payload = event.payload as any;
      protectionStatus.update(status => ({
        ...status,
        enabled: payload.enabled,
        monitored_paths: payload.monitoredPaths
      }));
      
      notify(
        'Protection Status', 
        `Protection ${payload.enabled ? 'enabled' : 'disabled'}`, 
        'info'
      );
    });
    
    // Listen for signature updates
    await listen('signatures-updated', (event) => {
      const payload = event.payload as any;
      notify(
        'Signatures Updated', 
        `Signatures updated: ${payload.rules_added} new rules added`, 
        'success'
      );
    });
  }
  
  // Load initial protection status
  async function loadProtectionStatus() {
    try {
      // Get protection status from Tauri backend
      const status = await invoke('get_protection_status') as {
        enabled: boolean;
        version: string;
        monitored_paths: string[];
        last_updated: string;
        scanning_enabled: boolean;
      };
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
    // Update UI immediately for responsiveness
    let newEnabledStatus = false;
    protectionStatus.update(status => {
      newEnabledStatus = !status.enabled;
      return {
        ...status,
        enabled: newEnabledStatus
      };
    });
    
    // Call backend to actually toggle protection
    try {
      await invoke('toggle_protection', { enable: newEnabledStatus });
    } catch (error) {
      // Revert UI state if backend call fails
      protectionStatus.update(status => ({
        ...status,
        enabled: !newEnabledStatus
      }));
      
      console.error('Failed to toggle protection:', error);
      notify(
        'Error', 
        `Failed to toggle protection: ${error}`, 
        'error'
      );
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
    // Setup event listeners and load initial state
    const setup = async () => {
      await setupListeners();
      await loadProtectionStatus();
    };
    setup();
    
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
    
    // Check system theme preference
    const prefersDarkScheme = window.matchMedia('(prefers-color-scheme: dark)');
    
    const setTheme = (isDark: boolean) => {
      if (isDark) {
        document.documentElement.classList.add('dark');
        theme.set("dark");
      } else {
        document.documentElement.classList.remove('dark');
        theme.set("light");
      }
    };
    
    // Set initial theme
    setTheme(prefersDarkScheme.matches);
    
    // Proper event listener with specific callback reference for easy cleanup
    const handleThemeChange = (e: MediaQueryListEvent) => setTheme(e.matches);
    prefersDarkScheme.addEventListener('change', handleThemeChange);
    
    return () => {
      window.removeEventListener('hashchange', handleHashChange);
      prefersDarkScheme.removeEventListener('change', handleThemeChange);
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