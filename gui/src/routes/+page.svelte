{#key $antivirusStore}
<script lang="ts">
  import { antivirusStore } from '$lib/stores/antivirus';
  import { onMount } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import Dashboard from '$components/Dashboard.svelte';
  import Sidebar from '$components/Sidebar.svelte';
  import Header from '$components/Header.svelte';
  import NotificationCenter from '$components/NotificationCenter.svelte';
  import type { Notification } from '$lib/types';

  let currentView = 'dashboard';

  onMount(async () => {
    // Suscribirse a eventos del backend
    const unsubscribe = await listen<Notification>('notification', (event) => {
      antivirusStore.addNotification(event.payload);
    });

    return () => {
      unsubscribe();
    };
  });
</script>

<div class="min-h-screen bg-gray-100 dark:bg-gray-900">
  <Header />
  
  <div class="flex">
    <Sidebar bind:currentView />
    
    <main class="flex-1 p-6">
      {#if currentView === 'dashboard'}
        <Dashboard />
      {:else if currentView === 'scan'}
        <ScanView />
      {:else if currentView === 'protection'}
        <ProtectionView />
      {:else if currentView === 'quarantine'}
        <QuarantineView />
      {:else if currentView === 'settings'}
        <SettingsView />
      {/if}
    </main>

    <NotificationCenter />
  </div>
</div>

<style lang="postcss">
  :global(html) {
    @apply antialiased;
  }
  
  :global(body) {
    @apply bg-gray-100 dark:bg-gray-900 text-gray-900 dark:text-gray-100;
  }
</style>
{/key} 