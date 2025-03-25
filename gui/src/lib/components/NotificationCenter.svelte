<script lang="ts">
  import { antivirusStore } from '$lib/stores/antivirus';
  import { slide } from 'svelte/transition';
  import Icon from './Icon.svelte';
  import type { Notification } from '$lib/types';
  
  let showNotifications = false;
  let unreadCount = 0;
  
  $: notifications = $antivirusStore.notifications;
  $: unreadCount = notifications.filter(n => !n.acknowledged).length;
  
  function toggleNotifications() {
    showNotifications = !showNotifications;
    if (showNotifications) {
      notifications.forEach(n => {
        if (!n.acknowledged) {
          antivirusStore.acknowledge(n.id);
        }
      });
    }
  }
  
  function getIcon(type: Notification['type']) {
    switch (type) {
      case 'threat':
        return 'alert-triangle';
      case 'system':
        return 'info';
      case 'update':
        return 'download';
      case 'scan':
        return 'search';
      default:
        return 'bell';
    }
  }
  
  function getPriorityColor(priority: Notification['priority']) {
    switch (priority) {
      case 'critical':
        return 'text-danger-500';
      case 'high':
        return 'text-danger-400';
      case 'medium':
        return 'text-primary-500';
      case 'low':
        return 'text-gray-500';
      default:
        return 'text-gray-500';
    }
  }
</script>

<div class="fixed right-4 top-4 z-50">
  <button
    class="relative p-2 text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-100"
    on:click={toggleNotifications}
  >
    <Icon name="bell" size={24} />
    {#if unreadCount > 0}
      <span
        class="absolute top-0 right-0 -mt-1 -mr-1 px-2 py-1 text-xs font-bold leading-none
               text-white transform translate-x-1/2 -translate-y-1/2 bg-danger-500 rounded-full"
      >
        {unreadCount}
      </span>
    {/if}
  </button>
  
  {#if showNotifications}
    <div
      class="absolute right-0 w-96 mt-2 bg-white dark:bg-gray-800 rounded-lg shadow-xl"
      transition:slide
    >
      <div class="p-4 border-b dark:border-gray-700">
        <div class="flex justify-between items-center">
          <h3 class="text-lg font-medium">Notificaciones</h3>
          <button
            class="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
            on:click={() => antivirusStore.clearNotifications()}
          >
            <Icon name="trash-2" size={20} />
          </button>
        </div>
      </div>
      
      <div class="max-h-96 overflow-y-auto">
        {#if notifications.length === 0}
          <div class="p-4 text-center text-gray-500">
            No hay notificaciones
          </div>
        {:else}
          {#each notifications as notification}
            <div
              class="p-4 border-b dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700
                     transition-colors duration-150"
            >
              <div class="flex items-start space-x-3">
                <div class={getPriorityColor(notification.priority)}>
                  <Icon name={getIcon(notification.type)} size={20} />
                </div>
                <div class="flex-1 min-w-0">
                  <p class="text-sm font-medium text-gray-900 dark:text-gray-100">
                    {notification.title}
                  </p>
                  <p class="text-sm text-gray-500 dark:text-gray-400">
                    {notification.message}
                  </p>
                  <p class="mt-1 text-xs text-gray-400 dark:text-gray-500">
                    {new Date(notification.timestamp).toLocaleString()}
                  </p>
                </div>
              </div>
            </div>
          {/each}
        {/if}
      </div>
    </div>
  {/if}
</div> 