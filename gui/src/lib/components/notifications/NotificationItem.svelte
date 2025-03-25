<script lang="ts">
  import { fade, fly } from 'svelte/transition';
  import Icon from '../Icon.svelte';
  import type { Notification } from '$lib/types';
  import { antivirusStore } from '$lib/stores/antivirus';
  
  export let notification: Notification;
  export let animate: boolean = true;
  
  function getIcon(type: Notification['type']) {
    switch (type) {
      case 'threat':
        return 'shield-alert';
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
  
  function getPriorityStyles(priority: Notification['priority']) {
    switch (priority) {
      case 'critical':
        return 'bg-red-50 dark:bg-red-900/20 border-red-400 dark:border-red-700';
      case 'high':
        return 'bg-orange-50 dark:bg-orange-900/20 border-orange-400 dark:border-orange-700';
      case 'medium':
        return 'bg-primary-50 dark:bg-primary-900/20 border-primary-400 dark:border-primary-700';
      case 'low':
      default:
        return 'bg-gray-50 dark:bg-gray-800 border-gray-200 dark:border-gray-700';
    }
  }
  
  function getPriorityIconColor(priority: Notification['priority']) {
    switch (priority) {
      case 'critical':
        return 'text-red-500 dark:text-red-400';
      case 'high':
        return 'text-orange-500 dark:text-orange-400';
      case 'medium':
        return 'text-primary-500 dark:text-primary-400';
      case 'low':
      default:
        return 'text-gray-500 dark:text-gray-400';
    }
  }
  
  function acknowledge() {
    antivirusStore.clearNotifications(); // En un caso real deberíamos marcar solo esta como leída
  }
</script>

<div 
  class="relative p-4 rounded-lg border mb-3 shadow-sm hover:shadow-md transition-all duration-200 {getPriorityStyles(notification.priority)}"
  in:fly={{ y: 20, duration: animate ? 300 : 0 }}
  out:fade={{ duration: animate ? 200 : 0 }}
>
  <div class="flex items-start space-x-4">
    <div class="flex-shrink-0 {getPriorityIconColor(notification.priority)}">
      <Icon name={getIcon(notification.type)} size={24} />
    </div>
    
    <div class="flex-1 min-w-0">
      <h4 class="text-sm font-medium text-gray-900 dark:text-white">
        {notification.title}
      </h4>
      
      <p class="mt-1 text-sm text-gray-600 dark:text-gray-300">
        {notification.message}
      </p>
      
      <div class="mt-2 flex items-center justify-between">
        <span class="text-xs text-gray-500 dark:text-gray-400">
          {new Date(notification.timestamp).toLocaleString()}
        </span>
        
        {#if notification.metadata && notification.type === 'threat'}
          <button 
            class="text-xs px-2 py-1 bg-primary-100 dark:bg-primary-900 text-primary-700 dark:text-primary-300 rounded hover:bg-primary-200 dark:hover:bg-primary-800 transition"
            on:click={() => console.log('Ver detalles', notification.metadata)}
          >
            Ver detalles
          </button>
        {/if}
      </div>
    </div>
    
    <button 
      class="flex-shrink-0 ml-2 text-gray-400 hover:text-gray-500 dark:text-gray-500 dark:hover:text-gray-400"
      on:click={acknowledge}
      aria-label="Cerrar notificación"
    >
      <Icon name="x" size={18} />
    </button>
  </div>
</div> 