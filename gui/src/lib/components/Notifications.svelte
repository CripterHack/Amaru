<script lang="ts" context="module">
  import { writable } from 'svelte/store';

  export type NotificationType = 'success' | 'error' | 'warning' | 'info';

  export interface Notification {
    id: string;
    type: NotificationType;
    title: string;
    message: string;
    duration: number;
    dismissible: boolean;
  }

  // Create a writable store for notifications
  const notifications = writable<Notification[]>([]);

  // Function to add a notification
  export function notify(
    title: string,
    message: string = '',
    type: NotificationType = 'info',
    duration: number = 5000,
    dismissible: boolean = true
  ): string {
    const id = crypto.randomUUID();
    
    notifications.update(all => [
      {
        id,
        type,
        title,
        message,
        duration,
        dismissible
      },
      ...all
    ]);
    
    if (duration > 0) {
      setTimeout(() => {
        dismiss(id);
      }, duration);
    }
    
    return id;
  }

  // Function to dismiss a notification
  export function dismiss(id: string): void {
    notifications.update(all => all.filter(n => n.id !== id));
  }
</script>

<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  
  // Add support for dark mode
  let darkMode = false;
  
  // Track notification subscriptions
  let unsubscribe: () => void;
  
  // Local notifications state
  let allNotifications: Notification[] = [];
  
  // Subscribe to notification store on mount
  onMount(() => {
    // Check system theme preference
    darkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
    
    // Subscribe to notifications
    unsubscribe = notifications.subscribe(value => {
      allNotifications = value;
    });
    
    return () => {
      if (unsubscribe) unsubscribe();
    };
  });
  
  // Clean up subscription on component destroy
  onDestroy(() => {
    if (unsubscribe) unsubscribe();
  });
  
  // Helper function for notification icons
  function getIcon(type: NotificationType): string {
    switch (type) {
      case 'success': return 'check_circle';
      case 'error': return 'error';
      case 'warning': return 'warning';
      case 'info': return 'info';
      default: return 'notifications';
    }
  }
  
  // Helper function for notification colors
  function getColors(type: NotificationType) {
    switch (type) {
      case 'success':
        return {
          bg: 'bg-green-50 dark:bg-green-900/20',
          border: 'border-green-500',
          text: 'text-green-800 dark:text-green-200',
          icon: 'text-green-500',
          progress: 'bg-green-500'
        };
      case 'error':
        return {
          bg: 'bg-red-50 dark:bg-red-900/20',
          border: 'border-red-500',
          text: 'text-red-800 dark:text-red-200',
          icon: 'text-red-500',
          progress: 'bg-red-500'
        };
      case 'warning':
        return {
          bg: 'bg-yellow-50 dark:bg-yellow-900/20',
          border: 'border-yellow-500',
          text: 'text-yellow-800 dark:text-yellow-200',
          icon: 'text-yellow-500',
          progress: 'bg-yellow-500'
        };
      case 'info':
      default:
        return {
          bg: 'bg-blue-50 dark:bg-blue-900/20',
          border: 'border-blue-500',
          text: 'text-blue-800 dark:text-blue-200',
          icon: 'text-blue-500',
          progress: 'bg-blue-500'
        };
    }
  }
</script>

<div class="notifications-container fixed right-0 top-0 p-4 w-full max-w-sm z-50 space-y-4">
  {#each allNotifications as notification (notification.id)}
    <div 
      class="notification rounded-lg border-l-4 shadow-md overflow-hidden animate-slideIn {getColors(notification.type).bg} {getColors(notification.type).border}"
      role="alert"
    >
      <div class="p-4 flex">
        <div class="flex-shrink-0 mr-3">
          <span class="material-icons {getColors(notification.type).icon}">
            {getIcon(notification.type)}
          </span>
        </div>
        <div class="flex-1 mr-2">
          <h3 class="font-medium {getColors(notification.type).text}">{notification.title}</h3>
          {#if notification.message}
            <p class="text-sm opacity-90 mt-1 {getColors(notification.type).text}">{notification.message}</p>
          {/if}
        </div>
        {#if notification.dismissible}
          <button 
            on:click={() => dismiss(notification.id)}
            class="text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200 transition-colors"
          >
            <span class="material-icons">close</span>
          </button>
        {/if}
      </div>
      
      {#if notification.duration > 0}
        <div class="bg-gray-200 dark:bg-gray-700 h-1">
          <div 
            class="h-1 {getColors(notification.type).progress} progress-bar"
            style="animation-duration: {notification.duration}ms"
          ></div>
        </div>
      {/if}
    </div>
  {/each}
</div>

<style>
  .notifications-container {
    pointer-events: none;
  }
  
  .notification {
    pointer-events: auto;
  }
  
  @keyframes slideIn {
    from {
      transform: translateX(100%);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }
  
  @keyframes progress {
    from {
      width: 100%;
    }
    to {
      width: 0%;
    }
  }
  
  .animate-slideIn {
    animation: slideIn 0.3s ease-out forwards;
  }
  
  .progress-bar {
    animation: progress linear forwards;
  }
</style> 