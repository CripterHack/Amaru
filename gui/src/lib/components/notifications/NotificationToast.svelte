<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { fly, fade } from 'svelte/transition';
  import { antivirusStore } from '$lib/stores/antivirus';
  import type { Notification } from '$lib/types';
  import Icon from '../Icon.svelte';
  
  export let notification: Notification;
  export let position: 'top-right' | 'top-left' | 'bottom-right' | 'bottom-left' = 'top-right';
  export let duration: number = 5000; // Duración en milisegundos
  
  let visible = true;
  let timer: ReturnType<typeof setTimeout>;
  
  // Posiciones CSS
  const positionClasses = {
    'top-right': 'top-4 right-4',
    'top-left': 'top-4 left-4',
    'bottom-right': 'bottom-4 right-4',
    'bottom-left': 'bottom-4 left-4'
  };
  
  // Iconos por tipo de notificación
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
  
  // Colores según prioridad
  function getColorClasses(priority: Notification['priority']) {
    switch (priority) {
      case 'critical':
        return 'bg-red-500 dark:bg-red-700';
      case 'high':
        return 'bg-orange-500 dark:bg-orange-600';
      case 'medium':
        return 'bg-primary-500 dark:bg-primary-600';
      case 'low':
      default:
        return 'bg-gray-600 dark:bg-gray-700';
    }
  }
  
  // Iniciar temporizador para ocultar la notificación
  onMount(() => {
    timer = setTimeout(() => {
      visible = false;
    }, duration);
  });
  
  // Cancelar temporizador al desmontar
  onDestroy(() => {
    clearTimeout(timer);
  });
  
  // Detener temporizador al pasar el mouse
  function stopTimer() {
    clearTimeout(timer);
  }
  
  // Reiniciar temporizador al quitar el mouse
  function startTimer() {
    timer = setTimeout(() => {
      visible = false;
    }, duration);
  }
  
  // Cerrar notificación
  function close() {
    visible = false;
  }
</script>

{#if visible}
  <div 
    class="fixed z-50 {positionClasses[position]} max-w-sm w-full"
    in:fly={{ y: 20, duration: 500 }}
    out:fade={{ duration: 300 }}
    on:mouseenter={stopTimer}
    on:mouseleave={startTimer}
  >
    <div class="p-4 rounded-lg shadow-lg {getColorClasses(notification.priority)} text-white">
      <div class="flex items-start space-x-3">
        <div class="flex-shrink-0">
          <Icon name={getIcon(notification.type)} size={22} class_="text-white" />
        </div>
        
        <div class="flex-1 ml-3">
          <p class="font-medium text-white">{notification.title}</p>
          <p class="mt-1 text-sm text-white/90">{notification.message}</p>
        </div>
        
        <button 
          class="flex-shrink-0 ml-auto text-white/70 hover:text-white transition-colors"
          on:click={close}
          aria-label="Cerrar notificación"
        >
          <Icon name="x" size={18} />
        </button>
      </div>
      
      <!-- Barra de progreso que se reduce con el tiempo -->
      <div class="mt-3 w-full h-1 bg-white/30 rounded-full overflow-hidden">
        <div 
          class="h-full bg-white/70 rounded-full" 
          style="animation: progress-timer {duration}ms linear forwards;"
        ></div>
      </div>
    </div>
  </div>
{/if}

<style>
  @keyframes progress-timer {
    from { width: 100%; }
    to { width: 0%; }
  }
</style> 