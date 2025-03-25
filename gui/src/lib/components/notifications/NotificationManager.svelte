<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { antivirusStore } from '$lib/stores/antivirus';
  import { configStore } from '$lib/stores/config';
  import NotificationToast from './NotificationToast.svelte';
  import type { Notification } from '$lib/types';
  
  // Props para configurar el comportamiento
  export let maxToasts: number = 3;
  export let position: 'top-right' | 'top-left' | 'bottom-right' | 'bottom-left' = 'top-right';
  
  // Lista de notificaciones a mostrar como toast
  let toasts: Notification[] = [];
  
  // Suscribirse a los cambios en el store de notificaciones
  let unsubscribe: () => void;
  
  onMount(() => {
    unsubscribe = antivirusStore.subscribe(state => {
      // Filtrar notificaciones nuevas (no reconocidas) para mostrarlas como toast
      const newNotifications = state.notifications
        .filter(n => !n.acknowledged)
        .slice(0, maxToasts);
      
      if (newNotifications.length > 0 && $configStore.ui.showNotifications) {
        toasts = [...newNotifications];
        
        // Marcar como reconocidas después de un breve retraso
        setTimeout(() => {
          newNotifications.forEach(notification => {
            // Aquí llamaríamos a una función para marcar como leída
            // En un caso real esto actualizaría el estado en el store
          });
        }, 500);
      }
    });
  });
  
  onDestroy(() => {
    if (unsubscribe) unsubscribe();
  });
  
  // Función para remover un toast específico
  function removeToast(id: string) {
    toasts = toasts.filter(toast => toast.id !== id);
  }
</script>

<div class="notification-manager">
  {#each toasts as toast (toast.id)}
    <NotificationToast 
      notification={toast} 
      position={position}
      duration={toast.priority === 'critical' ? 10000 : 5000}
      on:close={() => removeToast(toast.id)}
    />
  {/each}
</div>

<style>
  .notification-manager {
    /* Este contenedor es invisible pero asegura que las notificaciones
       se posicionen correctamente en la página */
    position: fixed;
    z-index: 1000;
    pointer-events: none;
  }
  
  /* Las notificaciones individuales tendrán pointer-events: auto */
  :global(.notification-manager > *) {
    pointer-events: auto;
  }
</style> 