<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { antivirusStore } from '$lib/stores/antivirus';
  import { configStore } from '$lib/stores/config';
  import ModernHeader from '$lib/components/ModernHeader.svelte';
  import NotificationManager from '$lib/components/notifications/NotificationManager.svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  import { listen } from '@tauri-apps/api/event';
  import type { Notification } from '$lib/types';
  
  let darkMode = false;
  
  // Inicializar configuración y suscribirse a cambios
  onMount(async () => {
    // Cargar configuración inicial
    try {
      await configStore.init();
      
      // Suscribirse a eventos de notificación desde el backend
      const unsubscribe = await listen<Notification>('notification', (event) => {
        antivirusStore.addNotification(event.payload);
      });
      
      // Suscribirse a cambios de tema
      const themeUnsubscribe = configStore.subscribe(config => {
        if (config) {
          // Aplicar tema
          darkMode = config.ui.theme === 'dark' || 
                    (config.ui.theme === 'system' && 
                     window.matchMedia('(prefers-color-scheme: dark)').matches);
          
          if (darkMode) {
            document.documentElement.classList.add('dark');
          } else {
            document.documentElement.classList.remove('dark');
          }
        }
      });
      
      // Verificar estado del sistema
      await checkSystemStatus();
      
      // Programar verificaciones periódicas
      const intervalId = setInterval(checkSystemStatus, 30000);
      
      return () => {
        unsubscribe();
        themeUnsubscribe();
        clearInterval(intervalId);
      };
    } catch (error) {
      console.error('Error al inicializar la aplicación:', error);
    }
  });
  
  // Comprobar estado del sistema (protección, actualizaciones, etc.)
  async function checkSystemStatus() {
    try {
      const status = await invoke('get_system_status');
      antivirusStore.updateSystemStatus(status);
    } catch (error) {
      console.error('Error al obtener el estado del sistema:', error);
    }
  }
</script>

<!-- Aplicar clases globales para modo oscuro -->
<div class="h-full min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
  <ModernHeader />
  
  <main class="container mx-auto px-4 py-6">
    <!-- Contenido de la página -->
    <slot />
  </main>
  
  <!-- Gestor de notificaciones -->
  <NotificationManager maxToasts={3} position="top-right" />
</div>

<style>
  :global(html) {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
    @apply antialiased;
  }
  
  :global(body) {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }
  
  :global(.dark) {
    color-scheme: dark;
  }
  
  /* Transiciones suaves para cambios de tema */
  :global(*, *::before, *::after) {
    transition-property: background-color, border-color, color, fill, stroke;
    transition-duration: 200ms;
    transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);
  }
  
  /* Excepciones para evitar transiciones en elementos que no lo necesitan */
  :global(svg *, .no-transition) {
    transition: none !important;
  }
</style> 