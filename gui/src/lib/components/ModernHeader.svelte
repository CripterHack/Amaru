<script lang="ts">
  import { onMount } from 'svelte';
  import { antivirusStore } from '$lib/stores/antivirus';
  import { configStore } from '$lib/stores/config';
  import Icon from './Icon.svelte';
  
  // Estado de protección
  let protectionEnabled = true;
  let searchQuery = '';
  let unreadNotifications = 0;
  let showDropdown = false;
  let showProfileMenu = false;
  
  onMount(() => {
    // Suscribirse a cambios en el estado
    const unsubscribe = antivirusStore.subscribe(state => {
      protectionEnabled = state.realtimeProtection;
      unreadNotifications = state.notifications.filter(n => !n.acknowledged).length;
    });
    
    return () => {
      unsubscribe();
    };
  });
  
  // Funciones para manejar eventos
  const toggleProtection = () => {
    antivirusStore.toggleRealtimeProtection();
  };
  
  const handleSearchSubmit = () => {
    if (searchQuery.trim()) {
      console.log(`Búsqueda: ${searchQuery}`);
      // Aquí iría la lógica para buscar archivos
      searchQuery = '';
    }
  };
  
  const toggleDarkMode = () => {
    const currentTheme = $configStore.ui.theme;
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    configStore.setTheme(newTheme);
  };
</script>

<header class="bg-white shadow-sm dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
  <div class="px-4 sm:px-6 lg:px-8">
    <div class="flex items-center justify-between h-16">
      <!-- Logo y título -->
      <div class="flex items-center">
        <div class="flex-shrink-0">
          <img src="/logo.svg" alt="Amaru Logo" class="h-10 w-10" />
        </div>
        <div class="ml-3">
          <h1 class="text-lg font-medium text-gray-900 dark:text-white">
            Amaru Antivirus
          </h1>
          <p class="text-xs text-gray-500 dark:text-gray-400">Protección avanzada</p>
        </div>
      </div>
      
      <!-- Búsqueda -->
      <div class="hidden md:block flex-1 mx-6">
        <form on:submit|preventDefault={handleSearchSubmit} class="max-w-lg mx-auto">
          <div class="relative">
            <input
              type="text"
              placeholder="Buscar archivos..."
              bind:value={searchQuery}
              class="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md leading-5 bg-gray-50 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
            />
            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Icon name="search" size={16} class_="text-gray-400" />
            </div>
            <button
              type="submit"
              class="absolute inset-y-0 right-0 pr-3 flex items-center"
            >
              <Icon name="arrow-right" size={16} class_="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300" />
            </button>
          </div>
        </form>
      </div>
      
      <!-- Controles a la derecha -->
      <div class="flex items-center space-x-3">
        <!-- Estado de protección -->
        <div 
          class="hidden md:flex items-center px-3 py-1 rounded-full {protectionEnabled ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'}"
        >
          <Icon 
            name={protectionEnabled ? "shield-check" : "shield-off"} 
            size={18} 
            class_="mr-1" 
          />
          <span class="text-sm font-medium">
            {protectionEnabled ? "Protegido" : "Desprotegido"}
          </span>
        </div>
        
        <!-- Botón de tema claro/oscuro -->
        <button
          class="p-2 rounded-full text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
          on:click={toggleDarkMode}
          aria-label="Cambiar tema"
        >
          <Icon name={$configStore.ui.theme === 'dark' ? "sun" : "moon"} size={20} />
        </button>
        
        <!-- Notificaciones -->
        <div class="relative">
          <button
            class="p-2 rounded-full text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
            on:click={() => showDropdown = !showDropdown}
            aria-label="Ver notificaciones"
          >
            <Icon name="bell" size={20} />
            {#if unreadNotifications > 0}
              <span class="absolute top-0 right-0 -mt-1 -mr-1 px-2 py-1 text-xs font-bold leading-none text-white transform translate-x-1/2 -translate-y-1/2 bg-red-500 rounded-full">
                {unreadNotifications}
              </span>
            {/if}
          </button>
          
          {#if showDropdown}
            <div
              class="origin-top-right absolute right-0 mt-2 w-80 rounded-md shadow-lg bg-white dark:bg-gray-800 ring-1 ring-black ring-opacity-5 focus:outline-none z-30"
              tabindex="-1"
            >
              <div class="py-1" role="menu" aria-orientation="vertical">
                <div class="px-4 py-2 border-b border-gray-200 dark:border-gray-700">
                  <h3 class="text-sm font-medium text-gray-900 dark:text-white">Notificaciones</h3>
                </div>
                {#if $antivirusStore.notifications.length === 0}
                  <div class="px-4 py-6 text-sm text-center text-gray-500 dark:text-gray-400">
                    No hay notificaciones
                  </div>
                {:else}
                  <div class="max-h-60 overflow-y-auto">
                    {#each $antivirusStore.notifications.slice(0, 5) as notification}
                      <div class="px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700">
                        <p class="text-sm font-medium text-gray-900 dark:text-white">{notification.title}</p>
                        <p class="text-xs text-gray-500 dark:text-gray-400">{notification.message}</p>
                      </div>
                    {/each}
                  </div>
                  <div class="border-t border-gray-200 dark:border-gray-700">
                    <button
                      class="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700"
                      on:click={() => antivirusStore.clearNotifications()}
                    >
                      Borrar todas
                    </button>
                  </div>
                {/if}
              </div>
            </div>
          {/if}
        </div>
        
        <!-- Perfil / Menú -->
        <div class="relative">
          <button
            class="p-1 rounded-full border-2 border-gray-300 dark:border-gray-600 hover:border-primary-500 dark:hover:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
            on:click={() => showProfileMenu = !showProfileMenu}
            aria-label="Menú de usuario"
          >
            <span class="sr-only">Abrir menú de usuario</span>
            <Icon name="user" size={18} class_="text-gray-600 dark:text-gray-300" />
          </button>
          
          {#if showProfileMenu}
            <div
              class="origin-top-right absolute right-0 mt-2 w-48 rounded-md shadow-lg bg-white dark:bg-gray-800 ring-1 ring-black ring-opacity-5 focus:outline-none z-30"
              tabindex="-1"
            >
              <div class="py-1" role="menu" aria-orientation="vertical">
                <a
                  href="#"
                  class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700"
                  role="menuitem"
                >
                  Configuración
                </a>
                <a
                  href="#"
                  class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700"
                  role="menuitem"
                >
                  Ayuda
                </a>
                <a
                  href="#"
                  class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700"
                  role="menuitem"
                >
                  Cerrar sesión
                </a>
              </div>
            </div>
          {/if}
        </div>
      </div>
    </div>
  </div>
</header> 