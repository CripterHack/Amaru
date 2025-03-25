<script lang="ts">
  import { configStore } from '$lib/stores/config';
  import { antivirusStore } from '$lib/stores/antivirus';
  import Icon from '../Icon.svelte';
  import Card from '../Card.svelte';
  
  // Categorías disponibles
  const categories = [
    { id: 'general', name: 'General', icon: 'settings' },
    { id: 'scanning', name: 'Escaneo', icon: 'search' },
    { id: 'protection', name: 'Protección', icon: 'shield' },
    { id: 'notifications', name: 'Notificaciones', icon: 'bell' },
    { id: 'performance', name: 'Rendimiento', icon: 'cpu' },
    { id: 'updates', name: 'Actualizaciones', icon: 'download' },
  ];
  
  // Categoría seleccionada
  let selectedCategory = 'general';
  
  // Función para guardar cambios
  const saveChanges = async () => {
    try {
      // Aquí llamaríamos a una función para guardar la configuración
      await configStore.save();
      
      // Mostrar notificación de éxito
      antivirusStore.addNotification({
        id: crypto.randomUUID(),
        type: 'system',
        title: 'Configuración guardada',
        message: 'La configuración se ha guardado correctamente.',
        timestamp: new Date(),
        priority: 'low',
        acknowledged: false
      });
    } catch (error) {
      console.error('Error al guardar la configuración:', error);
      
      // Mostrar notificación de error
      antivirusStore.addNotification({
        id: crypto.randomUUID(),
        type: 'system',
        title: 'Error al guardar',
        message: 'No se pudo guardar la configuración.',
        timestamp: new Date(),
        priority: 'high',
        acknowledged: false
      });
    }
  };
</script>

<div class="max-w-7xl mx-auto">
  <h1 class="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-6">
    Configuración
  </h1>
  
  <div class="flex flex-col md:flex-row gap-6">
    <!-- Sidebar de categorías -->
    <div class="w-full md:w-64 shrink-0">
      <Card>
        <ul class="space-y-1">
          {#each categories as category}
            <li>
              <button
                on:click={() => (selectedCategory = category.id)}
                class="w-full flex items-center px-3 py-2 rounded-md transition-colors 
                       {selectedCategory === category.id 
                       ? 'bg-primary-100 text-primary-700 dark:bg-primary-900 dark:text-primary-300' 
                       : 'hover:bg-gray-100 dark:hover:bg-gray-800'}"
              >
                <Icon name={category.icon} size={20} class_="mr-2" />
                <span>{category.name}</span>
              </button>
            </li>
          {/each}
        </ul>
      </Card>
    </div>
    
    <!-- Contenido de configuración -->
    <div class="flex-1">
      <Card>
        {#if selectedCategory === 'general'}
          <h2 class="text-xl font-semibold mb-4">Configuración General</h2>
          
          <div class="space-y-4">
            <div class="flex items-center justify-between p-3 border-b border-gray-200 dark:border-gray-700">
              <div>
                <h3 class="font-medium">Inicio automático</h3>
                <p class="text-sm text-gray-500 dark:text-gray-400">
                  Iniciar Amaru Antivirus automáticamente al arrancar Windows
                </p>
              </div>
              <label class="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  class="sr-only peer" 
                  bind:checked={$configStore.autostart}
                />
                <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:peer-focus:ring-primary-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-primary-600"></div>
              </label>
            </div>
            
            <div class="flex items-center justify-between p-3 border-b border-gray-200 dark:border-gray-700">
              <div>
                <h3 class="font-medium">Tema de la interfaz</h3>
                <p class="text-sm text-gray-500 dark:text-gray-400">
                  Selecciona el tema visual para la aplicación
                </p>
              </div>
              <select 
                class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-500 focus:border-primary-500 p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-primary-500 dark:focus:border-primary-500"
                bind:value={$configStore.ui.theme}
              >
                <option value="light">Claro</option>
                <option value="dark">Oscuro</option>
                <option value="system">Sistema</option>
              </select>
            </div>
            
            <div class="flex items-center justify-between p-3">
              <div>
                <h3 class="font-medium">Minimizar a la bandeja</h3>
                <p class="text-sm text-gray-500 dark:text-gray-400">
                  Mantener la aplicación en la bandeja del sistema al cerrar
                </p>
              </div>
              <label class="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  class="sr-only peer" 
                  bind:checked={$configStore.ui.minimizeToTray}
                />
                <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:peer-focus:ring-primary-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-primary-600"></div>
              </label>
            </div>
          </div>
          
        {:else if selectedCategory === 'notifications'}
          <h2 class="text-xl font-semibold mb-4">Configuración de Notificaciones</h2>
          
          <div class="space-y-4">
            <div class="flex items-center justify-between p-3 border-b border-gray-200 dark:border-gray-700">
              <div>
                <h3 class="font-medium">Mostrar notificaciones</h3>
                <p class="text-sm text-gray-500 dark:text-gray-400">
                  Habilitar notificaciones en tiempo real
                </p>
              </div>
              <label class="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  class="sr-only peer" 
                  bind:checked={$configStore.ui.showNotifications}
                />
                <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:peer-focus:ring-primary-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-primary-600"></div>
              </label>
            </div>
            
            <div class="flex items-center justify-between p-3 border-b border-gray-200 dark:border-gray-700">
              <div>
                <h3 class="font-medium">Notificar amenazas</h3>
                <p class="text-sm text-gray-500 dark:text-gray-400">
                  Mostrar alerta cuando se detecta una amenaza
                </p>
              </div>
              <label class="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  class="sr-only peer" 
                  checked
                  disabled
                />
                <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:peer-focus:ring-primary-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-primary-600"></div>
              </label>
            </div>
            
            <div class="flex items-center justify-between p-3">
              <div>
                <h3 class="font-medium">Notificar actualizaciones</h3>
                <p class="text-sm text-gray-500 dark:text-gray-400">
                  Mostrar alertas de actualizaciones disponibles
                </p>
              </div>
              <label class="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  class="sr-only peer" 
                  checked
                />
                <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:peer-focus:ring-primary-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-primary-600"></div>
              </label>
            </div>
          </div>
          
        {:else if selectedCategory === 'performance'}
          <h2 class="text-xl font-semibold mb-4">Configuración de Rendimiento</h2>
          
          <div class="space-y-4">
            <div class="flex items-center justify-between p-3 border-b border-gray-200 dark:border-gray-700">
              <div>
                <h3 class="font-medium">Modo de bajo consumo</h3>
                <p class="text-sm text-gray-500 dark:text-gray-400">
                  Reducir el uso de recursos del sistema
                </p>
              </div>
              <label class="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  class="sr-only peer" 
                  bind:checked={$configStore.performance.lowResourceMode}
                />
                <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:peer-focus:ring-primary-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-primary-600"></div>
              </label>
            </div>
            
            <div class="flex items-center justify-between p-3 border-b border-gray-200 dark:border-gray-700">
              <div>
                <h3 class="font-medium">Prioridad del proceso</h3>
                <p class="text-sm text-gray-500 dark:text-gray-400">
                  Establecer prioridad para el servicio de Amaru
                </p>
              </div>
              <select 
                class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-500 focus:border-primary-500 p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-primary-500 dark:focus:border-primary-500"
                bind:value={$configStore.performance.processPriority}
              >
                <option value="low">Baja</option>
                <option value="below-normal">Por debajo de lo normal</option>
                <option value="normal">Normal</option>
                <option value="above-normal">Por encima de lo normal</option>
                <option value="high">Alta</option>
              </select>
            </div>
            
            <div class="p-3">
              <div>
                <h3 class="font-medium mb-2">Límite de uso de CPU (%)</h3>
                <input 
                  type="range" 
                  min="10" 
                  max="100" 
                  step="5" 
                  class="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer dark:bg-gray-700"
                  bind:value={$configStore.performance.highUsageThreshold}
                />
                <div class="flex justify-between text-xs text-gray-500 dark:text-gray-400 mt-1">
                  <span>10%</span>
                  <span>50%</span>
                  <span>100%</span>
                </div>
                <p class="text-sm text-primary-600 dark:text-primary-400 mt-2">
                  Valor actual: {$configStore.performance.highUsageThreshold}%
                </p>
              </div>
            </div>
          </div>
          
        {/if}
        
        <!-- Botones -->
        <div class="mt-6 flex justify-end space-x-4">
          <button
            class="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md shadow-sm hover:bg-gray-50 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-600 dark:hover:bg-gray-700"
            on:click={() => configStore.reset()}
          >
            Restablecer
          </button>
          
          <button
            class="px-4 py-2 text-sm font-medium text-white bg-primary-600 border border-transparent rounded-md shadow-sm hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 dark:bg-primary-700 dark:hover:bg-primary-600"
            on:click={saveChanges}
          >
            Guardar cambios
          </button>
        </div>
      </Card>
    </div>
  </div>
</div> 