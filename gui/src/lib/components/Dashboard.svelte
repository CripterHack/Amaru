<script lang="ts">
  import { antivirusStore } from '$lib/stores/antivirus';
  import { configStore } from '$lib/stores/config';
  import { formatNumber, formatDate } from '$lib/utils';
  import Icon from '$components/Icon.svelte';
  import Card from '$components/Card.svelte';
  import Button from '$components/Button.svelte';
  import { open } from '@tauri-apps/api/dialog';

  let scanning = false;
  let showPerformancePanel = false;

  async function handleQuickScan() {
    const selected = await open({
      directory: true,
      multiple: false,
      title: 'Seleccionar carpeta para escaneo rápido'
    });

    if (selected) {
      await antivirusStore.startScan(selected as string, $configStore.heuristicAnalysis);
    }
  }

  function togglePerformancePanel() {
    showPerformancePanel = !showPerformancePanel;
  }

  function toggleLowResourceMode() {
    configStore.update(config => {
      config.performance.lowResourceMode = !config.performance.lowResourceMode;
      return config;
    });
  }

  $: ({ stats, realtimeProtection, heuristicEnabled } = $antivirusStore);
  $: ({ performance, autostart } = $configStore);
</script>

<div class="space-y-6">
  <div class="flex justify-between items-center">
    <div>
      <h1 class="text-2xl font-semibold">Panel de Control</h1>
      <p class="text-sm text-gray-500 dark:text-gray-400">
        {#if realtimeProtection}
          <span class="text-success-600 dark:text-success-400 font-medium flex items-center">
            <Icon name="shield-check" class="w-4 h-4 mr-1" />
            Protección en tiempo real activa
          </span>
        {:else}
          <span class="text-danger-600 dark:text-danger-400 font-medium flex items-center">
            <Icon name="shield-off" class="w-4 h-4 mr-1" />
            Protección en tiempo real inactiva
          </span>
        {/if}
      </p>
    </div>
    <div class="flex space-x-3">
      <Button variant="outline" on:click={togglePerformancePanel}>
        <Icon name="settings" class="w-5 h-5 mr-2" />
        Rendimiento
      </Button>
      <Button variant="primary" on:click={handleQuickScan} disabled={scanning}>
        <Icon name="search" class="w-5 h-5 mr-2" />
        Escaneo Rápido
      </Button>
      <Button
        variant={realtimeProtection ? "success" : "danger"}
        on:click={() => antivirusStore.toggleRealtimeProtection()}
      >
        <Icon name={realtimeProtection ? "shield-check" : "shield-off"} class="w-5 h-5 mr-2" />
        {realtimeProtection ? 'Protección Activa' : 'Activar Protección'}
      </Button>
    </div>
  </div>

  {#if showPerformancePanel}
    <Card class="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700">
      <div class="space-y-4">
        <div class="flex justify-between items-center">
          <h3 class="text-lg font-semibold">Configuración de Rendimiento</h3>
          <Button variant="ghost" on:click={togglePerformancePanel}>
            <Icon name="x" class="w-5 h-5" />
          </Button>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex items-center justify-between p-3 bg-white dark:bg-gray-800 rounded-lg">
            <div class="flex items-center">
              <Icon name="cpu" class="w-5 h-5 text-primary-600 dark:text-primary-400 mr-3" />
              <span>Modo de bajo consumo</span>
            </div>
            <label class="relative inline-flex items-center cursor-pointer">
              <input 
                type="checkbox" 
                class="sr-only peer" 
                checked={performance.lowResourceMode}
                on:change={toggleLowResourceMode}
              />
              <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:peer-focus:ring-primary-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-primary-600"></div>
            </label>
          </div>
          
          <div class="flex items-center justify-between p-3 bg-white dark:bg-gray-800 rounded-lg">
            <div class="flex items-center">
              <Icon name="power" class="w-5 h-5 text-primary-600 dark:text-primary-400 mr-3" />
              <span>Inicio automático</span>
            </div>
            <label class="relative inline-flex items-center cursor-pointer">
              <input 
                type="checkbox" 
                class="sr-only peer" 
                checked={autostart}
                on:change={() => configStore.toggleAutostart()}
              />
              <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:peer-focus:ring-primary-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-primary-600"></div>
            </label>
          </div>
          
          <div class="flex items-center justify-between p-3 bg-white dark:bg-gray-800 rounded-lg">
            <div class="flex items-center">
              <Icon name="zap" class="w-5 h-5 text-primary-600 dark:text-primary-400 mr-3" />
              <span>Análisis heurístico</span>
            </div>
            <label class="relative inline-flex items-center cursor-pointer">
              <input 
                type="checkbox" 
                class="sr-only peer" 
                checked={heuristicEnabled}
                on:change={() => antivirusStore.toggleHeuristicAnalysis()}
              />
              <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:peer-focus:ring-primary-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-primary-600"></div>
            </label>
          </div>
          
          <div class="flex items-center justify-between p-3 bg-white dark:bg-gray-800 rounded-lg">
            <div class="flex items-center">
              <Icon name="bell" class="w-5 h-5 text-primary-600 dark:text-primary-400 mr-3" />
              <span>Notificaciones</span>
            </div>
            <label class="relative inline-flex items-center cursor-pointer">
              <input 
                type="checkbox" 
                class="sr-only peer" 
                checked={$configStore.ui.showNotifications}
                on:change={() => configStore.toggleNotifications()}
              />
              <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 dark:peer-focus:ring-primary-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-primary-600"></div>
            </label>
          </div>
        </div>
      </div>
    </Card>
  {/if}

  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
    <Card>
      <div class="flex items-center space-x-4">
        <div class="p-3 bg-primary-100 dark:bg-primary-900 rounded-lg">
          <Icon name="file-search" class="w-8 h-8 text-primary-600 dark:text-primary-400" />
        </div>
        <div>
          <p class="text-sm text-gray-500 dark:text-gray-400">Archivos Escaneados</p>
          <p class="text-2xl font-semibold">{formatNumber(stats.filesScanned)}</p>
        </div>
      </div>
    </Card>

    <Card>
      <div class="flex items-center space-x-4">
        <div class="p-3 bg-danger-100 dark:bg-danger-900 rounded-lg">
          <Icon name="alert-triangle" class="w-8 h-8 text-danger-600 dark:text-danger-400" />
        </div>
        <div>
          <p class="text-sm text-gray-500 dark:text-gray-400">Amenazas Encontradas</p>
          <p class="text-2xl font-semibold">{formatNumber(stats.threatsFound)}</p>
          {#if stats.heuristicThreats > 0}
            <p class="text-xs text-danger-600 dark:text-danger-400">
              {stats.heuristicThreats} por heurística
            </p>
          {/if}
        </div>
      </div>
    </Card>

    <Card>
      <div class="flex items-center space-x-4">
        <div class="p-3 bg-success-100 dark:bg-success-900 rounded-lg">
          <Icon name="shield" class="w-8 h-8 text-success-600 dark:text-success-400" />
        </div>
        <div>
          <p class="text-sm text-gray-500 dark:text-gray-400">Estado de Protección</p>
          <p class="text-2xl font-semibold">{realtimeProtection ? 'Activa' : 'Inactiva'}</p>
          {#if heuristicEnabled && realtimeProtection}
            <p class="text-xs text-success-600 dark:text-success-400">
              Con análisis heurístico
            </p>
          {/if}
        </div>
      </div>
    </Card>

    <Card>
      <div class="flex items-center space-x-4">
        <div class="p-3 bg-primary-100 dark:bg-primary-900 rounded-lg">
          <Icon name="clock" class="w-8 h-8 text-primary-600 dark:text-primary-400" />
        </div>
        <div>
          <p class="text-sm text-gray-500 dark:text-gray-400">Último Escaneo</p>
          <p class="text-2xl font-semibold">
            {stats.lastScan ? formatDate(stats.lastScan) : 'Nunca'}
          </p>
        </div>
      </div>
    </Card>
  </div>

  {#if scanning}
    <Card>
      <div class="space-y-4">
        <div class="flex items-center justify-between">
          <h3 class="text-lg font-medium">Escaneo en Progreso</h3>
          <Button variant="danger" on:click={() => antivirusStore.stopScan()}>
            Detener
          </Button>
        </div>
        <div class="relative pt-1">
          <div class="overflow-hidden h-2 text-xs flex rounded bg-primary-200 dark:bg-primary-700">
            <div
              class="animate-pulse shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center bg-primary-500"
              style="width: 100%"
            />
          </div>
        </div>
        {#if $antivirusStore.currentFile}
          <p class="text-sm text-gray-500 dark:text-gray-400 truncate">
            Analizando: {$antivirusStore.currentFile}
          </p>
        {/if}
      </div>
    </Card>
  {/if}
  
  {#if stats.threatsFound > 0}
    <Card class="bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800">
      <div class="flex items-start space-x-4">
        <div class="p-2 bg-danger-100 dark:bg-danger-800 rounded-lg">
          <Icon name="alert-octagon" class="w-6 h-6 text-danger-600 dark:text-danger-400" />
        </div>
        <div class="flex-1">
          <h3 class="text-lg font-medium text-danger-800 dark:text-danger-300">Se detectaron amenazas</h3>
          <p class="text-sm text-danger-600 dark:text-danger-400">
            Se encontraron {stats.threatsFound} amenazas en tu sistema.
            {#if stats.heuristicThreats > 0}
              {stats.heuristicThreats} fueron detectadas mediante análisis heurístico.
            {/if}
          </p>
          <div class="mt-3">
            <Button variant="danger" size="sm">
              <Icon name="trash-2" class="w-4 h-4 mr-2" />
              Eliminar Amenazas
            </Button>
            <Button variant="ghost" size="sm" class="ml-2">
              Ver Detalles
            </Button>
          </div>
        </div>
      </div>
    </Card>
  {/if}
</div>

<style>
  :global(.card) {
    @apply bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6 transition-all duration-200;
  }
  
  :global(.card:hover) {
    @apply shadow-md;
  }
</style> 