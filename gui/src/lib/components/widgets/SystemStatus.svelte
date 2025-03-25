<script lang="ts">
  import { antivirusStore } from '$lib/stores/antivirus';
  import Icon from '../Icon.svelte';
  import Card from '../Card.svelte';
  import ScanAnimation from '../animations/ScanAnimation.svelte';
  
  // Función para formatear números grandes
  function formatNumber(num: number): string {
    if (num >= 1000000) {
      return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
      return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
  }
  
  // Función para formatear fecha a formato local
  function formatDate(date: Date | null): string {
    if (!date) return 'Nunca';
    return date.toLocaleString();
  }
  
  // Función para calcular tiempo desde último escaneo
  function getTimeSinceLastScan(date: Date | null): string {
    if (!date) return 'Nunca';
    
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    const diffHours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    
    if (diffDays > 0) {
      return `Hace ${diffDays} día${diffDays !== 1 ? 's' : ''}`;
    } else if (diffHours > 0) {
      return `Hace ${diffHours} hora${diffHours !== 1 ? 's' : ''}`;
    } else {
      return 'Hace menos de una hora';
    }
  }
</script>

<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
  <!-- Estado de la protección -->
  <Card>
    <div class="p-4">
      <div class="flex items-center justify-between">
        <div>
          <h3 class="text-sm font-medium text-gray-500 dark:text-gray-400">Estado</h3>
          <div class="mt-1 flex items-center">
            <Icon 
              name={$antivirusStore.realtimeProtection ? "shield-check" : "shield-off"} 
              size={20} 
              class_={$antivirusStore.realtimeProtection 
                ? "text-green-500 dark:text-green-400" 
                : "text-yellow-500 dark:text-yellow-400"} 
            />
            <span 
              class="ml-2 text-lg font-semibold {$antivirusStore.realtimeProtection 
                ? 'text-green-600 dark:text-green-500' 
                : 'text-yellow-600 dark:text-yellow-500'}"
            >
              {$antivirusStore.realtimeProtection ? "Protegido" : "Desprotegido"}
            </span>
          </div>
        </div>
        <div class="flex-shrink-0">
          <button
            class={`inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded-full shadow-sm text-white focus:outline-none focus:ring-2 focus:ring-offset-2 ${
              $antivirusStore.realtimeProtection
                ? 'bg-red-600 hover:bg-red-700 focus:ring-red-500'
                : 'bg-green-600 hover:bg-green-700 focus:ring-green-500'
            }`}
            on:click={() => antivirusStore.toggleRealtimeProtection()}
          >
            {$antivirusStore.realtimeProtection ? "Desactivar" : "Activar"}
          </button>
        </div>
      </div>
    </div>
  </Card>
  
  <!-- Escaneos realizados -->
  <Card>
    <div class="p-4">
      <h3 class="text-sm font-medium text-gray-500 dark:text-gray-400">Archivos Escaneados</h3>
      <div class="mt-1 flex items-center">
        <Icon name="file-check" size={20} class_="text-primary-500 dark:text-primary-400" />
        <span class="ml-2 text-2xl font-semibold text-gray-900 dark:text-gray-100">
          {formatNumber($antivirusStore.stats.filesScanned)}
        </span>
      </div>
      <p class="mt-2 text-xs text-gray-500 dark:text-gray-400">
        Último escaneo: {getTimeSinceLastScan($antivirusStore.stats.lastScan)}
      </p>
    </div>
  </Card>
  
  <!-- Amenazas detectadas -->
  <Card>
    <div class="p-4">
      <h3 class="text-sm font-medium text-gray-500 dark:text-gray-400">Amenazas Detectadas</h3>
      <div class="mt-1 flex items-center">
        <Icon name="shield-alert" size={20} class_="text-red-500 dark:text-red-400" />
        <span class="ml-2 text-2xl font-semibold text-gray-900 dark:text-gray-100">
          {formatNumber($antivirusStore.stats.threatsFound)}
        </span>
      </div>
      {#if $antivirusStore.stats.heuristicThreats > 0}
        <p class="mt-2 text-xs text-gray-500 dark:text-gray-400">
          <span class="inline-flex items-center">
            <Icon name="brain" size={12} class_="mr-1" />
            {$antivirusStore.stats.heuristicThreats} detectadas por heurística
          </span>
        </p>
      {/if}
    </div>
  </Card>
  
  <!-- Estado del análisis en curso -->
  <Card>
    <div class="p-4">
      {#if $antivirusStore.scanning}
        <div class="flex items-center">
          <div class="flex-shrink-0">
            <ScanAnimation size={48} animate={true} />
          </div>
          <div class="ml-3">
            <h3 class="text-sm font-medium text-gray-900 dark:text-white">Escaneando...</h3>
            {#if $antivirusStore.currentFile}
              <p class="text-xs text-gray-500 dark:text-gray-400 truncate max-w-[180px]">
                {$antivirusStore.currentFile}
              </p>
            {/if}
            <button
              class="mt-2 inline-flex items-center px-2.5 py-1 border border-transparent text-xs font-medium rounded shadow-sm text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
              on:click={() => antivirusStore.stopScan()}
            >
              Detener
            </button>
          </div>
        </div>
      {:else}
        <div class="flex flex-col items-center justify-center h-full py-2">
          <h3 class="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Iniciar Escaneo</h3>
          <div class="flex space-x-2">
            <button
              class="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded shadow-sm text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
              on:click={() => antivirusStore.startScan('C:\\', true)}
            >
              <Icon name="search" size={14} class_="mr-1" />
              Rápido
            </button>
            <button
              class="inline-flex items-center px-3 py-1.5 border border-gray-300 dark:border-gray-700 text-xs font-medium rounded shadow-sm text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
              on:click={() => antivirusStore.startScan('C:\\', true)}
            >
              <Icon name="hard-drive" size={14} class_="mr-1" />
              Completo
            </button>
          </div>
        </div>
      {/if}
    </div>
  </Card>
</div> 