<script>
  import { Shield, Activity, Clock, AlertTriangle } from 'lucide-svelte';
  
  export let title = '';
  export let status = '';
  export let statusType = 'success'; // success, warning, danger, info
  export let icon = 'shield'; // shield, activity, clock, alert-triangle
  export let action = null;
  export let actionText = 'Toggle';
  
  const icons = {
    shield: Shield,
    activity: Activity,
    clock: Clock,
    'alert-triangle': AlertTriangle
  };
  
  const statusColors = {
    success: 'bg-green-100 text-green-800',
    warning: 'bg-yellow-100 text-yellow-800',
    danger: 'bg-red-100 text-red-800',
    info: 'bg-blue-100 text-blue-800'
  };
  
  const iconColors = {
    success: 'text-green-500',
    warning: 'text-yellow-500',
    danger: 'text-red-500',
    info: 'text-blue-500'
  };
  
  const IconComponent = icons[icon];
</script>

<div class="bg-white rounded-lg shadow-md p-6 relative overflow-hidden">
  <div class="absolute top-0 right-0 opacity-10 scale-150 transform translate-x-1/4 -translate-y-1/4">
    <svelte:component this={IconComponent} size={80} />
  </div>

  <div class="flex justify-between items-start">
    <div>
      <h3 class="text-lg font-medium text-gray-700">{title}</h3>
      <div class="flex items-center mt-2">
        <span class="inline-flex items-center justify-center w-8 h-8 rounded-full {iconColors[statusType]}">
          <svelte:component this={IconComponent} size={18} />
        </span>
        <span class="ml-2 text-xl font-bold {statusColors[statusType]} px-2 py-1 rounded-md">{status}</span>
      </div>
    </div>
    
    {#if action}
      <button 
        on:click={action}
        class="text-xs px-3 py-1 rounded-md bg-gray-100 hover:bg-gray-200 text-gray-700 transition-colors duration-200"
      >
        {actionText}
      </button>
    {/if}
  </div>
</div> 