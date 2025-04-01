<script lang="ts">
  export let title: string;
  export let value: string | number;
  export let subtitle: string = '';
  export let icon: string = '';
  export let iconBg: string = 'bg-blue-100';
  export let iconColor: string = 'text-blue-500';
  export let trend: number | null = null;
  export let trendTime: string = 'vs last period';
</script>

<div class="p-6 bg-white dark:bg-gray-800 rounded-lg shadow">
  <div class="flex justify-between items-start mb-4">
    <div>
      <h3 class="text-lg font-medium text-gray-900 dark:text-white">{title}</h3>
      {#if subtitle}
        <p class="text-sm text-gray-500 dark:text-gray-400">{subtitle}</p>
      {/if}
    </div>
    {#if icon}
      <div class={`p-3 rounded-full ${iconBg}`}>
        <span class={`material-icons ${iconColor}`}>{icon}</span>
      </div>
    {/if}
  </div>
  
  <div class="flex flex-col">
    <div class="text-3xl font-bold text-gray-900 dark:text-white">{value}</div>
    
    {#if trend !== null}
      <div class="flex items-center mt-2">
        <span class={`material-icons text-sm ${trend >= 0 ? 'text-green-500' : 'text-red-500'}`}>
          {trend >= 0 ? 'trending_up' : 'trending_down'}
        </span>
        <span class={`ml-1 text-sm ${trend >= 0 ? 'text-green-500' : 'text-red-500'}`}>
          {Math.abs(trend)}%
        </span>
        <span class="ml-1 text-xs text-gray-500 dark:text-gray-400">{trendTime}</span>
      </div>
    {/if}
  </div>
</div> 