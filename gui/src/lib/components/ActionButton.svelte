<script>
  import { Search, HardDrive, Download, Archive, Shield } from 'lucide-svelte';
  
  export let text = '';
  export let icon = '';
  export let onClick = () => {};
  export let disabled = false;
  export let primary = false;
  
  const icons = {
    'search': Search,
    'hard-drive': HardDrive,
    'download': Download,
    'archive': Archive,
    'shield': Shield
  };
  
  const IconComponent = icons[icon];
</script>

<button
  on:click={onClick}
  {disabled}
  class="flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors duration-200
    {primary 
      ? 'bg-blue-600 text-white hover:bg-blue-700 disabled:bg-blue-300' 
      : 'bg-gray-100 text-gray-700 hover:bg-gray-200 disabled:bg-gray-100 disabled:text-gray-400'}
    {disabled ? 'cursor-not-allowed' : 'cursor-pointer'}"
>
  {#if icon && IconComponent}
    <svelte:component this={IconComponent} size={16} class="mr-2" />
  {/if}
  {text}
</button> 