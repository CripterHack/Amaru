<script lang="ts">
  import { icons } from 'lucide-svelte';
  
  export let name: keyof typeof icons;
  export let size = 24;
  export let strokeWidth = 2;
  export let class_ = '';
  
  $: icon = icons[name];
</script>

<svg
  xmlns="http://www.w3.org/2000/svg"
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width={strokeWidth}
  stroke-linecap="round"
  stroke-linejoin="round"
  class={class_}
  {...$$restProps}
>
  {@html icon}
</svg> 