<script lang="ts">
  export let variant: 'default' | 'primary' | 'danger' | 'success' = 'default';
  export let hoverable = true;
  export let padding = true;
</script>

<div
  class="card"
  class:hoverable
  class:padding
  class:primary={variant === 'primary'}
  class:danger={variant === 'danger'}
  class:success={variant === 'success'}
>
  <slot />
</div>

<style lang="postcss">
  .card {
    @apply bg-white dark:bg-gray-800 rounded-lg shadow-sm transition-all duration-200;
  }
  
  .card.hoverable:hover {
    @apply shadow-md transform -translate-y-0.5;
  }
  
  .card.padding {
    @apply p-6;
  }
  
  .card.primary {
    @apply border-l-4 border-primary-500;
  }
  
  .card.danger {
    @apply border-l-4 border-danger-500;
  }
  
  .card.success {
    @apply border-l-4 border-success-500;
  }
</style> 