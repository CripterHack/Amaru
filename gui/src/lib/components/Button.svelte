<script lang="ts">
  export let variant: 'default' | 'primary' | 'danger' | 'success' = 'default';
  export let size: 'sm' | 'md' | 'lg' = 'md';
  export let type: 'button' | 'submit' | 'reset' = 'button';
  export let disabled = false;
  export let loading = false;
  export let fullWidth = false;
  export let icon: string | null = null;
</script>

<button
  {type}
  {disabled}
  class="button"
  class:primary={variant === 'primary'}
  class:danger={variant === 'danger'}
  class:success={variant === 'success'}
  class:sm={size === 'sm'}
  class:lg={size === 'lg'}
  class:loading
  class:fullWidth
  on:click
  on:focus
  on:blur
  {...$$restProps}
>
  {#if loading}
    <svg
      class="animate-spin -ml-1 mr-2 h-4 w-4"
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
    >
      <circle
        class="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        stroke-width="4"
      />
      <path
        class="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      />
    </svg>
  {:else if icon}
    <span class="icon mr-2">
      <slot name="icon" />
    </span>
  {/if}
  <slot />
</button>

<style lang="postcss">
  .button {
    @apply inline-flex items-center justify-center px-4 py-2 border border-transparent
           rounded-md font-medium focus:outline-none focus:ring-2 focus:ring-offset-2
           transition-colors duration-200 ease-in-out;
  }
  
  .button:disabled {
    @apply opacity-50 cursor-not-allowed;
  }
  
  .button.primary {
    @apply bg-primary-600 text-white hover:bg-primary-700 focus:ring-primary-500;
  }
  
  .button.danger {
    @apply bg-danger-600 text-white hover:bg-danger-700 focus:ring-danger-500;
  }
  
  .button.success {
    @apply bg-success-600 text-white hover:bg-success-700 focus:ring-success-500;
  }
  
  .button.default {
    @apply bg-gray-100 text-gray-700 hover:bg-gray-200 focus:ring-gray-500
           dark:bg-gray-700 dark:text-gray-100 dark:hover:bg-gray-600;
  }
  
  .button.sm {
    @apply text-sm px-3 py-1.5;
  }
  
  .button.lg {
    @apply text-lg px-6 py-3;
  }
  
  .button.fullWidth {
    @apply w-full;
  }
  
  .icon {
    @apply -ml-1 mr-2 h-5 w-5;
  }
</style> 