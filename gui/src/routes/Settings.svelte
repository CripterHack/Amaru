<script lang="ts">
  import { theme } from '../lib/stores/theme';
</script>

<div class="p-6 space-y-6 max-w-3xl">
  <h1 class="text-2xl font-bold">Settings</h1>
  <section class="bg-white dark:bg-gray-800 rounded-lg shadow p-5 space-y-3">
    <h2 class="text-xl font-semibold">Appearance</h2>
    <label for="theme" class="block font-medium">Color theme</label>
    <select id="theme" bind:value={$theme} class="border rounded p-2 dark:bg-gray-700">
      <option value="system">Use Windows theme</option>
      <option value="light">Light</option>
      <option value="dark">Dark</option>
    </select>
  </section>
  <section class="bg-white dark:bg-gray-800 rounded-lg shadow p-5 space-y-3">
    <h2 class="text-xl font-semibold">Scanning and protection</h2>
    <p><a href="#/scan-config" class="underline">Configure quick scan folders and schedule</a></p>
    <p><a href="#/dashboard" class="underline">View real-time protection status</a></p>
    <p class="text-sm text-gray-600 dark:text-gray-300">Administrators can edit monitored folders, engine limits and the automatic quarantine policy in the installation's config.toml. Restart the service after changing that file.</p>
  </section>
</div>
