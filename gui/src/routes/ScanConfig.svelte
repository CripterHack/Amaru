<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  import { open } from '@tauri-apps/api/dialog';

  type Schedule = { frequency: 'daily' | 'weekly'; day: number; time: string; path?: string | null };
  const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  let paths: string[] = [];
  let pathsReady = false;
  let scheduleReady = false;
  let enabled = false;
  let schedule: Schedule = { frequency: 'weekly', day: 0, time: '02:00' };
  let pathsMessage = '';
  let scheduleMessage = '';
  let savingPaths = false;
  let savingSchedule = false;

  function showSchedule(value: Schedule | null) {
    enabled = value !== null;
    if (value) schedule = value;
  }

  onMount(() => {
    invoke<string[]>('get_quick_paths').then(value => { paths = value; pathsReady = true; })
      .catch(e => pathsMessage = String(e));
    invoke<Schedule | null>('get_schedule').then(value => { showSchedule(value); scheduleReady = true; })
      .catch(e => scheduleMessage = String(e));
  });

  async function addFolder() {
    try {
      const selected = await open({ directory: true, multiple: false });
      if (typeof selected === 'string' && !paths.includes(selected)) paths = [...paths, selected];
    } catch (error) { pathsMessage = String(error); }
  }

  async function savePaths(reset: boolean) {
    savingPaths = true;
    try {
      paths = await invoke<string[]>('save_quick_paths', { paths: reset ? null : paths });
      pathsReady = true;
      pathsMessage = reset ? 'Default folders restored.' : 'Quick scan folders saved.';
    } catch (error) { pathsMessage = String(error); }
    finally { savingPaths = false; }
  }

  async function saveSchedule() {
    savingSchedule = true;
    try {
      const value = await invoke<Schedule | null>('set_schedule', { schedule: enabled ? schedule : null });
      showSchedule(value);
      scheduleMessage = enabled ? 'Schedule saved in Windows Task Scheduler.' : 'Scheduled quick scan disabled.';
    } catch (error) { scheduleMessage = String(error); }
    finally { savingSchedule = false; }
  }
</script>

<div class="p-6 space-y-6 max-w-3xl">
  <h1 class="text-2xl font-bold">Scan configuration</h1>
  <section class="bg-white dark:bg-gray-800 rounded-lg shadow p-5 space-y-4">
    <h2 class="text-xl font-semibold">Quick scan folders</h2>
    <p>Manual and scheduled quick scans include these folders and their contents.</p>
    {#if pathsReady}
      <ul>
        {#each paths as path}
          <li class="flex items-center justify-between gap-4 py-2 border-b">
            <span class="break-all">{path}</span>
            <button aria-label={'Remove ' + path} on:click={() => paths = paths.filter(p => p !== path)}>Remove</button>
          </li>
        {/each}
      </ul>
    {/if}
    <div class="flex flex-wrap gap-4">
      <button class="underline" disabled={!pathsReady || savingPaths} on:click={addFolder}>Add folder</button>
      <button class="underline" disabled={savingPaths} on:click={() => savePaths(true)}>Restore defaults</button>
      <button class="rounded bg-blue-700 px-4 py-2 text-white disabled:opacity-50" disabled={!pathsReady || !paths.length || savingPaths} on:click={() => savePaths(false)}>Save folders</button>
    </div>
    {#if pathsMessage}<p role="status">{pathsMessage}</p>{/if}
  </section>
  <form on:submit|preventDefault={saveSchedule} class="bg-white dark:bg-gray-800 rounded-lg shadow p-5 space-y-4">
    <h2 class="text-xl font-semibold">Scheduled quick scan</h2>
    <p>Windows runs the scan under your account while you are signed in. Results appear in Scan history.</p>
    <fieldset disabled={!scheduleReady || savingSchedule} class="space-y-4">
      <label class="block"><input type="checkbox" bind:checked={enabled}> Enable scheduled scans</label>
      {#if enabled}
        {#if schedule.path}
          <p>Scheduled location <strong class="break-all">{schedule.path}</strong>
            <button type="button" class="underline" on:click={() => schedule = {...schedule, path: null}}>Use quick scan folders</button>
          </p>
        {/if}
        <label class="block">Frequency
          <select bind:value={schedule.frequency} class="border rounded p-1 dark:bg-gray-700">
            <option value="daily">Daily</option><option value="weekly">Weekly</option>
          </select>
        </label>
        {#if schedule.frequency === 'weekly'}
          <label class="block">Weekday
            <select bind:value={schedule.day} class="border rounded p-1 dark:bg-gray-700">
              {#each days as day, i}<option value={i}>{day}</option>{/each}
            </select>
          </label>
        {/if}
        <label class="block">Local time <input required type="time" bind:value={schedule.time} class="border rounded p-1 dark:bg-gray-700"></label>
      {/if}
      <button class="rounded bg-blue-700 px-4 py-2 text-white disabled:opacity-50">Save schedule</button>
    </fieldset>
    {#if scheduleMessage}<p role="status">{scheduleMessage}</p>{/if}
  </form>
</div>
