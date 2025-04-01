<script lang="ts">
	import { onMount } from 'svelte';
	import { notify } from '../lib/components/Notifications.svelte';

	// Scan configuration
	let scanConfig = {
		scanLocations: [
			{ path: 'C:\\', label: 'System Drive (C:)', checked: true },
			{ path: 'D:\\', label: 'Data Drive (D:)', checked: false },
			{ path: '%USERPROFILE%\\Downloads', label: 'Downloads Folder', checked: true },
			{ path: '%USERPROFILE%\\Documents', label: 'Documents Folder', checked: true }
		],
		customLocations: [] as string[],
		scanOptions: {
			scanArchives: true,
			scanHidden: true,
			scanRemovable: true,
			scanNetwork: false,
			heuristicLevel: 2, // 0: Off, 1: Low, 2: Medium, 3: High
			threatActions: 'quarantine' // 'report', 'quarantine', 'delete'
		},
		schedule: {
			enabled: true,
			frequency: 'weekly', // 'daily', 'weekly', 'monthly'
			day: 0, // 0-6 for days of week (weekly), 1-31 for days of month (monthly)
			time: '02:00',
			type: 'quick' // 'quick', 'full', 'custom'
		}
	};

	// New custom location
	let newLocation = '';

	// Add custom location
	function addCustomLocation() {
		if (!newLocation.trim()) return;
		
		scanConfig.customLocations = [...scanConfig.customLocations, newLocation.trim()];
		newLocation = '';
		
		notify('Location added', `Added ${newLocation} to scan locations`, 'success');
	}

	// Remove custom location
	function removeCustomLocation(index: number) {
		const location = scanConfig.customLocations[index];
		scanConfig.customLocations = scanConfig.customLocations.filter((_, i) => i !== index);
		
		notify('Location removed', `Removed ${location} from scan locations`, 'info');
	}

	// Save configuration
	async function saveConfiguration() {
		try {
			// Here we would normally save to backend
			// await invoke('save_scan_config', { config: scanConfig });
			
			// For now, just simulate
			await new Promise(resolve => setTimeout(resolve, 500));
			
			notify('Configuration saved', 'Scan configuration has been updated successfully', 'success');
		} catch (error) {
			console.error('Failed to save scan configuration:', error);
			notify('Save failed', 'Failed to save scan configuration', 'error');
		}
	}

	onMount(async () => {
		try {
			// Here we would normally load from backend
			// const config = await invoke('get_scan_config');
			// scanConfig = config;
			
			// For now, just simulate a delay
			await new Promise(resolve => setTimeout(resolve, 500));
			
			notify('Configuration loaded', 'Scan configuration loaded successfully', 'info');
		} catch (error) {
			console.error('Failed to load scan configuration:', error);
			notify('Load failed', 'Failed to load scan configuration', 'error');
		}
	});
</script>

<div class="container mx-auto px-4 py-8">
	<h1 class="text-3xl font-bold mb-8">Scan Configuration</h1>
	
	<div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
		<!-- Scan Locations -->
		<div class="lg:col-span-2">
			<div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6 mb-8">
				<h2 class="text-xl font-semibold mb-4">Scan Locations</h2>
				
				<div class="mb-6">
					<h3 class="text-lg font-medium mb-2">Default Locations</h3>
					{#each scanConfig.scanLocations as location, i}
						<div class="flex items-center mb-2">
							<input
								type="checkbox"
								id={`location-${i}`}
								bind:checked={location.checked}
								class="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
							/>
							<label for={`location-${i}`} class="ml-2">{location.label} <span class="text-gray-500">({location.path})</span></label>
						</div>
					{/each}
				</div>
				
				<div>
					<h3 class="text-lg font-medium mb-2">Custom Locations</h3>
					{#if scanConfig.customLocations.length === 0}
						<p class="text-gray-500 dark:text-gray-400 mb-4">No custom locations added.</p>
					{:else}
						<ul class="mb-4">
							{#each scanConfig.customLocations as location, i}
								<li class="flex justify-between items-center py-2 border-b dark:border-gray-700">
									<span>{location}</span>
									<button 
										on:click={() => removeCustomLocation(i)} 
										class="text-red-500 hover:text-red-700"
									>
										Remove
									</button>
								</li>
							{/each}
						</ul>
					{/if}
					
					<div class="flex">
						<input
							type="text"
							bind:value={newLocation}
							placeholder="Enter path (e.g. C:\Program Files)"
							class="flex-1 border border-gray-300 dark:border-gray-600 rounded-l px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700"
						/>
						<button
							on:click={addCustomLocation}
							class="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-r"
						>
							Add
						</button>
					</div>
				</div>
			</div>
		</div>
		
		<!-- Scan Options -->
		<div>
			<div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6 mb-8">
				<h2 class="text-xl font-semibold mb-4">Scan Options</h2>
				
				<div class="mb-4">
					<label class="block mb-2 font-medium">Scan Items</label>
					
					<div class="flex items-center mb-2">
						<input
							type="checkbox"
							id="scanArchives"
							bind:checked={scanConfig.scanOptions.scanArchives}
							class="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
						/>
						<label for="scanArchives" class="ml-2">Scan inside archives</label>
					</div>
					
					<div class="flex items-center mb-2">
						<input
							type="checkbox"
							id="scanHidden"
							bind:checked={scanConfig.scanOptions.scanHidden}
							class="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
						/>
						<label for="scanHidden" class="ml-2">Scan hidden files</label>
					</div>
					
					<div class="flex items-center mb-2">
						<input
							type="checkbox"
							id="scanRemovable"
							bind:checked={scanConfig.scanOptions.scanRemovable}
							class="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
						/>
						<label for="scanRemovable" class="ml-2">Scan removable drives</label>
					</div>
					
					<div class="flex items-center">
						<input
							type="checkbox"
							id="scanNetwork"
							bind:checked={scanConfig.scanOptions.scanNetwork}
							class="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
						/>
						<label for="scanNetwork" class="ml-2">Scan network drives</label>
					</div>
				</div>
				
				<div class="mb-4">
					<label for="heuristicLevel" class="block mb-2 font-medium">Heuristic Level</label>
					<select
						id="heuristicLevel"
						bind:value={scanConfig.scanOptions.heuristicLevel}
						class="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700"
					>
						<option value={0}>Off - Signature-based detection only</option>
						<option value={1}>Low - Minimal false positives</option>
						<option value={2}>Medium - Balanced detection</option>
						<option value={3}>High - Aggressive detection</option>
					</select>
				</div>
				
				<div>
					<label for="threatActions" class="block mb-2 font-medium">When Threats Found</label>
					<select
						id="threatActions"
						bind:value={scanConfig.scanOptions.threatActions}
						class="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700"
					>
						<option value="report">Report only</option>
						<option value="quarantine">Move to quarantine</option>
						<option value="delete">Delete immediately</option>
					</select>
				</div>
			</div>
			
			<div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
				<h2 class="text-xl font-semibold mb-4">Schedule</h2>
				
				<div class="flex items-center mb-4">
					<input
						type="checkbox"
						id="scheduleEnabled"
						bind:checked={scanConfig.schedule.enabled}
						class="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
					/>
					<label for="scheduleEnabled" class="ml-2 font-medium">Enable scheduled scan</label>
				</div>
				
				{#if scanConfig.schedule.enabled}
					<div class="mb-4">
						<label for="frequency" class="block mb-2">Frequency</label>
						<select
							id="frequency"
							bind:value={scanConfig.schedule.frequency}
							class="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700"
						>
							<option value="daily">Daily</option>
							<option value="weekly">Weekly</option>
							<option value="monthly">Monthly</option>
						</select>
					</div>
					
					{#if scanConfig.schedule.frequency === 'weekly'}
						<div class="mb-4">
							<label for="day" class="block mb-2">Day of Week</label>
							<select
								id="day"
								bind:value={scanConfig.schedule.day}
								class="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700"
							>
								<option value={0}>Sunday</option>
								<option value={1}>Monday</option>
								<option value={2}>Tuesday</option>
								<option value={3}>Wednesday</option>
								<option value={4}>Thursday</option>
								<option value={5}>Friday</option>
								<option value={6}>Saturday</option>
							</select>
						</div>
					{:else if scanConfig.schedule.frequency === 'monthly'}
						<div class="mb-4">
							<label for="day" class="block mb-2">Day of Month</label>
							<select
								id="day"
								bind:value={scanConfig.schedule.day}
								class="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700"
							>
								{#each Array(31) as _, i}
									<option value={i + 1}>{i + 1}</option>
								{/each}
							</select>
						</div>
					{/if}
					
					<div class="mb-4">
						<label for="time" class="block mb-2">Time</label>
						<input
							type="time"
							id="time"
							bind:value={scanConfig.schedule.time}
							class="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700"
						/>
					</div>
					
					<div>
						<label for="scanType" class="block mb-2">Scan Type</label>
						<select
							id="scanType"
							bind:value={scanConfig.schedule.type}
							class="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700"
						>
							<option value="quick">Quick Scan</option>
							<option value="full">Full Scan</option>
							<option value="custom">Custom Scan</option>
						</select>
					</div>
				{/if}
			</div>
		</div>
	</div>
	
	<div class="mt-8 flex justify-end">
		<button
			on:click={saveConfiguration}
			class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-3 rounded-lg font-medium"
		>
			Save Configuration
		</button>
	</div>
</div> 