<script>
  import { formatDate, formatDuration } from '$lib/utils';
  
  export let history = [];
</script>

{#if history.length === 0}
  <div class="text-center py-8 text-gray-500">
    <p>No scan history available</p>
    <p class="text-sm mt-2">Run your first scan to see results here</p>
  </div>
{:else}
  <div class="divide-y divide-gray-200">
    {#each history as scan}
      <div class="py-4 first:pt-0">
        <div class="flex justify-between items-start">
          <div>
            <h4 class="font-medium text-gray-900">{scan.scanType === 'quick' ? 'Quick Scan' : 'Full Scan'}</h4>
            <p class="text-sm text-gray-500">{formatDate(scan.completedAt)}</p>
          </div>
          <div class="text-right">
            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium 
              {scan.threatsFound > 0 ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}">
              {scan.threatsFound} {scan.threatsFound === 1 ? 'threat' : 'threats'}
            </span>
            <p class="text-xs text-gray-500 mt-1">Duration: {formatDuration(scan.duration)}</p>
          </div>
        </div>
        
        <div class="mt-2">
          <div class="flex justify-between text-xs">
            <span>Files scanned: {scan.filesScanned.toLocaleString()}</span>
            <span>Items in quarantine: {scan.itemsQuarantined}</span>
          </div>
          
          {#if scan.threatsFound > 0}
            <div class="mt-3 bg-gray-50 rounded p-3">
              <h5 class="text-xs font-bold mb-1">Detected Threats:</h5>
              <ul class="text-xs space-y-1">
                {#each scan.detectedThreats.slice(0, 3) as threat}
                  <li class="flex justify-between">
                    <span class="truncate" title={threat.path}>{threat.path}</span>
                    <span class="ml-2 font-medium text-red-700">{threat.type}</span>
                  </li>
                {/each}
                {#if scan.detectedThreats.length > 3}
                  <li class="text-gray-500 italic">+ {scan.detectedThreats.length - 3} more</li>
                {/if}
              </ul>
            </div>
          {/if}
        </div>
      </div>
    {/each}
  </div>
  
  {#if history.length > 5}
    <div class="mt-4 text-center">
      <a href="/history" class="text-sm text-blue-600 hover:text-blue-800">View full history</a>
    </div>
  {/if}
{/if} 