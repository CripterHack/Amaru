<script>
  import { formatDate } from '$lib/utils';
  import { AlertTriangle, File, Shield, Trash2, Archive } from 'lucide-svelte';
  
  export let threat = {};
  
  const getThreatColor = (level) => {
    switch (level) {
      case 'critical':
        return 'bg-red-100 text-red-800';
      case 'high':
        return 'bg-orange-100 text-orange-800';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800';
      case 'low':
        return 'bg-blue-100 text-blue-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };
  
  async function deleteFromQuarantine() {
    try {
      await window.invoke('delete_quarantined_file', { id: threat.id });
    } catch (error) {
      console.error('Failed to delete from quarantine:', error);
    }
  }
  
  async function restoreFromQuarantine() {
    try {
      await window.invoke('restore_quarantined_file', { id: threat.id });
    } catch (error) {
      console.error('Failed to restore from quarantine:', error);
    }
  }
</script>

<div class="bg-white border border-gray-100 rounded-lg shadow-sm p-4 hover:shadow-md transition-shadow duration-200">
  <div class="flex items-start">
    <div class="flex-shrink-0 mt-1">
      <span class="inline-flex items-center justify-center h-8 w-8 rounded-full bg-red-100 text-red-500">
        <AlertTriangle size={16} />
      </span>
    </div>
    
    <div class="ml-3 flex-1">
      <div class="flex justify-between">
        <div>
          <h3 class="text-sm font-medium text-gray-900">{threat.name}</h3>
          <p class="text-xs text-gray-500 truncate" title={threat.path}>{threat.path}</p>
        </div>
        
        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {getThreatColor(threat.riskLevel)}">
          {threat.riskLevel}
        </span>
      </div>
      
      <div class="mt-2">
        <p class="text-xs text-gray-600">{threat.description}</p>
        
        <div class="mt-2 flex justify-between items-center">
          <span class="text-xs text-gray-500">Detected: {formatDate(threat.detectedAt)}</span>
          
          {#if threat.inQuarantine}
            <div class="flex space-x-2">
              <button 
                on:click={restoreFromQuarantine}
                class="inline-flex items-center text-xs px-2 py-1 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded"
              >
                <Archive size={12} class="mr-1" />
                Restore
              </button>
              
              <button 
                on:click={deleteFromQuarantine}
                class="inline-flex items-center text-xs px-2 py-1 bg-red-100 hover:bg-red-200 text-red-700 rounded"
              >
                <Trash2 size={12} class="mr-1" />
                Delete
              </button>
            </div>
          {:else}
            <div>
              <span class="inline-flex items-center text-xs px-2 py-1 bg-orange-100 text-orange-800 rounded">
                <Shield size={12} class="mr-1" />
                {threat.action || 'Blocked'}
              </span>
            </div>
          {/if}
        </div>
      </div>
    </div>
  </div>
</div> 