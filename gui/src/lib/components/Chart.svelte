<script lang="ts">
  import { onMount } from 'svelte';
  import { Chart as ChartJS, registerables } from 'chart.js';
  
  // Register all Chart.js components
  ChartJS.register(...registerables);
  
  export let data = [];
  export let type: 'bar' | 'pie' | 'line' = 'bar';
  export let labelKey = 'label';
  export let valueKey = 'value';
  export let height = '200px';
  
  let chartElement: HTMLCanvasElement;
  let chart: ChartJS;
  
  // Generate random colors for the chart
  function generateColors(count: number) {
    const colors = [];
    for (let i = 0; i < count; i++) {
      // Generate pastel colors
      const hue = (i * 137) % 360; // Use golden angle to distribute colors
      colors.push(`hsl(${hue}, 70%, 65%)`);
    }
    return colors;
  }
  
  // Create chart based on provided data
  function createChart() {
    if (!chartElement || !data || data.length === 0) return;
    
    const ctx = chartElement.getContext('2d');
    if (!ctx) return;
    
    // Extract labels and values from data
    const labels = data.map(item => item[labelKey]);
    const values = data.map(item => item[valueKey]);
    const colors = generateColors(data.length);
    
    // Destroy previous chart instance if it exists
    if (chart) {
      chart.destroy();
    }
    
    // Create new chart
    chart = new ChartJS(ctx, {
      type,
      data: {
        labels,
        datasets: [{
          label: type === 'pie' ? '' : 'Count',
          data: values,
          backgroundColor: colors,
          borderColor: colors.map(color => color.replace('65%', '55%')),
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            display: type === 'pie'
          },
          tooltip: {
            enabled: true
          }
        },
        scales: type === 'pie' ? undefined : {
          y: {
            beginAtZero: true
          }
        }
      }
    });
  }
  
  // Update chart when data changes
  $: if (data && chartElement) {
    createChart();
  }
  
  onMount(() => {
    createChart();
  });
</script>

<div style="height: {height};">
  <canvas bind:this={chartElement}></canvas>
</div> 