<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  
  export let size: number = 100;
  export let color: string = '#4f46e5';  // Indigo-600
  export let duration: number = 2000;
  export let animate: boolean = true;
  
  let canvas: HTMLCanvasElement;
  let ctx: CanvasRenderingContext2D;
  let animationId: number;
  let particles: Array<{
    x: number;
    y: number;
    size: number;
    speed: number;
    color: string;
    alpha: number;
  }> = [];
  
  // Inicializar canvas y animación
  onMount(() => {
    if (!canvas) return;
    
    ctx = canvas.getContext('2d')!;
    
    // Configurar para pantallas de alta resolución
    const dpr = window.devicePixelRatio || 1;
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    ctx.scale(dpr, dpr);
    
    // Generar partículas iniciales
    createParticles();
    
    // Iniciar animación si está habilitada
    if (animate) {
      startAnimation();
    }
    
    return () => {
      stopAnimation();
    };
  });
  
  // Crear partículas para la animación
  function createParticles() {
    particles = [];
    const particleCount = 30;
    
    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: Math.random() * size,
        y: Math.random() * size,
        size: Math.random() * 3 + 1,
        speed: Math.random() * 1 + 0.5,
        color,
        alpha: Math.random() * 0.6 + 0.2
      });
    }
  }
  
  // Iniciar animación
  function startAnimation() {
    if (!ctx) return;
    
    const animate = () => {
      ctx.clearRect(0, 0, size, size);
      
      // Dibujar círculo de escaneo
      const time = Date.now() % duration / duration;
      const radius = (size / 2) * 0.8;
      
      // Dibujar círculo exterior
      ctx.beginPath();
      ctx.arc(size / 2, size / 2, radius, 0, Math.PI * 2);
      ctx.strokeStyle = color;
      ctx.globalAlpha = 0.2;
      ctx.lineWidth = 2;
      ctx.stroke();
      
      // Dibujar línea giratoria
      ctx.beginPath();
      const startAngle = time * Math.PI * 2;
      const endAngle = startAngle + Math.PI / 4;
      ctx.arc(size / 2, size / 2, radius, startAngle, endAngle);
      ctx.strokeStyle = color;
      ctx.globalAlpha = 1;
      ctx.lineWidth = 3;
      ctx.stroke();
      
      // Actualizar y dibujar partículas
      particles.forEach(particle => {
        // Mover en círculo
        const angle = time * Math.PI * 2;
        particle.x = (size / 2) + Math.cos(angle + particle.speed) * (radius * particle.speed);
        particle.y = (size / 2) + Math.sin(angle + particle.speed) * (radius * particle.speed);
        
        // Dibujar partícula
        ctx.beginPath();
        ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
        ctx.fillStyle = particle.color;
        ctx.globalAlpha = particle.alpha;
        ctx.fill();
      });
      
      animationId = requestAnimationFrame(animate);
    };
    
    animate();
  }
  
  // Detener animación
  function stopAnimation() {
    if (animationId) {
      cancelAnimationFrame(animationId);
    }
  }
  
  // Reiniciar animación cuando cambien propiedades
  $: if (canvas && ctx) {
    stopAnimation();
    if (animate) {
      startAnimation();
    }
  }
</script>

<canvas 
  bind:this={canvas} 
  width={size} 
  height={size} 
  style="width: {size}px; height: {size}px;"
  class="scan-animation"
></canvas>

<style>
  .scan-animation {
    display: block;
  }
</style> 