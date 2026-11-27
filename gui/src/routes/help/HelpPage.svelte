<script lang="ts">
  import { onMount } from 'svelte';
  import { fly } from 'svelte/transition';
  import { quintOut } from 'svelte/easing';
  import Icon from '../../lib/components/Icon.svelte';
  import Button from '../../lib/components/Button.svelte';
  
  // Categories structure
  const guideBase = "https://github.com/CripterHack/Amaru/blob/main/docs/user-guides/";
  const categories = [
    {
      id: 'getting-started',
      title: 'Primeros pasos',
      icon: 'rocket',
      description: 'Guías básicas para empezar a usar Amaru Antivirus',
      articles: [
        { id: 'installation', page: 'getting-started.md#instalación', title: 'Instalación y configuración inicial', popular: true },
        { id: 'first-scan', page: 'getting-started.md#realizar-un-primer-escaneo', title: 'Tu primer análisis de seguridad' },
        { id: 'interface-overview', page: 'getting-started.md', title: 'Descripción general de la interfaz' },
        { id: 'system-requirements', page: 'getting-started.md#requisitos-del-sistema', title: 'Requisitos del sistema' }
      ]
    },
    {
      id: 'scanning',
      title: 'Análisis y detección',
      icon: 'shield-check',
      description: 'Todo sobre escaneo de malware y configuraciones',
      articles: [
        { id: 'scan-types', page: 'analyzing.md#tipos-de-análisis', title: 'Tipos de análisis disponibles', popular: true },
        { id: 'scheduled-scans', page: 'analyzing.md#análisis-programados', title: 'Configurar análisis programados' },
        { id: 'custom-scans', page: 'analyzing.md#análisis-personalizado', title: 'Análisis personalizados' },
        { id: 'exclusions', page: 'realtime-protection.md#exclusiones', title: 'Configurar exclusiones' }
      ]
    },
    {
      id: 'real-time',
      title: 'Protección en tiempo real',
      icon: 'shield',
      description: 'Protección proactiva contra amenazas',
      articles: [
        { id: 'real-time-overview', page: 'realtime-protection.md#componentes-de-protección', title: 'Cómo funciona la protección en tiempo real', popular: true },
        { id: 'shields-config', page: 'realtime-protection.md#configuración-de-la-protección', title: 'Configuración de escudos de protección' },
        { id: 'behavior-monitoring', page: 'realtime-protection.md#componentes-de-protección', title: 'Monitoreo de comportamiento' },
        { id: 'ransomware-protection', page: 'faq.md#amaru-protege-contra-ransomware', title: 'Protección contra ransomware' }
      ]
    },
    {
      id: 'updates',
      title: 'Actualizaciones',
      icon: 'refresh-cw',
      description: 'Mantén tu protección al día',
      articles: [
        { id: 'auto-updates', page: 'updates.md#actualizaciones-automáticas', title: 'Configurar actualizaciones automáticas', popular: true },
        { id: 'manual-updates', page: 'updates.md#actualizaciones-manuales', title: 'Actualizaciones manuales' },
        { id: 'offline-updates', page: 'updates.md#descarga-offline', title: 'Actualizar sin conexión a internet' },
        { id: 'update-troubleshooting', page: 'updates.md#solución-de-problemas', title: 'Solución de problemas de actualización' }
      ]
    },
    {
      id: 'quarantine',
      title: 'Cuarentena',
      icon: 'lock',
      description: 'Gestión de archivos potencialmente peligrosos',
      articles: [
        { id: 'quarantine-overview', page: 'quarantine.md', title: 'Entendiendo la cuarentena' },
        { id: 'manage-quarantined', page: 'quarantine.md', title: 'Administrar archivos en cuarentena', popular: true },
        { id: 'restore-files', page: 'quarantine.md#restaurar', title: 'Restaurar archivos de cuarentena' },
        { id: 'report-false-positive', page: 'quarantine.md#cómo-gestiono-un-falso-positivo', title: 'Reportar falsos positivos' }
      ]
    },
    {
      id: 'troubleshooting',
      title: 'Solución de problemas',
      icon: 'wrench',
      description: 'Resolver problemas comunes',
      articles: [
        { id: 'performance-issues', page: 'faq.md#rendimiento', title: 'Problemas de rendimiento' },
        { id: 'scan-errors', page: 'getting-started.md#solución-de-problemas-comunes', title: 'Errores durante el análisis' },
        { id: 'activation-issues', page: 'faq.md#instalación-y-activación', title: 'Problemas de activación', popular: true },
        { id: 'diagnostic-tools', page: '../support/contact.md#diagnóstico-y-herramientas', title: 'Herramientas de diagnóstico' }
      ]
    }
  ];
  
  // State variables
  type Category = (typeof categories)[number];
  type ArticleResult = Category['articles'][number] & { categoryId: string; categoryTitle: string };
  let searchQuery = '';
  let filteredCategories = [...categories];
  let filteredArticles: ArticleResult[] = [];
  let selectedCategory: Category | null = null;
  let showAllArticles = false;
  let popularArticles: ArticleResult[] = [];
  let isLoading = true;
  
  // Search functionality
  function handleSearch(queryText: string) {
    searchQuery = queryText;
    selectedCategory = null;
    // Reset view when clearing search
    if (!searchQuery) {
      filteredCategories = [...categories];
      filteredArticles = [];
      showAllArticles = false;
      return;
    }
    
    // Enable all articles view with search
    showAllArticles = true;
    
    // Search in all articles across categories
    filteredArticles = categories.flatMap(category => 
      category.articles
        .filter(article => 
          article.title.toLowerCase().includes(searchQuery.toLowerCase())
        )
        .map(article => ({
          ...article,
          categoryId: category.id,
          categoryTitle: category.title
        }))
    );
    
    // Also filter categories for broader matches
    filteredCategories = categories.filter(category => 
      category.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      category.description.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }
  
  // Select category
  function selectCategory(categoryId: string) {
    selectedCategory = categories.find(cat => cat.id === categoryId) ?? null;
    searchQuery = '';
    filteredArticles = [];
    showAllArticles = false;
  }
  
  // Back to categories
  function backToCategories() {
    selectedCategory = null;
    searchQuery = '';
    filteredArticles = [];
    showAllArticles = false;
  }
  
  // Show all articles
  function toggleAllArticles() {
    showAllArticles = !showAllArticles;
    if (showAllArticles) {
      filteredArticles = categories.flatMap(category => 
        category.articles.map(article => ({
          ...article,
          categoryId: category.id,
          categoryTitle: category.title
        }))
      );
    } else {
      filteredArticles = [];
    }
  }
  
  
  // Initialize component
  onMount(() => {
    // Populate popular articles on load
    popularArticles = categories
      .flatMap(category => 
        category.articles
          .filter(article => article.popular)
          .map(article => ({
            ...article,
            categoryId: category.id,
            categoryTitle: category.title
          }))
      )
      .slice(0, 5); // Limit to top 5
      
    isLoading = false;
  });
</script>

<div class="help-container">
  <div class="help-header">
    <h1>Centro de Ayuda</h1>
    <p>Encuentra respuestas a tus preguntas sobre Amaru Antivirus</p>
    
    <div class="search-container">
      <input
        type="search"
        class="help-search"
        aria-label="Buscar en la ayuda"
        placeholder="Buscar en la ayuda..."
        value={searchQuery}
        on:input={(event) => handleSearch(event.currentTarget.value)}
      />
    </div>
  </div>
  
  {#if isLoading}
    <div class="loading">
      <div class="spinner"></div>
      <p>Cargando recursos de ayuda...</p>
    </div>
  {:else}
    {#if selectedCategory}
      <!-- Category detail view -->
      <div class="category-view" transition:fly={{ y: 20, duration: 300, easing: quintOut }}>
        <div class="category-header">
          <Button 
            variant="text" 
            icon="arrow-left" 
            on:click={backToCategories}
          >
            Volver a categorías
          </Button>
          
          <h2>
            <Icon name={selectedCategory.icon} />
            {selectedCategory.title}
          </h2>
          <p>{selectedCategory.description}</p>
        </div>
        
        <div class="articles-list">
          {#each selectedCategory.articles as article}
            <a href={guideBase + article.page} target="_blank" rel="noreferrer" class="article-item">
              <div class="article-info">
                <h3>{article.title}</h3>
                <Icon name="chevron-right" />
              </div>
              {#if article.popular}
                <span class="popular-tag">Popular</span>
              {/if}
            </a>
          {/each}
        </div>
      </div>
    {:else if showAllArticles || filteredArticles.length > 0}
      <!-- Search results or all articles view -->
      <div class="search-results" transition:fly={{ y: 20, duration: 300, easing: quintOut }}>
        
        <div class="results-header">
          {#if searchQuery}
            <h2>Resultados para "{searchQuery}"</h2>
            {#if filteredArticles.length === 0}
              <p>No se encontraron resultados. Intenta con otros términos.</p>
            {:else}
              <p>Se encontraron {filteredArticles.length} artículos</p>
            {/if}
          {:else}
            <h2>Todos los artículos</h2>
          {/if}
          
          <Button 
            variant="text" 
            icon="arrow-left" 
            on:click={backToCategories}
          >
            Volver a categorías
          </Button>
        </div>
        
        <div class="articles-list">
          {#each filteredArticles as article}
            <a href={guideBase + article.page} target="_blank" rel="noreferrer" class="article-item">
              <div class="article-info">
                <h3>{article.title}</h3>
                <span class="category-tag">{article.categoryTitle}</span>
                <Icon name="chevron-right" />
              </div>
              {#if article.popular}
                <span class="popular-tag">Popular</span>
              {/if}
            </a>
          {/each}
        </div>
      </div>
    {:else}
      <!-- Categories grid view (default view) -->
      <div class="categories-grid" transition:fly={{ y: 20, duration: 300, easing: quintOut }}>
        {#each filteredCategories as category}
          <button type="button" on:click={() => selectCategory(category.id)} class="category-card">
            <span class="category-icon">
              <Icon name={category.icon} size={32} />
            </span>
            <span class="category-title">{category.title}</span>
            <span class="category-description">{category.description}</span>
          </button>
        {/each}
      </div>
      
      <!-- Popular articles section -->
      <div class="popular-section" transition:fly={{ y: 20, duration: 300, easing: quintOut }}>
        <div class="popular-header">
          <h2>Artículos populares</h2>
          <Button 
            variant="text" 
            on:click={toggleAllArticles}
          >
            Ver todos los artículos
          </Button>
        </div>
          
        <div class="popular-articles">
          {#each popularArticles as article}
            <a href={guideBase + article.page} target="_blank" rel="noreferrer" class="popular-article">
              <Icon name="file-text" />
              <div class="article-info">
                <span>{article.title}</span>
                <small>{article.categoryTitle}</small>
              </div>
              <Icon name="chevron-right" size={16} />
            </a>
          {/each}
        </div>
      </div>
      
      <!-- Contact support section -->
      <div class="support-section">
        <h2>¿No encuentras lo que buscas?</h2>
        <p>Consulta los problemas conocidos o informa de uno nuevo.</p>
        <div class="support-buttons">
          <a href="https://github.com/CripterHack/Amaru/issues" target="_blank" rel="noreferrer">Consultar los issues</a>
        </div>
      </div>
    {/if}
  {/if}
</div>

<style>
  .help-search {
    width: 100%;
    padding: 0.65rem 1rem;
    border: 1px solid currentColor;
    border-radius: 0.5rem;
    background: transparent;
    color: inherit;
  }

  .help-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
    color: var(--text-color);
  }
  
  .help-header {
    text-align: center;
    margin-bottom: 3rem;
  }
  
  .help-header h1 {
    font-size: 2.5rem;
    margin-bottom: 0.5rem;
    color: var(--primary-color);
  }
  
  .help-header p {
    font-size: 1.2rem;
    margin-bottom: 2rem;
    color: var(--text-secondary);
  }
  
  .search-container {
    max-width: 600px;
    margin: 0 auto;
  }
  
  .categories-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 1.5rem;
    margin-bottom: 3rem;
  }
  
  .category-card {
    background: var(--card-bg);
    border-radius: 10px;
    padding: 1.5rem;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.05);
    transition: transform 0.2s, box-shadow 0.2s;
    cursor: pointer;
  }
  
  .category-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1);
  }
  
  .category-title {
    display: block;
    margin: 1rem 0 0.5rem;
    font-size: 1.3rem;
    color: var(--heading-color);
  }
  
  .category-description {
    display: block;
    color: var(--text-secondary);
    font-size: 0.95rem;
    margin: 0;
  }
  
  .category-icon {
    color: var(--primary-color);
    font-size: 1.8rem;
    height: 50px;
    display: flex;
    align-items: center;
  }
  
  .popular-section {
    margin-bottom: 3rem;
  }
  
  .popular-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
  }
  
  .popular-header h2 {
    font-size: 1.5rem;
    color: var(--heading-color);
    margin: 0;
  }
  
  .popular-articles {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 1rem;
  }
  
  .popular-article {
    display: flex;
    align-items: center;
    padding: 1rem;
    background: var(--card-bg);
    border-radius: 8px;
    cursor: pointer;
    transition: background 0.2s;
  }
  
  .popular-article:hover {
    background: var(--card-hover-bg);
  }
  
  .popular-article .article-info {
    flex: 1;
    margin: 0 1rem;
  }
  
  .popular-article .article-info span {
    display: block;
    font-weight: 500;
  }
  
  .popular-article .article-info small {
    color: var(--text-secondary);
    font-size: 0.8rem;
  }
  
  .support-section {
    text-align: center;
    padding: 2rem;
    background: var(--card-bg);
    border-radius: 10px;
    margin-top: 2rem;
  }
  
  .support-section h2 {
    margin-top: 0;
    color: var(--heading-color);
  }
  
  .support-section p {
    color: var(--text-secondary);
    margin-bottom: 1.5rem;
  }
  
  .support-buttons {
    display: flex;
    justify-content: center;
    gap: 1rem;
    flex-wrap: wrap;
  }
  
  .category-view {
    margin-bottom: 2rem;
  }
  
  .category-header {
    margin-bottom: 2rem;
  }
  
  .category-header h2 {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 1.8rem;
    margin: 1rem 0 0.5rem;
    color: var(--heading-color);
  }
  
  .articles-list {
    display: flex;
    flex-direction: column;
    gap: 0.8rem;
  }
  
  .article-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 1.2rem;
    background: var(--card-bg);
    border-radius: 8px;
    cursor: pointer;
    transition: background 0.2s;
  }
  
  .article-item:hover {
    background: var(--card-hover-bg);
  }
  
  .article-item .article-info {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex: 1;
  }
  
  .article-item h3 {
    margin: 0;
    font-size: 1.1rem;
    font-weight: 500;
  }
  
  .category-tag {
    font-size: 0.8rem;
    background: var(--tag-bg);
    color: var(--tag-color);
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    margin-left: 0.5rem;
  }
  
  .popular-tag {
    font-size: 0.75rem;
    background: var(--primary-light);
    color: var(--primary-color);
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    white-space: nowrap;
  }
  
  .search-results {
    margin-bottom: 2rem;
  }
  
  .results-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
  }
  
  .results-header h2 {
    font-size: 1.5rem;
    margin: 0;
    color: var(--heading-color);
  }
  
  .loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 3rem;
  }
  
  .spinner {
    border: 4px solid rgba(0, 0, 0, 0.1);
    border-left-color: var(--primary-color);
    border-radius: 50%;
    width: 40px;
    height: 40px;
    animation: spin 1s linear infinite;
    margin-bottom: 1rem;
  }
  
  @keyframes spin {
    to { transform: rotate(360deg); }
  }
  
  /* Responsive adjustments */
  @media (max-width: 768px) {
    .help-container {
      padding: 1rem;
    }
    
    .categories-grid {
      grid-template-columns: 1fr;
    }
    
    .popular-articles {
      grid-template-columns: 1fr;
    }
    
    .support-buttons {
      flex-direction: column;
    }
  }
</style> 