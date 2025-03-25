<script>
  import { onMount } from 'svelte';
  import { fly } from 'svelte/transition';
  import { quintOut } from 'svelte/easing';
  import Icon from '../../components/Icon.svelte';
  import SearchBar from '../../components/SearchBar.svelte';
  import Button from '../../components/Button.svelte';
  
  // Categories structure
  const categories = [
    {
      id: 'getting-started',
      title: 'Primeros pasos',
      icon: 'rocket',
      description: 'Guías básicas para empezar a usar Amaru Antivirus',
      articles: [
        { id: 'installation', title: 'Instalación y configuración inicial', popular: true },
        { id: 'first-scan', title: 'Tu primer análisis de seguridad' },
        { id: 'interface-overview', title: 'Descripción general de la interfaz' },
        { id: 'system-requirements', title: 'Requisitos del sistema' }
      ]
    },
    {
      id: 'scanning',
      title: 'Análisis y detección',
      icon: 'shield-check',
      description: 'Todo sobre escaneo de malware y configuraciones',
      articles: [
        { id: 'scan-types', title: 'Tipos de análisis disponibles', popular: true },
        { id: 'scheduled-scans', title: 'Configurar análisis programados' },
        { id: 'custom-scans', title: 'Análisis personalizados' },
        { id: 'exclusions', title: 'Configurar exclusiones' }
      ]
    },
    {
      id: 'real-time',
      title: 'Protección en tiempo real',
      icon: 'shield',
      description: 'Protección proactiva contra amenazas',
      articles: [
        { id: 'real-time-overview', title: 'Cómo funciona la protección en tiempo real', popular: true },
        { id: 'shields-config', title: 'Configuración de escudos de protección' },
        { id: 'behavior-monitoring', title: 'Monitoreo de comportamiento' },
        { id: 'ransomware-protection', title: 'Protección contra ransomware' }
      ]
    },
    {
      id: 'updates',
      title: 'Actualizaciones',
      icon: 'refresh-cw',
      description: 'Mantén tu protección al día',
      articles: [
        { id: 'auto-updates', title: 'Configurar actualizaciones automáticas', popular: true },
        { id: 'manual-updates', title: 'Actualizaciones manuales' },
        { id: 'offline-updates', title: 'Actualizar sin conexión a internet' },
        { id: 'update-troubleshooting', title: 'Solución de problemas de actualización' }
      ]
    },
    {
      id: 'quarantine',
      title: 'Cuarentena',
      icon: 'lock',
      description: 'Gestión de archivos potencialmente peligrosos',
      articles: [
        { id: 'quarantine-overview', title: 'Entendiendo la cuarentena' },
        { id: 'manage-quarantined', title: 'Administrar archivos en cuarentena', popular: true },
        { id: 'restore-files', title: 'Restaurar archivos de cuarentena' },
        { id: 'report-false-positive', title: 'Reportar falsos positivos' }
      ]
    },
    {
      id: 'troubleshooting',
      title: 'Solución de problemas',
      icon: 'tool',
      description: 'Resolver problemas comunes',
      articles: [
        { id: 'performance-issues', title: 'Problemas de rendimiento' },
        { id: 'scan-errors', title: 'Errores durante el análisis' },
        { id: 'activation-issues', title: 'Problemas de activación', popular: true },
        { id: 'diagnostic-tools', title: 'Herramientas de diagnóstico' }
      ]
    }
  ];
  
  // State variables
  let searchQuery = '';
  let filteredCategories = [...categories];
  let filteredArticles = [];
  let selectedCategory = null;
  let showAllArticles = false;
  let popularArticles = [];
  let isLoading = true;
  
  // Search functionality
  function handleSearch() {
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
  function selectCategory(categoryId) {
    selectedCategory = categories.find(cat => cat.id === categoryId);
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
  
  // Navigate to article - would link to actual documentation
  function navigateToArticle(articleId, categoryId) {
    console.log(`Navigating to article: ${articleId} in category: ${categoryId}`);
    // Implementation would depend on routing solution
    // For example: router.push(`/help/article/${categoryId}/${articleId}`);
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
      <SearchBar
        bind:value={searchQuery}
        placeholder="Buscar en la ayuda..."
        on:search={handleSearch}
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
            <div 
              class="article-item"
              on:click={() => navigateToArticle(article.id, selectedCategory.id)}
              on:keypress={(e) => e.key === 'Enter' && navigateToArticle(article.id, selectedCategory.id)}
              tabindex="0"
            >
              <div class="article-info">
                <h3>{article.title}</h3>
                <Icon name="chevron-right" />
              </div>
              {#if article.popular}
                <span class="popular-tag">Popular</span>
              {/if}
            </div>
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
            <div 
              class="article-item"
              on:click={() => navigateToArticle(article.id, article.categoryId)}
              on:keypress={(e) => e.key === 'Enter' && navigateToArticle(article.id, article.categoryId)}
              tabindex="0"
            >
              <div class="article-info">
                <h3>{article.title}</h3>
                <span class="category-tag">{article.categoryTitle}</span>
                <Icon name="chevron-right" />
              </div>
              {#if article.popular}
                <span class="popular-tag">Popular</span>
              {/if}
            </div>
          {/each}
        </div>
      </div>
    {:else}
      <!-- Categories grid view (default view) -->
      <div class="categories-grid" transition:fly={{ y: 20, duration: 300, easing: quintOut }}>
        {#each filteredCategories as category}
          <div 
            class="category-card"
            on:click={() => selectCategory(category.id)}
            on:keypress={(e) => e.key === 'Enter' && selectCategory(category.id)}
            tabindex="0"
          >
            <div class="category-icon">
              <Icon name={category.icon} size="large" />
            </div>
            <h2>{category.title}</h2>
            <p>{category.description}</p>
          </div>
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
            <div 
              class="popular-article"
              on:click={() => navigateToArticle(article.id, article.categoryId)}
              on:keypress={(e) => e.key === 'Enter' && navigateToArticle(article.id, article.categoryId)}
              tabindex="0"
            >
              <Icon name="file-text" />
              <div class="article-info">
                <span>{article.title}</span>
                <small>{article.categoryTitle}</small>
              </div>
              <Icon name="chevron-right" size="small" />
            </div>
          {/each}
        </div>
      </div>
      
      <!-- Contact support section -->
      <div class="support-section">
        <h2>¿No encuentras lo que buscas?</h2>
        <p>Nuestro equipo de soporte está listo para ayudarte</p>
        <div class="support-buttons">
          <Button variant="primary" icon="message-circle">Contactar Soporte</Button>
          <Button variant="outline" icon="mail">Enviar Email</Button>
        </div>
      </div>
    {/if}
  {/if}
</div>

<style>
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
  
  .category-card h2 {
    margin: 1rem 0 0.5rem;
    font-size: 1.3rem;
    color: var(--heading-color);
  }
  
  .category-card p {
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