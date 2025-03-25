<script>
  import { onMount } from 'svelte';
  import { fly } from 'svelte/transition';
  import { quintOut } from 'svelte/easing';
  import Icon from '../../components/Icon.svelte';
  import SearchBar from '../../components/SearchBar.svelte';
  import Button from '../../components/Button.svelte';
  
  // Lista de categorías de ayuda
  const categories = [
    { 
      id: 'getting-started',
      title: 'Primeros Pasos',
      icon: 'rocket-launch',
      articles: [
        { id: 'installation', title: 'Instalación y Activación', views: 2453 },
        { id: 'quick-start', title: 'Guía de Inicio Rápido', views: 1876 },
        { id: 'system-requirements', title: 'Requisitos del Sistema', views: 934 },
        { id: 'interface-overview', title: 'Vista General de la Interfaz', views: 762 }
      ]
    },
    { 
      id: 'protection',
      title: 'Protección',
      icon: 'shield-check',
      articles: [
        { id: 'real-time-protection', title: 'Protección en Tiempo Real', views: 3245 },
        { id: 'scanning', title: 'Tipos de Escaneo', views: 2876 },
        { id: 'quarantine', title: 'Uso de la Cuarentena', views: 1932 },
        { id: 'web-protection', title: 'Protección Web', views: 1128 },
        { id: 'ransomware-protection', title: 'Protección contra Ransomware', views: 1543 }
      ]
    },
    { 
      id: 'configuration',
      title: 'Configuración',
      icon: 'cog',
      articles: [
        { id: 'settings-overview', title: 'Vista General de Configuración', views: 1532 },
        { id: 'exclusions', title: 'Configurar Exclusiones', views: 2145 },
        { id: 'scheduled-scans', title: 'Escaneos Programados', views: 1432 },
        { id: 'notifications', title: 'Configurar Notificaciones', views: 965 },
        { id: 'performance', title: 'Optimización de Rendimiento', views: 1876 }
      ]
    },
    { 
      id: 'troubleshooting',
      title: 'Solución de Problemas',
      icon: 'wrench',
      articles: [
        { id: 'common-issues', title: 'Problemas Comunes', views: 3421 },
        { id: 'false-positives', title: 'Gestión de Falsos Positivos', views: 2876 },
        { id: 'crash-recovery', title: 'Recuperación tras Fallos', views: 1243 },
        { id: 'performance-issues', title: 'Problemas de Rendimiento', views: 1987 }
      ]
    },
    { 
      id: 'updates',
      title: 'Actualizaciones',
      icon: 'refresh-cw',
      articles: [
        { id: 'update-virus-db', title: 'Actualizar Base de Datos de Virus', views: 1876 },
        { id: 'auto-updates', title: 'Actualizaciones Automáticas', views: 1324 },
        { id: 'manual-updates', title: 'Actualización Manual', views: 854 },
        { id: 'update-history', title: 'Historial de Actualizaciones', views: 643 }
      ]
    },
    { 
      id: 'licensing',
      title: 'Licencias',
      icon: 'key',
      articles: [
        { id: 'activate-license', title: 'Activar Licencia', views: 2543 },
        { id: 'license-types', title: 'Tipos de Licencia', views: 1435 },
        { id: 'license-renewal', title: 'Renovación de Licencia', views: 1876 },
        { id: 'transfer-license', title: 'Transferir Licencia', views: 954 }
      ]
    }
  ];
  
  // Estado del componente
  let searchQuery = '';
  let filteredCategories = [...categories];
  let filteredArticles = [];
  let selectedCategory = null;
  let showAllArticles = false;
  let popularArticles = [];
  let isLoading = true;
  
  // Buscar en artículos
  function handleSearch() {
    if (!searchQuery.trim()) {
      filteredCategories = [...categories];
      filteredArticles = [];
      return;
    }
    
    const query = searchQuery.toLowerCase();
    
    // Filtrar artículos que coincidan con la búsqueda
    filteredArticles = categories.flatMap(category => 
      category.articles.filter(article => 
        article.title.toLowerCase().includes(query)
      ).map(article => ({
        ...article,
        category: category.title,
        categoryId: category.id,
        categoryIcon: category.icon
      }))
    );
    
    // Filtrar categorías que coincidan con la búsqueda
    filteredCategories = categories.filter(category => 
      category.title.toLowerCase().includes(query) ||
      category.articles.some(article => article.title.toLowerCase().includes(query))
    );
  }
  
  // Seleccionar categoría
  function selectCategory(categoryId) {
    selectedCategory = categories.find(cat => cat.id === categoryId);
    searchQuery = '';
    filteredArticles = [];
  }
  
  // Mostrar todos los artículos
  function toggleAllArticles() {
    showAllArticles = !showAllArticles;
    if (showAllArticles) {
      filteredArticles = categories.flatMap(category => 
        category.articles.map(article => ({
          ...article,
          category: category.title,
          categoryId: category.id,
          categoryIcon: category.icon
        }))
      ).sort((a, b) => b.views - a.views);
    } else {
      filteredArticles = [];
    }
  }
  
  // Navegar a artículo
  function navigateToArticle(articleId, categoryId) {
    console.log(`Navigating to article: ${articleId} in category: ${categoryId}`);
    // Aquí implementarías la navegación real
  }
  
  // Al montar el componente
  onMount(() => {
    // Simulamos una carga de datos
    setTimeout(() => {
      // Obtener artículos populares (los más vistos)
      popularArticles = categories.flatMap(category => 
        category.articles.map(article => ({
          ...article,
          category: category.title,
          categoryId: category.id,
          categoryIcon: category.icon
        }))
      ).sort((a, b) => b.views - a.views).slice(0, 5);
      
      isLoading = false;
    }, 500);
  });
</script>

<div class="help-center">
  <header>
    <h1>Centro de Ayuda</h1>
    <p>Encuentra respuestas a tus preguntas y aprende cómo aprovechar al máximo Amaru Antivirus</p>
    
    <div class="search-container">
      <SearchBar 
        bind:value={searchQuery} 
        on:input={handleSearch}
        placeholder="Buscar en la ayuda..."
        fullWidth={true}
      />
    </div>
  </header>
  
  {#if isLoading}
    <div class="loading-state">
      <Icon name="loader" size="2rem" spin={true} />
      <p>Cargando recursos de ayuda...</p>
    </div>
  {:else}
    {#if selectedCategory}
      <!-- Vista de categoría seleccionada -->
      <div class="category-view" transition:fly={{ y: 20, duration: 300, easing: quintOut }}>
        <div class="category-header">
          <button class="back-button" on:click={() => selectedCategory = null}>
            <Icon name="arrow-left" />
            <span>Volver</span>
          </button>
          
          <h2>
            <Icon name={selectedCategory.icon} />
            {selectedCategory.title}
          </h2>
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
                <span class="views">{article.views} visualizaciones</span>
              </div>
              <Icon name="chevron-right" />
            </div>
          {/each}
        </div>
      </div>
    {:else if filteredArticles.length > 0}
      <!-- Resultados de búsqueda -->
      <div class="search-results" transition:fly={{ y: 20, duration: 300, easing: quintOut }}>
        <h2>
          {#if showAllArticles}
            Todos los artículos
          {:else}
            Resultados para "{searchQuery}"
          {/if}
        </h2>
        
        <div class="articles-list">
          {#each filteredArticles as article}
            <div 
              class="article-item"
              on:click={() => navigateToArticle(article.id, article.categoryId)}
              on:keypress={(e) => e.key === 'Enter' && navigateToArticle(article.id, article.categoryId)}
              tabindex="0"
            >
              <div class="category-badge">
                <Icon name={article.categoryIcon} size="0.8rem" />
                <span>{article.category}</span>
              </div>
              <div class="article-info">
                <h3>{article.title}</h3>
                <span class="views">{article.views} visualizaciones</span>
              </div>
              <Icon name="chevron-right" />
            </div>
          {/each}
        </div>
      </div>
    {:else}
      <!-- Vista principal con categorías -->
      <div class="help-main" transition:fly={{ y: 20, duration: 300, easing: quintOut }}>
        <section class="categories-section">
          <div class="section-header">
            <h2>Categorías</h2>
            <button class="text-button" on:click={toggleAllArticles}>
              Ver todos los artículos
            </button>
          </div>
          
          <div class="categories-grid">
            {#each filteredCategories as category}
              <div 
                class="category-card"
                on:click={() => selectCategory(category.id)}
                on:keypress={(e) => e.key === 'Enter' && selectCategory(category.id)}
                tabindex="0"
              >
                <div class="category-icon">
                  <Icon name={category.icon} size="1.8rem" />
                </div>
                <h3>{category.title}</h3>
                <p>{category.articles.length} artículos</p>
              </div>
            {/each}
          </div>
        </section>
        
        <section class="popular-section">
          <h2>Artículos Populares</h2>
          
          <div class="popular-articles">
            {#each popularArticles as article}
              <div 
                class="popular-article"
                on:click={() => navigateToArticle(article.id, article.categoryId)}
                on:keypress={(e) => e.key === 'Enter' && navigateToArticle(article.id, article.categoryId)}
                tabindex="0"
              >
                <div class="article-info">
                  <div class="category-badge">
                    <Icon name={article.categoryIcon} size="0.8rem" />
                    <span>{article.category}</span>
                  </div>
                  <h3>{article.title}</h3>
                </div>
                <Icon name="chevron-right" />
              </div>
            {/each}
          </div>
        </section>
        
        <section class="support-section">
          <h2>¿Necesitas más ayuda?</h2>
          
          <div class="support-options">
            <div class="support-card">
              <Icon name="message-circle" size="2rem" />
              <h3>Contactar Soporte</h3>
              <p>Nuestro equipo está listo para ayudarte con cualquier problema</p>
              <Button variant="secondary">Contactar Ahora</Button>
            </div>
            
            <div class="support-card">
              <Icon name="users" size="2rem" />
              <h3>Comunidad</h3>
              <p>Conecta con otros usuarios y encuentra soluciones compartidas</p>
              <Button variant="secondary">Visitar Foros</Button>
            </div>
            
            <div class="support-card">
              <Icon name="video" size="2rem" />
              <h3>Video Tutoriales</h3>
              <p>Aprende a usar todas las funciones con nuestros videos</p>
              <Button variant="secondary">Ver Videos</Button>
            </div>
          </div>
        </section>
      </div>
    {/if}
  {/if}
</div>

<style>
  .help-center {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
    color: var(--text-color);
  }
  
  header {
    text-align: center;
    margin-bottom: 3rem;
  }
  
  header h1 {
    font-size: 2.5rem;
    margin-bottom: 0.5rem;
    color: var(--primary-color);
  }
  
  header p {
    font-size: 1.1rem;
    color: var(--text-secondary);
    margin-bottom: 2rem;
  }
  
  .search-container {
    max-width: 700px;
    margin: 0 auto;
  }
  
  .loading-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 300px;
    color: var(--text-secondary);
  }
  
  .loading-state p {
    margin-top: 1rem;
  }
  
  /* Estilos para la vista principal */
  .section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
  }
  
  .section-header h2 {
    font-size: 1.5rem;
    color: var(--text-color);
  }
  
  .text-button {
    background: none;
    border: none;
    color: var(--primary-color);
    cursor: pointer;
    font-size: 0.9rem;
    padding: 0.5rem;
    transition: color 0.2s;
  }
  
  .text-button:hover {
    color: var(--primary-dark);
    text-decoration: underline;
  }
  
  .categories-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 1.5rem;
    margin-bottom: 3rem;
  }
  
  .category-card {
    background-color: var(--surface-color);
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
    transition: transform 0.2s, box-shadow 0.2s;
    cursor: pointer;
    border: 1px solid var(--border-color);
  }
  
  .category-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 8px 15px rgba(0, 0, 0, 0.1);
  }
  
  .category-icon {
    background-color: var(--primary-light);
    color: var(--primary-color);
    width: 50px;
    height: 50px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 1rem;
  }
  
  .category-card h3 {
    font-size: 1.2rem;
    margin-bottom: 0.5rem;
  }
  
  .category-card p {
    color: var(--text-secondary);
    font-size: 0.9rem;
  }
  
  /* Artículos populares */
  .popular-section {
    margin-bottom: 3rem;
  }
  
  .popular-section h2 {
    font-size: 1.5rem;
    margin-bottom: 1.5rem;
  }
  
  .popular-articles {
    background-color: var(--surface-color);
    border-radius: 12px;
    border: 1px solid var(--border-color);
    overflow: hidden;
  }
  
  .popular-article {
    padding: 1.2rem 1.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
    transition: background-color 0.2s;
    border-bottom: 1px solid var(--border-color);
  }
  
  .popular-article:last-child {
    border-bottom: none;
  }
  
  .popular-article:hover {
    background-color: var(--hover-color);
  }
  
  .category-badge {
    display: inline-flex;
    align-items: center;
    background-color: var(--primary-light);
    color: var(--primary-color);
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.8rem;
    margin-bottom: 0.5rem;
  }
  
  .category-badge span {
    margin-left: 0.25rem;
  }
  
  .popular-article h3 {
    font-size: 1.1rem;
    margin: 0;
  }
  
  /* Sección de soporte */
  .support-section h2 {
    font-size: 1.5rem;
    margin-bottom: 1.5rem;
  }
  
  .support-options {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 1.5rem;
  }
  
  .support-card {
    background-color: var(--surface-color);
    border-radius: 12px;
    padding: 1.5rem;
    text-align: center;
    border: 1px solid var(--border-color);
    transition: transform 0.2s;
  }
  
  .support-card:hover {
    transform: translateY(-5px);
  }
  
  .support-card h3 {
    margin: 1rem 0 0.5rem;
  }
  
  .support-card p {
    color: var(--text-secondary);
    margin-bottom: 1.5rem;
    font-size: 0.95rem;
  }
  
  .support-card :global(svg) {
    color: var(--primary-color);
  }
  
  /* Vista de categoría */
  .category-header {
    display: flex;
    align-items: center;
    margin-bottom: 2rem;
  }
  
  .back-button {
    display: flex;
    align-items: center;
    background: none;
    border: none;
    color: var(--primary-color);
    cursor: pointer;
    padding: 0.5rem 1rem;
    margin-right: 1rem;
    border-radius: 6px;
    transition: background-color 0.2s;
  }
  
  .back-button:hover {
    background-color: var(--primary-light);
  }
  
  .back-button span {
    margin-left: 0.5rem;
  }
  
  .category-header h2 {
    display: flex;
    align-items: center;
    font-size: 1.75rem;
  }
  
  .category-header h2 :global(svg) {
    margin-right: 0.75rem;
    color: var(--primary-color);
  }
  
  /* Lista de artículos */
  .articles-list {
    background-color: var(--surface-color);
    border-radius: 12px;
    border: 1px solid var(--border-color);
    overflow: hidden;
  }
  
  .article-item {
    padding: 1.2rem 1.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
    transition: background-color 0.2s;
    border-bottom: 1px solid var(--border-color);
  }
  
  .article-item:last-child {
    border-bottom: none;
  }
  
  .article-item:hover {
    background-color: var(--hover-color);
  }
  
  .article-info {
    flex: 1;
  }
  
  .article-info h3 {
    font-size: 1.1rem;
    margin: 0 0 0.3rem 0;
  }
  
  .views {
    font-size: 0.85rem;
    color: var(--text-secondary);
  }
  
  /* Resultados de búsqueda */
  .search-results h2 {
    font-size: 1.5rem;
    margin-bottom: 1.5rem;
  }
  
  /* Estilos responsivos */
  @media (max-width: 768px) {
    .help-center {
      padding: 1.5rem;
    }
    
    header {
      margin-bottom: 2rem;
    }
    
    header h1 {
      font-size: 2rem;
    }
    
    .categories-grid {
      grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    }
    
    .support-options {
      grid-template-columns: 1fr;
    }
    
    .category-card {
      padding: 1rem;
    }
    
    .category-header h2 {
      font-size: 1.5rem;
    }
  }
</style> 