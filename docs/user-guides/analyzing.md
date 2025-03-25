# Guía de Análisis y Escaneo

Esta guía explica en detalle las diferentes opciones de análisis disponibles en Amaru Antivirus, cómo configurarlas y utilizarlas de manera efectiva para mantener tu sistema seguro.

## Índice

1. [Tipos de Análisis](#tipos-de-análisis)
2. [Análisis Rápido](#análisis-rápido)
3. [Análisis Completo](#análisis-completo)
4. [Análisis Personalizado](#análisis-personalizado)
5. [Análisis Programados](#análisis-programados)
6. [Análisis de Unidades Externas](#análisis-de-unidades-externas)
7. [Análisis de Memoria](#análisis-de-memoria)
8. [Análisis desde el Menú Contextual](#análisis-desde-el-menú-contextual)
9. [Opciones Avanzadas de Análisis](#opciones-avanzadas-de-análisis)
10. [Entender los Resultados](#entender-los-resultados)

## Tipos de Análisis

Amaru Antivirus ofrece varios tipos de análisis diseñados para diferentes necesidades:

### Análisis Rápido
Escanea las áreas más críticas y comúnmente infectadas del sistema. Ideal para verificaciones rutinarias.

### Análisis Completo
Examina todos los archivos y carpetas del sistema. Más exhaustivo pero requiere más tiempo.

### Análisis Personalizado
Permite seleccionar archivos, carpetas o unidades específicas para analizar.

### Análisis de Memoria
Examina todos los procesos en ejecución en la memoria RAM.

### Análisis de Arranque
Verifica los sectores de arranque y archivos de inicio del sistema.

## Análisis Rápido

El análisis rápido está diseñado para ofrecer un equilibrio entre velocidad y seguridad, revisando las áreas donde comúnmente se encuentran amenazas.

### Qué analiza

- **Memoria del sistema**: Procesos activos y controladores cargados
- **Registro de Windows**: Entradas de inicio automático y configuraciones críticas
- **Archivos de sistema**: Carpetas principales del sistema operativo
- **Carpetas de inicio**: Archivos que se ejecutan al iniciar Windows
- **Archivos temporales**: Áreas comunes donde el malware puede ocultarse

### Cómo ejecutarlo

1. Abre Amaru Antivirus
2. En la pantalla principal, selecciona "Análisis"
3. Haz clic en "Análisis Rápido"
4. Opcionalmente, ajusta las configuraciones específicas
5. Haz clic en "Iniciar Análisis"

### Duración y recursos

- **Tiempo promedio**: 5-15 minutos (dependiendo de tu hardware)
- **Uso de recursos**: Bajo a moderado
- **Impacto en el sistema**: Mínimo, puedes seguir trabajando normalmente

### Cuándo utilizarlo

- Diariamente o varias veces por semana
- Cuando sospechas de una posible infección
- Después de visitar sitios web potencialmente peligrosos
- Tras instalar nuevo software

## Análisis Completo

El análisis completo realiza una inspección exhaustiva de todos los archivos accesibles en tu sistema.

### Qué analiza

- Todo lo incluido en el análisis rápido
- **Todos los archivos** en todas las unidades locales
- **Archivos comprimidos** (ZIP, RAR, etc.)
- **Correos electrónicos** almacenados
- **Archivos de programa** de todas las aplicaciones instaladas
- **Documentos y archivos multimedia**

### Cómo ejecutarlo

1. Abre Amaru Antivirus
2. Selecciona "Análisis" en el menú principal
3. Haz clic en "Análisis Completo"
4. Opcionalmente, configura las opciones de análisis (profundidad, exclusiones, etc.)
5. Haz clic en "Iniciar Análisis"

### Duración y recursos

- **Tiempo promedio**: 1-4 horas (depende del tamaño del disco y cantidad de archivos)
- **Uso de recursos**: Moderado a alto
- **Impacto en el sistema**: Considerable, puede ralentizar otras tareas

### Cuándo utilizarlo

- Mensualmente como parte del mantenimiento regular
- Al configurar el software por primera vez
- Después de recuperarte de una infección
- Cuando instalas un nuevo sistema operativo
- Al transferir datos importantes entre dispositivos

## Análisis Personalizado

El análisis personalizado te permite decidir exactamente qué archivos o carpetas analizar.

### Cómo crearlo

1. Abre Amaru Antivirus
2. Ve a "Análisis" > "Análisis Personalizado"
3. Haz clic en "Añadir elemento" para seleccionar archivos o carpetas
4. Usa la ventana de explorador para seleccionar ubicaciones
5. Define opciones específicas para estos elementos:
   - Profundidad de análisis
   - Tipos de archivos a analizar
   - Acciones automáticas

### Ejemplos de uso

- **Análisis de documentos de trabajo**: Selecciona solo tus carpetas de documentos importantes
- **Verificación de descargas**: Analiza la carpeta de descargas
- **Verificación de unidad externa**: Selecciona una unidad USB específica
- **Análisis de aplicaciones**: Verifica carpetas de programas recién instalados

### Almacenar perfiles personalizados

Puedes guardar configuraciones de análisis personalizados para uso frecuente:

1. Después de configurar tu análisis personalizado
2. Haz clic en "Guardar como perfil"
3. Asigna un nombre descriptivo (ej. "Análisis Documentos Trabajo")
4. Opcionalmente, añade una descripción
5. La próxima vez, selecciona el perfil desde la lista desplegable

## Análisis Programados

Los análisis programados automatizan la seguridad para que no tengas que recordar ejecutarlos.

### Tipos de programación

- **Diaria**: Ejecuta el análisis todos los días a una hora específica
- **Semanal**: Selecciona días de la semana y hora
- **Mensual**: Elige un día específico del mes
- **Al inicio**: Ejecuta un análisis cada vez que enciendes el equipo
- **Cuando el equipo está inactivo**: Realiza el análisis cuando no estás usando la computadora

### Cómo configurarlos

1. Ve a "Configuración" > "Análisis Programados"
2. Haz clic en "Nuevo análisis programado"
3. Selecciona el tipo de análisis (rápido, completo o personalizado)
4. Define la frecuencia y el horario
5. Configura opciones adicionales:
   - Comportamiento si el equipo estaba apagado en la hora programada
   - Acciones automáticas para amenazas detectadas
   - Notificaciones

### Opciones recomendadas

- **Análisis rápido**: Programarlo 2-3 veces por semana
- **Análisis completo**: Programarlo mensualmente
- **Análisis personalizado**: Según necesidades específicas

### Gestión de análisis programados

Puedes administrar tus análisis programados desde el panel de control:
- Ver próximos análisis
- Verificar resultados de análisis anteriores
- Modificar o eliminar análisis programados
- Ejecutar manualmente un análisis programado fuera de su horario

## Análisis de Unidades Externas

Las unidades externas pueden ser vectores de infección comunes. Amaru ofrece protección específica para ellas.

### Análisis automático al conectar

Por defecto, Amaru analizará brevemente cualquier dispositivo USB o unidad externa cuando se conecte:

1. Ve a "Configuración" > "Análisis" > "Dispositivos externos"
2. Activa "Analizar automáticamente dispositivos al conectar"
3. Define el tipo de análisis a realizar:
   - Análisis rápido (predeterminado)
   - Análisis completo 
   - Solo analizar archivos autoejecutable

### Análisis manual de unidades

Para analizar manualmente una unidad externa:

1. Conecta la unidad a tu dispositivo
2. Abre Amaru Antivirus
3. Ve a "Análisis" > "Análisis Personalizado"
4. Selecciona la unidad externa en el explorador
5. Configura las opciones de análisis
6. Haz clic en "Iniciar análisis"

### Opciones específicas para unidades externas

- **Análisis preventivo**: Analiza antes de permitir el acceso a los archivos
- **Bloqueo de autoejecución**: Impide la ejecución automática de programas
- **Aislamiento de unidades desconocidas**: Mayor seguridad para unidades no reconocidas

## Análisis de Memoria

El análisis de memoria examina los procesos activos en tu sistema en busca de amenazas.

### Qué detecta

- **Malware residente en memoria**: Amenazas que se ejecutan activamente
- **Rootkits**: Programas maliciosos que ocultan su presencia
- **Procesos sospechosos**: Aplicaciones con comportamiento anómalo
- **Inyección de código**: Técnicas para infiltrar código malicioso en procesos legítimos

### Cómo ejecutarlo

1. Ve a "Análisis" > "Análisis Avanzado" > "Análisis de Memoria"
2. Selecciona el nivel de profundidad:
   - Básico: Solo procesos principales
   - Completo: Todos los procesos y su espacio de memoria
   - Profundo: Análisis exhaustivo con técnicas heurísticas
3. Haz clic en "Iniciar análisis"

### Interpretación de resultados

Los resultados mostrarán:
- Lista de procesos analizados
- Anomalías o amenazas detectadas
- Nivel de riesgo para cada detección
- Recomendaciones de acción

## Análisis desde el Menú Contextual

Amaru integra opciones de análisis directamente en el menú contextual de Windows para un acceso rápido.

### Cómo utilizarlo

1. Haz clic derecho sobre cualquier archivo o carpeta en el Explorador de Windows
2. En el menú contextual, selecciona "Analizar con Amaru Antivirus"
3. Elige entre las opciones disponibles:
   - Análisis rápido
   - Análisis con configuración predeterminada
   - Análisis con opciones avanzadas

### Personalización del menú contextual

Puedes personalizar estas opciones:

1. Ve a "Configuración" > "Integración con sistema"
2. En la sección "Menú contextual", selecciona:
   - Opciones a mostrar en el menú
   - Acción predeterminada
   - Mostrar resultados después del análisis

### Análisis por arrastrar y soltar

También puedes arrastrar archivos o carpetas y soltarlos en:
- El icono de Amaru en el escritorio
- La ventana principal de Amaru
- El icono de la bandeja del sistema

## Opciones Avanzadas de Análisis

Amaru ofrece configuraciones avanzadas para usuarios que necesitan un control más preciso.

### Configuración de profundidad

Determina cuán exhaustivo será el análisis:

- **Profundidad de análisis de archivos comprimidos**:
  - Nivel 1: Solo primer nivel de compresión
  - Nivel 2: Dos niveles de anidamiento
  - Nivel máximo: Todos los niveles (puede aumentar significativamente el tiempo)

- **Tamaño máximo de archivos**:
  - Define el tamaño máximo de archivos a analizar
  - Los archivos más grandes se omitirán

### Técnicas de detección

- **Análisis heurístico**: Detecta amenazas nuevas o desconocidas
  - Nivel bajo: Menos falsos positivos
  - Nivel medio: Equilibrado (recomendado)
  - Nivel alto: Máxima detección pero más falsos positivos

- **Análisis de comportamiento**: Evalúa el comportamiento de los archivos

- **Inteligencia en la nube**: Verifica la reputación en la base de datos online

### Acciones automáticas

Configura qué debe hacer Amaru al detectar amenazas:

- **Preguntar siempre**: Solicita confirmación para cada amenaza
- **Poner en cuarentena automáticamente**: Acción predeterminada recomendada
- **Eliminar automáticamente**: Más agresivo, sin posibilidad de recuperación
- **Acciones por nivel de amenaza**: Configura respuestas diferentes según la gravedad

## Entender los Resultados

Después de un análisis, Amaru muestra un informe detallado de los resultados.

### Componentes del informe

- **Resumen**: Vista general del análisis
  - Archivos analizados
  - Amenazas detectadas
  - Tiempo de análisis
  - Estado general

- **Lista de amenazas**:
  - Nombre del malware
  - Ubicación del archivo
  - Nivel de riesgo
  - Acción tomada o recomendada

- **Detalles técnicos**:
  - Información sobre cada amenaza
  - Comportamiento y características
  - Métodos de propagación
  - Impacto potencial

### Acciones disponibles

Para cada amenaza detectada, puedes:

- **Poner en cuarentena**: Aísla el archivo en un entorno seguro
- **Eliminar**: Borra permanentemente el archivo
- **Ignorar**: Marca como falso positivo
- **Más información**: Muestra detalles técnicos sobre la amenaza

### Historial de análisis

Todos los análisis realizados se almacenan en el historial:

1. Ve a "Informes" > "Historial de análisis"
2. Selecciona cualquier análisis anterior para ver sus detalles
3. Filtra por fecha, tipo o resultados
4. Exporta informes en formato PDF o HTML para documentación

### Interpretación de falsos positivos

En ocasiones, Amaru puede identificar erróneamente archivos legítimos como amenazas:

1. Verifica la reputación del archivo (desarrollador, fuente, etc.)
2. Consulta nuestra base de datos de conocimiento
3. Si estás seguro de que es un falso positivo:
   - Restaura el archivo si fue puesto en cuarentena
   - Añádelo a la lista de exclusiones
   - Opcionalmente, repórtalo a nuestro equipo para mejorar la detección

---

Para más información sobre el sistema de análisis, consulta nuestra [documentación técnica](../technical/scanning-engine.md) o contacta con nuestro [equipo de soporte](../support/contact.md) si tienes preguntas específicas. 