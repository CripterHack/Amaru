# Mejoras en el Sistema de Detección

Esta guía recoge los objetivos de mejora del motor y los criterios pendientes para acreditar sus beneficios. La compilación de las reglas distribuidas y la detección del corpus EICAR tienen pruebas reproducibles. La validación de aprendizaje automático, servicios en la nube y detección de amenazas reales requiere evidencia adicional. [Estado de desarrollo](../../status_development.md) · [Prueba de firmas](../technical/eicar-corpus.md)

## Índice

1. [Nuevos Algoritmos de Detección](#nuevos-algoritmos-de-detección)
2. [Mayor Precisión en la Detección](#mayor-precisión-en-la-detección)
3. [Gestión Avanzada de Patrones de Malware](#gestión-avanzada-de-patrones-de-malware)
4. [Beneficios para el Usuario](#beneficios-para-el-usuario)
5. [Configuración Recomendada](#configuración-recomendada)
6. [Preguntas Frecuentes](#preguntas-frecuentes)

## Nuevos Algoritmos de Detección

La hoja de ruta contempla tres líneas de trabajo.

### Detección basada en Inteligencia Artificial

Los modelos propuestos tienen como objetivos:

- **Identifican patrones complejos** en archivos y comportamientos que los métodos tradicionales podrían pasar por alto
- **Aprenden y mejoran constantemente** a partir de nuevas amenazas detectadas
- **Detectan malware desconocido** basándose en similitudes con amenazas conocidas

### Análisis de Comportamiento Mejorado

La especificación de análisis de comportamiento contempla:

- **Secuencias de actividades sospechosas**: Detecta combinaciones de acciones potencialmente maliciosas
- **Grafos de comportamiento**: Analiza las relaciones entre diferentes acciones para identificar patrones maliciosos
- **Detección de anomalías**: Identifica cuando un programa se comporta de manera diferente a lo normal

### Detección Especializada por Tipo de Amenaza

Las categorías propuestas para algoritmos específicos incluyen:

- **Anti-Ransomware**: Detección temprana de comportamientos de cifrado malicioso
- **Anti-Rootkit**: Técnicas avanzadas para detectar malware que se oculta profundamente en el sistema
- **Protección contra Ataques de Día Cero**: Identificación de amenazas nunca vistas anteriormente
- **Detección de Malware sin Archivos**: Reconocimiento de amenazas que operan solo en memoria

## Mayor Precisión en la Detección

Los cambios propuestos buscan reducir los falsos positivos y aumentar la precisión. Para medir su efecto se necesitan corpus distintos de amenazas y software legítimo.

### Sistema Multi-verificación

El diseño prevé contrastar cada alerta antes de actuar.

- **Verificación cruzada**: Contrasta resultados de diferentes métodos de detección
- **Análisis contextual**: Considera el origen, reputación y contexto de los archivos
- **Clasificación de confianza**: Asigna niveles de certeza a cada detección

### Clasificación Mejorada de Amenazas

La clasificación propuesta considera tres dimensiones.

- **Tipo de amenaza**: Categorización detallada (troyano, ransomware, adware, etc.)
- **Nivel de riesgo**: Evaluación más precisa de la gravedad (crítico, alto, medio, bajo)
- **Impacto potencial**: Análisis de posibles efectos en tu sistema y datos

### Reducción Inteligente de Falsos Positivos

- **Listas blancas dinámicas**: Exclusiones automáticas basadas en reputación verificada
- **Aprendizaje de retroalimentación**: El sistema mejora basándose en reportes de falsos positivos
- **Pre-verificación de software legítimo**: Base de datos ampliada de aplicaciones confiables

## Gestión Avanzada de Patrones de Malware

La gestión de patrones tiene como objetivo reconocer familias y variantes mediante las siguientes técnicas.

### Detección de Variantes

- **Reconocimiento de familias**: Identifica nuevas variantes de amenazas conocidas
- **Similitud estructural**: Detecta malware modificado que intenta evadir la detección
- **Análisis de código genético**: Encuentra relaciones entre diferentes muestras de malware

### Base de Conocimiento Ampliada

- **Biblioteca de patrones de ataque**: Catálogo extenso de técnicas, tácticas y procedimientos
- **Indicadores de compromiso**: Base de datos actualizada de señales asociadas a amenazas específicas
- **Perfiles de comportamiento**: Modelos de actividad típica para diferentes tipos de malware

### Actualizaciones Optimizadas

- **Actualizaciones incrementales**: Descargas más pequeñas y rápidas
- **Sincronización en tiempo real**: Protección inmediata contra amenazas emergentes
- **Inteligencia colectiva**: Beneficio de detecciones realizadas en toda la comunidad de usuarios

## Beneficios para el Usuario

Los beneficios enumerados son objetivos. Las metas relativas de eficacia y tiempo de análisis requieren comparar dos versiones sobre el mismo corpus y hardware, con la misma configuración y resultados publicados.

### Mayor Protección

- **Detección mejorada**: Meta de mejora de hasta un 30 % de eficacia frente a la versión de referencia por definir
- **Protección proactiva**: Identificación de amenazas antes de que puedan activarse
- **Defensa contra amenazas sofisticadas**: Mayor capacidad contra ataques dirigidos

### Mejor Rendimiento

- **Análisis más eficiente**: Menor impacto en el rendimiento del sistema
- **Optimización inteligente**: Ajuste automático según la actividad del usuario
- **Análisis más rápidos**: Meta de reducción de hasta un 40 % del tiempo de escaneo frente a esa referencia

### Experiencia de Usuario Mejorada

- **Menos interrupciones**: Reducción de alertas innecesarias
- **Mayor precisión**: Menos falsos positivos que requieran tu atención
- **Información más clara**: Detalles más comprensibles sobre las amenazas detectadas

## Configuración Recomendada

Los perfiles, controles de nube y prioridades de actualización siguientes describen la configuración prevista. Su disponibilidad en una instalación requiere una prueba del flujo completo en Windows 11.

### Configuración General

- Mantener todos los componentes de protección activados
- Permitir la "Protección en la nube" para beneficiarte de las detecciones en tiempo real
- Programar análisis completos semanales para una verificación exhaustiva

### Ajustes de Detección

El diseño contempla tres perfiles de sensibilidad.

- **Equilibrado** (por defecto): Buen balance entre detección y rendimiento
- **Máxima seguridad**: Mayor sensibilidad, ideal para equipos con información sensible
- **Rendimiento**: Prioriza la velocidad del sistema, manteniendo protección esencial

### Actualizaciones

- Mantener activadas las actualizaciones automáticas
- Permitir las "Actualizaciones inteligentes" que optimizan el momento de instalación
- Activar la opción "Actualización prioritaria de firmas" para recibir primero las detecciones críticas

## Preguntas Frecuentes

### ¿Las nuevas tecnologías de detección ralentizarán mi equipo?

El impacto depende del número y tamaño de los archivos, las reglas, el almacenamiento y la actividad del equipo. Los objetivos de latencia y uso de recursos están pendientes de medición en Windows 11. [Objetivos de evaluación](./detection-system.md#evaluación-y-benchmarks)

### ¿Cómo puedo saber si las nuevas capacidades están funcionando?

La prueba del corpus permite comprobar las reglas distribuidas de manera reproducible. El indicador del panel espera una respuesta del servicio. La vista de informes y la atribución de detecciones a los nuevos algoritmos necesitan validación de extremo a extremo. [Prueba del corpus](../technical/eicar-corpus.md)

### ¿Necesito hacer algo para activar estas mejoras?

Consulta las capacidades verificadas para tu revisión del código. El despliegue automático de mejoras y la recarga de reglas en un servicio instalado están pendientes de validación. [Estado de desarrollo](../../status_development.md)

### ¿Estas mejoras funcionan en todos los sistemas operativos?

La aplicación tiene como plataforma objetivo Windows 11 de 64 bits. Hay pruebas de componentes en Linux. La compatibilidad de la aplicación completa con macOS o Linux requiere trabajo y validación adicionales.

### ¿Qué hago si sospecho que hay un falso positivo?

Anota la versión de Amaru, el nombre de la regla y el comportamiento esperado. Usa el canal de incidencias del proyecto. El envío anónimo desde cuarentena figura como función prevista. [Contacto](../support/contact.md)

### ¿Estas mejoras protegen contra las últimas variantes de ransomware?

La detección temprana de comportamientos de cifrado es un objetivo del diseño. Su validación requiere pruebas específicas de detección y respuesta, además de la prueba de firmas con EICAR.

---

Estas mejoras representan nuestro compromiso continuo con tu seguridad digital. Si tienes más preguntas sobre el sistema de detección mejorado, no dudes en contactar con nuestro [equipo de soporte](../support/contact.md). 