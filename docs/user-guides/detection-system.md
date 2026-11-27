# Sistema de Detección de Amaru Antivirus

El motor YARA de Amaru puede analizar archivos y búferes de memoria. La regresión de firmas contrasta 651 entradas EICAR y tres controles con YARA y YARA-X. La instalación en Windows 11, la detección de malware real y el coste de cada capa requieren evaluaciones propias. [Resultados por componente](../../status_development.md) · [Especificación del corpus](../technical/eicar-corpus.md)

## Índice

1. [Fundamentos del Sistema de Detección](#fundamentos-del-sistema-de-detección)
2. [Tecnologías y Algoritmos](#tecnologías-y-algoritmos)
3. [Mejoras en la Precisión](#mejoras-en-la-precisión)
4. [Gestión de Patrones de Malware](#gestión-de-patrones-de-malware)
5. [Integración con otros Componentes](#integración-con-otros-componentes)
6. [Configuración Avanzada](#configuración-avanzada)
7. [Evaluación y Benchmarks](#evaluación-y-benchmarks)
8. [Preguntas Frecuentes](#preguntas-frecuentes)

## Fundamentos del Sistema de Detección

El diseño combina análisis estático, dinámico y basado en la nube. Las secciones de arquitectura, algoritmos y configuración describen el alcance previsto. La integración de reputación en la nube, modelos de aprendizaje y monitoreo post-ejecución sigue pendiente de validación.

### Arquitectura del Sistema

La arquitectura propuesta asigna una responsabilidad a cada módulo.

- **Motor de Análisis Primario**: Evaluación rápida de bajo impacto
- **Motor de Análisis Avanzado**: Análisis profundo para elementos sospechosos
- **Sistema de Reputación**: Verificación en la nube de archivos y URLs
- **Analizador de Comportamiento**: Monitoreo de actividades en tiempo real
- **Evaluador de Patrones**: Identificación de patrones complejos entre diferentes amenazas
- **Sistema de Retroalimentación**: Aprendizaje continuo basado en datos anónimos

### Flujo de Detección

1. **Pre-filtrado**: Evaluación preliminar para descartar rápidamente archivos seguros conocidos
2. **Análisis primario**: Detección básica mediante firmas y heurística simple
3. **Verificación de reputación**: Consulta a la base de datos en la nube
4. **Análisis contextual**: Evaluación del origen, comportamiento y contexto del archivo
5. **Análisis avanzado**: Para elementos que requieren inspección más profunda
6. **Monitoreo post-ejecución**: Vigilancia del comportamiento tras la ejecución

## Tecnologías y Algoritmos

Las firmas YARA y el análisis estático de ejecutables con Radare2 disponen de pruebas de componente. En la hoja de ruta figuran también las técnicas siguientes. [Validación de reglas](../technical/yara-x.md) · [Análisis estático](../../radare2-analyzer/README.md)

### Algoritmos Fundamentales

- **Detección por Firmas**: Identificación de amenazas conocidas mediante hashes y firmas binarias
- **Análisis Heurístico**: Detección de amenazas desconocidas basada en reglas y patrones sospechosos
- **Emulación de Código**: Ejecución de código sospechoso en un entorno virtual controlado
- **Análisis Estático de Código**: Descompilación y análisis estructural de archivos ejecutables

### Algoritmos avanzados previstos

- **Detección por Redes Neuronales Convolucionales (CNN)**: Análisis visual de código malicioso estructurado como imágenes
- **Transformadores de Secuencia**: Identificación de patrones secuenciales en comportamientos maliciosos
- **Análisis de Grafos de Comportamiento**: Modelado de relaciones y dependencias entre acciones sospechosas
- **Algoritmos de Detección de Anomalías**: Identificación de comportamientos que se desvían de los patrones normales
- **Análisis de Memoria Profundo**: Detección de malware sin archivos (fileless) en memoria RAM
- **Alineamiento de Secuencias Binarias**: Identificación de similitudes entre diferentes variantes de malware
- **Detección de Ofuscación**: Reconocimiento de técnicas de evasión y ofuscación de código

### Algoritmos Especializados por Tipo de Amenaza

- **Anti-Evasión**: Contramedidas para malware que intenta evadir la detección
- **Detección Anti-Rootkit**: Técnicas específicas para identificar rootkits avanzados
- **Anti-Ransomware**: Algoritmos de detección temprana de comportamientos de cifrado malicioso
- **Anti-Exploit**: Prevención de explotación de vulnerabilidades en aplicaciones
- **Detección de Amenazas Persistentes Avanzadas (APT)**: Reconocimiento de patrones de ataque sofisticados a largo plazo

## Mejoras en la Precisión

La precisión en la detección es fundamental para evitar tanto falsos positivos como falsos negativos, ambos problemáticos para la experiencia del usuario y la seguridad del sistema.

### Optimización de Algoritmos

- **Calibración Dinámica**: Ajuste automático de sensibilidad basado en el perfil del usuario
- **Correlación Multi-señal**: Combina múltiples indicadores para reducir falsos positivos
- **Verificación Cruzada**: Contrasta resultados de diferentes métodos de detección antes de tomar acción
- **Análisis Contextual Avanzado**: Considera el contexto completo (origen, reputación, comportamiento)

### Sistema de Clasificación Mejorado

- **Clasificación Multinivel**: Categorización precisa de amenazas en múltiples dimensiones:
  - Tipo de amenaza (troyano, ransomware, spyware, etc.)
  - Nivel de riesgo (crítico, alto, medio, bajo)
  - Confianza en la detección (confirmada, alta probabilidad, sospechosa)
  - Impacto potencial (sistema, datos, privacidad)

- **Perfil de Comportamiento Adaptativo**: Aprende de los patrones de uso legitimados por el usuario

### Reducción de Falsos Positivos

- **Listas Blancas Inteligentes**: Exclusiones automáticas basadas en reputación y comportamiento
- **Aprendizaje de Feedback**: Mejora continua basada en reportes de falsos positivos
- **Pre-procesamiento de Software Legítimo**: Identificación previa de aplicaciones legítimas populares
- **Análisis de Certificados**: Verificación de firmas digitales y autoridades certificadoras

## Gestión de Patrones de Malware

El objetivo de la gestión de patrones es reconocer familias y variantes. Para evaluar esa capacidad hacen falta muestras etiquetadas por familia y controles de software legítimo.

### Tecnologías de Reconocimiento de Patrones

- **Clustering de Malware**: Agrupación automática de amenazas similares
- **Detección de Variantes**: Identificación de nuevas variantes de amenazas conocidas
- **Reconocimiento de Comportamiento Familiar**: Detección de patrones de comportamiento característicos de familias de malware
- **Análisis de Similitud de Código**: Comparación estructural con bibliotecas de código malicioso conocido

### Base de Conocimiento de Patrones

- **Biblioteca de Patrones de Ataque**: Catálogo extenso de técnicas, tácticas y procedimientos (TTPs)
- **Perfiles de Comportamiento**: Modelos de actividad típica para diferentes tipos de malware
- **Indicadores de Compromiso (IoCs)**: Base de datos actualizada de señales asociadas a amenazas específicas
- **Árbol de Comportamiento**: Modelos de secuencias de acciones maliciosas con sus variaciones conocidas

### Evolución y Adaptación

- **Actualización Automática de Patrones**: Sincronización regular con la base de datos en la nube
- **Aprendizaje por Retroalimentación**: Refinamiento basado en detecciones exitosas
- **Análisis Predictivo**: Anticipación de posibles evoluciones de amenazas conocidas
- **Generación Sintética**: Creación de modelos de posibles variantes para entrenamiento del sistema

## Integración con otros Componentes

El diseño contempla las siguientes conexiones. La prueba de aceptación en Windows 11 debe recorrer el camino desde el evento de archivo hasta la decisión del motor y su acción sobre la amenaza.

### Interacción con Módulos

- **Protección en Tiempo Real**: Implementación de algoritmos de detección en el monitoreo continuo
- **Análisis Bajo Demanda**: Uso de motores de detección en análisis programados y manuales
- **Sistema de Cuarentena**: Gestión segura de amenazas detectadas
- **Firewall y Protección Web**: Compartición de inteligencia para bloqueo preventivo

### Optimización de Recursos

- **Análisis por Etapas**: Aplicación progresiva de algoritmos según nivel de sospecha
- **Priorización Inteligente**: Asignación de recursos de análisis según el riesgo potencial
- **Análisis Diferido**: Programación de análisis intensivos para momentos de baja utilización

## Configuración Avanzada

Estas opciones y perfiles forman parte del diseño de configuración para administradores. La disponibilidad de cada ajuste depende de su integración con el servicio.

### Opciones Configurables

- **Nivel de Sensibilidad**: Ajuste del equilibrio entre detección y falsos positivos
- **Algoritmos Activos**: Activación/desactivación de tecnologías específicas de detección
- **Acciones Automáticas**: Configuración de respuestas automáticas según el tipo de amenaza
- **Exclusiones Avanzadas**: Definición granular de excepciones por características técnicas

### Perfiles Predefinidos

- **Máxima Seguridad**: Prioriza la detección total, incluso con más falsos positivos
- **Equilibrado**: Configuración recomendada para la mayoría de usuarios
- **Rendimiento**: Minimiza el impacto en el sistema, manteniendo protección esencial
- **Personalizado**: Configuración manual para necesidades específicas

## Evaluación y Benchmarks

Los umbrales de esta sección son objetivos de evaluación. Aún falta publicar un informe que identifique versión, corpus, controles, configuración, hardware y resultados. La prueba EICAR comprueba una firma de ensayo y carece de valor estadístico para estimar la eficacia sobre amenazas reales.

### Objetivos de rendimiento y precisión

- **Tasa de Detección**: Objetivo superior al 99,7 % en un corpus representativo de amenazas etiquetadas
- **Tasa de Falsos Positivos**: Objetivo inferior al 0,001 % en un corpus documentado de software legítimo
- **Tiempo de Respuesta**: Objetivo de latencia inferior a 100 ms desde el evento de archivo hasta el veredicto
- **Impacto en Rendimiento**: Objetivo inferior al 2 % frente a la misma carga sin análisis

### Comparativas

El proyecto contempla la evaluación de protección, rendimiento y usabilidad con AV-TEST, la clasificación Advanced+ de AV-Comparatives como meta y la medición de cobertura por técnica MITRE ATT&CK. Una atribución de puntuación o certificación requiere el informe público del evaluador, la fecha y la versión evaluada. Estas referencias quedan pendientes.

## Preguntas Frecuentes

### ¿Cómo impactan los nuevos algoritmos en el rendimiento del sistema?

Los nuevos algoritmos están diseñados para minimizar el impacto en el rendimiento mediante:
- Ejecución selectiva según nivel de sospecha
- Optimización para procesamiento multinúcleo
- Uso de aceleración por hardware cuando está disponible
- Análisis progresivo que aplica algoritmos más intensivos solo cuando es necesario

### ¿Cómo se mantienen actualizados los patrones de malware?

Las reglas disponibles se mantienen con el código. El actualizador de reglas comprueba la firma y la integridad de los archivos descargados. La operación continua del servicio y la siguiente política de suministro forman parte del diseño. [Guía de actualizaciones](./updates.md)
- Actualizaciones automáticas varias veces al día
- Inteligencia de amenazas en tiempo real desde la nube
- Análisis de amenazas emergentes por nuestro laboratorio de seguridad
- Colaboración con la comunidad de seguridad y CERT

### ¿Puedo confiar en que no habrá falsos positivos con mis aplicaciones?

Tres controles negativos pasaron la prueba EICAR. Para estimar falsos positivos en aplicaciones reales hace falta un conjunto representativo de software legítimo. La hoja de ruta contempla reputación, verificación múltiple y aprendizaje por retroalimentación. Puedes comunicar un caso indicando la versión y la regla que coincidió. [Soporte](../support/contact.md)

### ¿Cómo detecta Amaru amenazas nunca vistas antes (zero-day)?

Las técnicas previstas para evaluar amenazas desconocidas incluyen las siguientes. Su eficacia frente a amenazas de día cero queda por medir.
- Análisis heurístico avanzado
- Aprendizaje automático con un objetivo de entrenamiento a escala de millones de muestras
- Detección de comportamientos anómalos
- Emulación en un entorno aislado para observar el comportamiento

---

Para información más detallada sobre aspectos específicos del sistema de detección, consulta nuestra [documentación técnica](../technical/detection-engine.md) o contacta con nuestro [equipo de soporte](../support/contact.md). 