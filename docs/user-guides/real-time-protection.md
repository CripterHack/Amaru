# Protección en Tiempo Real

La protección en tiempo real es el escudo principal de Amaru Antivirus, monitorizando constantemente tu sistema para detectar, bloquear y eliminar amenazas antes de que puedan dañar tu dispositivo.

## Índice

1. [¿Qué es la Protección en Tiempo Real?](#qué-es-la-protección-en-tiempo-real)
2. [Componentes de la Protección](#componentes-de-la-protección)
3. [Cómo Funciona](#cómo-funciona)
4. [Estado y Notificaciones](#estado-y-notificaciones)
5. [Configuración](#configuración)
6. [Exclusiones](#exclusiones)
7. [Modos de Protección](#modos-de-protección)
8. [Optimización](#optimización)
9. [Solución de Problemas](#solución-de-problemas)
10. [Preguntas Frecuentes](#preguntas-frecuentes)

## ¿Qué es la Protección en Tiempo Real?

La protección en tiempo real es un sistema de defensa proactivo que:

- Supervisa continuamente todas las actividades del sistema
- Analiza archivos cuando se crean, modifican o ejecutan
- Monitoriza la actividad de red entrante y saliente
- Detecta comportamientos sospechosos en tiempo real
- Bloquea amenazas instantáneamente, sin esperar a análisis programados

A diferencia de los análisis bajo demanda, que revisan tu sistema en momentos específicos, la protección en tiempo real proporciona vigilancia constante, siendo la primera línea de defensa contra malware, ransomware, phishing y otras amenazas.

## Componentes de la Protección

Amaru integra múltiples capas de protección en tiempo real:

### Escudo de Archivos

Monitoriza todas las operaciones de archivos, analizándolos cuando:
- Son creados o modificados
- Se intentan ejecutar
- Se descargan de internet
- Se accede a ellos desde aplicaciones

### Protección Web

- Analiza el tráfico web para detectar sitios maliciosos
- Bloquea conexiones a servidores de distribución de malware
- Protege contra ataques de phishing
- Filtra descargas de contenido potencialmente peligroso

### Monitor de Comportamiento

- Analiza el comportamiento de las aplicaciones en ejecución
- Detecta acciones sospechosas (por ejemplo, cifrado no autorizado de archivos característico de ransomware)
- Bloquea actividades potencialmente peligrosas
- Detecta amenazas de día cero mediante análisis heurístico

### Protección contra Vulnerabilidades

- Monitoriza intentos de explotación de vulnerabilidades
- Protege aplicaciones vulnerables
- Bloquea técnicas de escalada de privilegios
- Previene ataques de desbordamiento de buffer

### Protección de Email

- Analiza correos electrónicos y sus adjuntos
- Detecta intentos de phishing
- Bloquea enlaces maliciosos en mensajes
- Identifica posibles estafas

### Protección Anti-Ransomware

- Monitoriza patrones de cifrado sospechosos
- Protege archivos y carpetas específicos contra modificaciones no autorizadas
- Crea copias de seguridad de archivos importantes en caso de ataque
- Detecta comportamientos típicos de ransomware

## Cómo Funciona

### Proceso de Detección y Respuesta

1. **Monitorización**: Amaru supervisa continuamente todos los procesos activos, operaciones de archivo y conexiones de red.

2. **Detección**: Cuando se detecta actividad sospechosa, Amaru evalúa la amenaza usando:
   - Base de datos de firmas de virus
   - Análisis heurístico y de comportamiento
   - Inteligencia de la nube
   - Aprendizaje automático

3. **Respuesta**: Dependiendo de la configuración y el nivel de amenaza, Amaru:
   - Bloquea la actividad maliciosa
   - Pone en cuarentena archivos sospechosos
   - Termina procesos peligrosos
   - Notifica al usuario
   - Registra el evento

4. **Aprendizaje**: El sistema mejora continuamente mediante:
   - Actualización regular de la base de datos de amenazas
   - Envío anónimo de información sobre nuevas amenazas (si está habilitado)
   - Ajustes automáticos basados en el comportamiento del usuario

### Tecnologías Utilizadas

- **Análisis de Firmas**: Compara archivos con una base de datos de malware conocido
- **Heurística**: Detecta malware desconocido basándose en patrones de comportamiento
- **Emulación Segura**: Ejecuta código sospechoso en un entorno aislado para evaluar su comportamiento
- **Inteligencia Artificial**: Identifica amenazas mediante algoritmos de aprendizaje automático
- **Protección Basada en la Nube**: Verifica archivos contra una base de datos en la nube en tiempo real

## Estado y Notificaciones

### Indicadores de Estado

La interfaz de Amaru muestra el estado de la protección en tiempo real mediante:

- **Icono en la Bandeja del Sistema**:
  - Verde: Protección activa y funcionando correctamente
  - Amarillo: Protección parcialmente activa o requiere atención
  - Rojo: Protección desactivada o problema crítico

- **Panel de Control Principal**:
  - Muestra el estado actual de todos los componentes
  - Proporciona acceso rápido a la configuración
  - Indica la última vez que se detectó una amenaza

### Sistema de Notificaciones

Amaru te mantiene informado mediante:

- **Notificaciones Emergentes**: Aparecen cuando:
  - Se detecta y bloquea una amenaza
  - Se requiere intervención del usuario
  - Hay cambios en el estado de protección

- **Centro de Notificaciones**: Almacena un historial de:
  - Amenazas detectadas
  - Actualizaciones importantes
  - Cambios de configuración
  - Recomendaciones de seguridad

- **Informes por Correo Electrónico** (opcional):
  - Resúmenes diarios o semanales
  - Alertas de amenazas críticas
  - Informes detallados de actividad

## Configuración

Amaru te permite personalizar la protección en tiempo real según tus necesidades:

### Acceso a la Configuración

1. Abre Amaru Antivirus
2. Haz clic en "Configuración" en el menú principal
3. Selecciona "Protección en tiempo real"

### Ajustes Generales

- **Activar/Desactivar**: Enciende o apaga la protección en tiempo real completa
  - **Advertencia**: Desactivar la protección deja tu sistema vulnerable. Solo hazlo temporalmente si es absolutamente necesario.

- **Nivel de Análisis**: Ajusta la profundidad del análisis
  - Rápido: Menor impacto en el rendimiento, análisis básico
  - Equilibrado: Configuración recomendada para la mayoría de usuarios
  - Completo: Máxima protección, puede afectar ligeramente al rendimiento

- **Acciones Automáticas**: Define cómo responde Amaru a las amenazas
  - Preguntar al usuario (recomendado para usuarios avanzados)
  - Cuarentena automática (configuración predeterminada)
  - Reparar si es posible, cuarentena si no
  - Bloquear acceso sin cuarentena

### Configuración por Componentes

#### Escudo de Archivos

- **Tipos de Archivos**:
  - Todos los archivos
  - Solo ejecutables y documentos
  - Personalizado (selecciona extensiones específicas)

- **Eventos de Análisis**:
  - Al abrir archivos
  - Al crear o modificar archivos
  - Al ejecutar programas

#### Protección Web

- **Navegadores Protegidos**: Selecciona qué navegadores monitorizar
- **Filtrado Web**: Activa/desactiva el bloqueo de sitios maliciosos
- **Análisis HTTPS**: Habilita/deshabilita la inspección de tráfico cifrado
- **Lista Negra/Blanca**: Gestiona sitios bloqueados o permitidos manualmente

#### Monitor de Comportamiento

- **Nivel de Sensibilidad**: Ajusta cuán agresiva es la detección
  - Alta: Detecta más amenazas potenciales, puede generar más falsos positivos
  - Media: Equilibrio recomendado
  - Baja: Solo detecta comportamiento claramente malicioso

- **Protección de Áreas Críticas**: Protege:
  - Registro del sistema
  - Carpetas del sistema
  - Procesos del sistema
  - Arranque del sistema

#### Protección Anti-Ransomware

- **Carpetas Protegidas**: Define qué carpetas proteger especialmente
  - Documentos, Imágenes, etc. (predeterminado)
  - Carpetas personalizadas

- **Aplicaciones Confiables**: Programas con permiso para modificar archivos protegidos

## Exclusiones

Las exclusiones te permiten definir archivos, carpetas o procesos que Amaru no analizará:

### Gestión de Exclusiones

1. Ve a "Configuración" > "Protección en tiempo real" > "Exclusiones"
2. Haz clic en "Añadir exclusión"
3. Selecciona el tipo:
   - Archivo
   - Carpeta
   - Proceso/aplicación
   - Dirección web
   - Hash de archivo

### Tipos de Exclusiones

- **Exclusiones de Archivos/Carpetas**: Útil para:
  - Archivos muy grandes que ralentizan el análisis
  - Carpetas de programas confiables que generan falsos positivos
  - Archivos de datos que se modifican frecuentemente

- **Exclusiones de Procesos**: Útil para:
  - Aplicaciones confiables que interactúan intensamente con el sistema
  - Software que funciona incorrectamente con el antivirus activo
  - Herramientas de desarrollo o virtualización

### Patrones y Comodines

Puedes usar comodines en las exclusiones:

- `*` representa cualquier secuencia de caracteres
  - Ejemplo: `*.log` excluye todos los archivos log
- `?` representa cualquier carácter individual
  - Ejemplo: `file?.dat` excluiría file1.dat, file2.dat, etc.

## Modos de Protección

Amaru ofrece diferentes modos de protección para adaptarse a distintas situaciones:

### Modo Estándar

- Equilibrio entre seguridad y rendimiento
- Recomendado para uso diario
- Configuración predeterminada

### Modo Juego/No Molestar

- Minimiza notificaciones y uso de recursos
- Pospone tareas no críticas
- Ideal durante juegos, presentaciones o trabajo que requiera máximo rendimiento
- Activación:
  - Manual: "Configuración" > "General" > "Modo Juego"
  - Automática: Cuando las aplicaciones se ejecutan a pantalla completa

### Modo Máxima Seguridad

- Aumenta la vigilancia y restricciones
- Analiza todo con máxima profundidad
- Útil cuando manipulas archivos sensibles o navegas por sitios desconocidos
- Puede afectar al rendimiento

## Optimización

Para maximizar la protección sin afectar al rendimiento:

### Rendimiento del Sistema

- **Programación Inteligente**: Amaru ajusta la intensidad del análisis según:
  - Uso actual de la CPU
  - Si el equipo funciona con batería
  - Si hay aplicaciones a pantalla completa

- **Análisis Selectivo**: Prioriza el análisis de:
  - Archivos nuevos o modificados recientemente
  - Áreas de alto riesgo del sistema
  - Procesos con comportamiento inusual

### Consejos de Optimización

- **Exclusiones Estratégicas**: Excluye:
  - Archivos muy grandes que sabes que son seguros
  - Carpetas de backups o archivos de datos que cambian constantemente
  - NO excluyas carpetas donde normalmente se descargan archivos

- **Actualización Regular**: Mantén Amaru actualizado para:
  - Mejorar el rendimiento con optimizaciones más recientes
  - Reducir falsos positivos
  - Obtener las últimas técnicas de detección

## Solución de Problemas

### Problemas Comunes

#### La Protección en Tiempo Real se Desactiva Sola

Posibles causas:
- Otro software de seguridad está causando conflictos
- Problemas con los servicios de Windows
- Fallos en actualizaciones recientes

Soluciones:
1. Reinicia tu equipo
2. Verifica que el servicio de Amaru esté en ejecución
3. Reinstala Amaru si persiste el problema

#### Rendimiento Lento del Sistema

Posibles causas:
- Nivel de análisis demasiado intensivo
- Falta de exclusiones adecuadas
- Recursos del sistema limitados

Soluciones:
1. Ajusta el nivel de análisis a "Equilibrado"
2. Añade exclusiones para carpetas de gran tamaño que uses frecuentemente
3. Programa análisis completos para horas de baja actividad

#### Falsos Positivos Frecuentes

Soluciones:
1. Reporta el falso positivo a través de la aplicación
2. Añade el archivo o carpeta a las exclusiones
3. Actualiza Amaru a la última versión

## Preguntas Frecuentes

### ¿Puedo desactivar temporalmente la protección en tiempo real?

Sí, aunque no es recomendable. Si necesitas hacerlo:
1. Haz clic derecho en el icono de Amaru en la bandeja del sistema
2. Selecciona "Desactivar protección en tiempo real"
3. Elige por cuánto tiempo (10 minutos, 30 minutos, 1 hora, hasta reiniciar)
4. Amaru reactivará automáticamente la protección después del tiempo seleccionado

### ¿Cómo afecta la protección en tiempo real al rendimiento?

El impacto es generalmente mínimo en equipos modernos. Amaru está diseñado para:
- Utilizar recursos de forma eficiente
- Ajustar su actividad según la carga del sistema
- Priorizar tareas críticas del usuario

Si experimentas problemas de rendimiento, prueba:
- Cambiar el nivel de análisis a "Equilibrado" o "Rápido"
- Revisar y ajustar tus exclusiones
- Activar el "Modo Juego" durante actividades que requieran alto rendimiento

### ¿Qué hago si un programa legítimo es bloqueado?

Si Amaru bloquea un programa que sabes que es seguro:
1. Abre Amaru y ve a "Historial de protección"
2. Encuentra la entrada relacionada con el bloqueo
3. Selecciona "Restaurar" y "Añadir a exclusiones"
4. Alternativamente, añade manualmente el programa a las exclusiones

### ¿Debo desactivar la protección si instalo ciertos programas?

Normalmente no es necesario. Sin embargo, algunos instaladores o software especializado pueden generar falsos positivos. En estos casos:
- Activa temporalmente el "Modo de instalación" desde la configuración
- Añade el instalador a las exclusiones antes de ejecutarlo
- Contacta con soporte si un programa importante es constantemente bloqueado

### ¿Cómo sé si la protección en tiempo real está funcionando correctamente?

Puedes verificar que todo funciona correctamente:
1. El icono en la bandeja del sistema debe ser verde
2. En el panel principal, todos los componentes deben mostrar "Activo"
3. Puedes realizar una prueba segura usando el archivo de prueba EICAR:
   - Visita [www.eicar.org](https://www.eicar.org/?page_id=3950)
   - Descarga el archivo de prueba estándar
   - Amaru debería detectarlo inmediatamente como una amenaza de prueba

### ¿La protección en tiempo real analiza dispositivos externos?

Sí, Amaru analiza automáticamente:
- Dispositivos USB cuando se conectan
- Discos duros externos
- Unidades de red mapeadas
- Tarjetas de memoria

Puedes configurar este comportamiento en "Configuración" > "Protección en tiempo real" > "Dispositivos extraíbles".

---

La protección en tiempo real es tu primera línea de defensa contra las amenazas informáticas. Mantenerla activada y correctamente configurada es fundamental para garantizar la seguridad de tu sistema y datos. 