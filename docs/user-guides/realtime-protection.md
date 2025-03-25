# Protección en Tiempo Real

La protección en tiempo real es la primera línea de defensa de Amaru Antivirus, monitoreando constantemente tu sistema para detectar y bloquear amenazas antes de que puedan causar daño. Esta guía te ayudará a entender cómo funciona esta protección y cómo configurarla para obtener el máximo nivel de seguridad.

## Índice

1. [¿Qué es la Protección en Tiempo Real?](#qué-es-la-protección-en-tiempo-real)
2. [Componentes de Protección](#componentes-de-protección)
3. [Niveles de Protección](#niveles-de-protección)
4. [Configuración de la Protección](#configuración-de-la-protección)
5. [Exclusiones](#exclusiones)
6. [Notificaciones](#notificaciones)
7. [Respuesta a Amenazas](#respuesta-a-amenazas)
8. [Solución de Problemas](#solución-de-problemas)
9. [Preguntas Frecuentes](#preguntas-frecuentes)

## ¿Qué es la Protección en Tiempo Real?

A diferencia de los análisis programados o manuales, la protección en tiempo real funciona de forma continua, supervisando todas las actividades del sistema mientras usas tu dispositivo. Actúa como un guardia de seguridad que verifica cada archivo que se abre, modifica o ejecuta.

### Características principales

- **Monitoreo constante**: Funciona 24/7 sin intervención del usuario
- **Bajo consumo de recursos**: Diseñada para tener un impacto mínimo en el rendimiento
- **Detección proactiva**: Identifica amenazas por su comportamiento, no solo por firmas conocidas
- **Respuesta inmediata**: Bloquea amenazas instantáneamente antes de que puedan ejecutarse
- **Protección multicapa**: Utiliza diferentes tecnologías para una defensa completa

### Cómo funciona

La protección en tiempo real de Amaru Antivirus intercepta y analiza los archivos en varios puntos:

1. **Al acceder a un archivo**: Cuando cualquier programa intenta abrir un archivo
2. **Al ejecutar un programa**: Antes de que cualquier aplicación comience a ejecutarse
3. **Al descargar contenido**: Durante la descarga de archivos de internet
4. **Al modificar archivos del sistema**: Cuando algo intenta cambiar archivos críticos
5. **Durante la ejecución**: Monitoreo continuo de los procesos activos

## Componentes de Protección

Amaru Antivirus incluye varios módulos de protección en tiempo real, cada uno especializado en un aspecto específico de la seguridad.

### Escudo de Archivos

Monitorea todas las operaciones de lectura y escritura de archivos en tu sistema.

- **Escaneo en acceso**: Analiza los archivos cuando se abren o modifican
- **Verificación de firmas**: Compara archivos con la base de datos de malware conocido
- **Análisis heurístico**: Detecta malware desconocido por características sospechosas
- **Cobertura**: Todos los archivos en discos locales y unidades conectadas

### Escudo Web

Protege tu navegación por internet y las descargas de contenido online.

- **Análisis de URLs**: Bloquea sitios web maliciosos o de phishing
- **Escaneo de descargas**: Verifica archivos mientras se descargan
- **Protección de datos personales**: Evita el robo de información sensible
- **Compatibilidad**: Funciona con todos los navegadores principales

### Escudo de Correo Electrónico

Analiza los mensajes y archivos adjuntos de correo electrónico para detectar amenazas.

- **Escaneo de adjuntos**: Verifica todos los archivos recibidos
- **Detección de phishing**: Identifica correos fraudulentos
- **Análisis de enlaces**: Comprueba la seguridad de los links en los mensajes
- **Compatibilidad**: Funciona con todos los clientes de correo populares

### Escudo de Comportamiento

Monitorea el comportamiento de los programas en ejecución para detectar actividades sospechosas.

- **Análisis de comportamiento**: Detecta patrones de actividad maliciosa
- **Prevención de exploits**: Bloquea intentos de aprovechar vulnerabilidades
- **Protección contra ransomware**: Detecta y detiene intentos de cifrado no autorizado
- **Detección de rootkits**: Identifica software malicioso que se oculta en el sistema

### Firewall

Controla las conexiones de red entrantes y salientes para prevenir intrusiones.

- **Filtrado de conexiones**: Bloquea comunicaciones no autorizadas
- **Protección de puertos**: Evita ataques a puertos vulnerables
- **Control de aplicaciones**: Gestiona qué programas pueden acceder a internet
- **Detección de intrusiones**: Identifica patrones de ataque de red

## Niveles de Protección

Amaru te permite elegir entre diferentes niveles de protección según tus necesidades y preferencias.

### Nivel Alto (Máxima Seguridad)

- **Características**: Todas las protecciones habilitadas con la configuración más estricta
- **Análisis heurístico**: Nivel máximo para detectar amenazas desconocidas
- **Ventajas**: Máxima protección contra todo tipo de amenazas
- **Desventajas**: Mayor uso de recursos y posibilidad de falsos positivos
- **Recomendado para**: Entornos de alto riesgo o usuarios que priorizan la seguridad sobre la comodidad

### Nivel Medio (Equilibrado)

- **Características**: Configuración equilibrada entre seguridad y rendimiento
- **Análisis heurístico**: Nivel moderado
- **Ventajas**: Buena protección con impacto mínimo en el rendimiento
- **Desventajas**: Puede no detectar las amenazas más sofisticadas o nuevas
- **Recomendado para**: La mayoría de los usuarios en uso diario normal

### Nivel Bajo (Rendimiento)

- **Características**: Protecciones básicas con uso mínimo de recursos
- **Análisis heurístico**: Nivel básico o desactivado
- **Ventajas**: Impacto casi imperceptible en el rendimiento del sistema
- **Desventajas**: Protección reducida contra amenazas avanzadas
- **Recomendado para**: Sistemas con recursos limitados o cuando se necesita máximo rendimiento

### Personalizado

Te permite ajustar individualmente cada componente y configuración para adaptarse exactamente a tus necesidades.

## Configuración de la Protección

Puedes modificar la configuración de la protección en tiempo real para adaptarla a tus necesidades específicas.

### Cómo acceder a la configuración

1. Abre Amaru Antivirus
2. Ve a "Configuración" > "Protección en Tiempo Real"
3. Selecciona el componente que deseas configurar o usa "Configuración general" para ajustes globales

### Configuración General

- **Estado**: Activa o desactiva toda la protección en tiempo real
- **Nivel de protección**: Selecciona entre los niveles predefinidos o personalizado
- **Acción al detectar amenazas**: Define la respuesta automática (preguntar, cuarentena, eliminar)
- **Notificaciones**: Configura cómo y cuándo se mostrarán las alertas

### Configuración del Escudo de Archivos

- **Tipos de archivos**: Define qué tipos de archivos se analizarán
  - Todos los archivos
  - Solo archivos ejecutables
  - Archivos según extensión
- **Profundidad de análisis**: Establece qué tan exhaustivo será el escaneo
- **Análisis heurístico**: Configura la sensibilidad de la detección basada en comportamiento

### Configuración del Escudo Web

- **Protocolos**: Selecciona qué protocolos de internet se monitorizarán (HTTP, HTTPS, FTP)
- **Navegadores**: Elige qué navegadores estarán protegidos
- **Lista negra/blanca**: Administra sitios que siempre se bloquearán o permitirán
- **Nivel de análisis de descargas**: Define la profundidad del análisis para archivos descargados

### Configuración del Escudo de Correo

- **Clientes de correo**: Selecciona qué programas de correo proteger
- **Análisis de adjuntos**: Define qué tipos de archivos adjuntos analizar
- **Filtro de spam**: Configura la sensibilidad de la detección de correo no deseado
- **Escaneo de enlaces**: Activa o desactiva la verificación de enlaces en los correos

### Configuración del Escudo de Comportamiento

- **Sensibilidad**: Ajusta la sensibilidad para detectar comportamientos sospechosos
- **Áreas protegidas**: Define qué partes del sistema estarán bajo monitoreo especial
- **Protección contra ransomware**: Configura la respuesta a intentos de cifrado
- **Aplicaciones confiables**: Administra programas que se consideran seguros

### Configuración del Firewall

- **Modo de operación**: Elige entre automático o basado en reglas
- **Redes confiables**: Define las redes que se consideran seguras
- **Reglas personalizadas**: Crea reglas específicas para aplicaciones o conexiones
- **Notificaciones**: Configura alertas sobre eventos de conexión

## Exclusiones

Las exclusiones te permiten definir archivos, carpetas o procesos que no serán analizados por la protección en tiempo real. Esto es útil para mejorar el rendimiento o evitar falsos positivos.

### Cuándo usar exclusiones

- **Aplicaciones confiables** que son incorrectamente detectadas como amenazas
- **Herramientas de desarrollo** que modifican muchos archivos (compiladores, IDEs)
- **Carpetas de datos** con muchos archivos que cambian frecuentemente
- **Archivos de gran tamaño** que no representan riesgo (videos, bases de datos)

### Cómo añadir exclusiones

1. Ve a "Configuración" > "Protección en Tiempo Real" > "Exclusiones"
2. Haz clic en "Añadir exclusión"
3. Selecciona el tipo de exclusión:
   - Archivo específico
   - Carpeta completa
   - Extensión de archivo
   - Proceso o aplicación
4. Selecciona o introduce la ruta del elemento
5. Opcionalmente, añade condiciones (solo para lectura, por hash, etc.)
6. Guarda la exclusión

### Mejores prácticas para exclusiones

- **Usa el mínimo necesario**: Cada exclusión reduce tu nivel de protección
- **Sé específico**: Excluye solo los elementos necesarios, no carpetas enteras si no es preciso
- **Revisa regularmente**: Elimina exclusiones que ya no sean necesarias
- **Considera alternativas**: A veces ajustar la configuración de protección es mejor que usar exclusiones

## Notificaciones

Amaru te mantiene informado sobre las amenazas detectadas y las acciones tomadas mediante notificaciones.

### Tipos de notificaciones

- **Amenaza detectada**: Cuando se identifica y bloquea una amenaza
- **Acción requerida**: Cuando se necesita tu intervención
- **Estado de protección**: Alertas sobre cambios en el estado de protección
- **Actualizaciones**: Información sobre actualizaciones de la base de virus
- **Resumen periódico**: Informes regulares sobre la actividad de protección

### Configuración de notificaciones

1. Ve a "Configuración" > "Notificaciones"
2. Selecciona qué tipos de eventos generarán notificaciones
3. Define el formato de notificación:
   - Notificaciones del sistema
   - Ventanas emergentes de Amaru
   - Mensajes en la bandeja del sistema
   - Correos electrónicos (para alertas críticas)
4. Establece el nivel de detalle de las notificaciones

### Modo No Molestar

Para situaciones donde necesitas concentración sin interrupciones:

1. Haz clic derecho en el icono de Amaru en la bandeja del sistema
2. Selecciona "Modo No Molestar"
3. Elige la duración (30 minutos, 1 hora, 2 horas, hasta nuevo aviso)

La protección seguirá activa, pero se suprimirán las notificaciones no críticas.

## Respuesta a Amenazas

Cuando la protección en tiempo real detecta una amenaza, puede responder de diferentes maneras según tu configuración.

### Acciones automáticas

- **Bloquear**: Impide el acceso al archivo o recurso malicioso
- **Poner en cuarentena**: Aísla el archivo para evitar daños
- **Eliminar**: Borra permanentemente el archivo infectado
- **Reparar**: Intenta eliminar el código malicioso del archivo
- **Denegar acceso a la red**: Bloquea conexiones maliciosas

### Intervención del usuario

En algunos casos, se te pedirá que decidas qué hacer:

1. Se mostrará una notificación con detalles de la amenaza
2. Tendrás opciones para:
   - Poner en cuarentena o eliminar la amenaza
   - Ignorar la advertencia (no recomendado)
   - Añadir a exclusiones (solo si estás seguro de que es un falso positivo)
   - Ver más detalles sobre la amenaza

### Registro de eventos

Todas las detecciones y acciones se registran para futuras referencias:

1. Ve a "Informes" > "Registro de Protección"
2. Filtra por:
   - Tipo de amenaza
   - Componente de protección
   - Acción tomada
   - Periodo de tiempo
3. Exporta el registro si necesitas compartirlo con soporte técnico

## Solución de Problemas

Si experimentas problemas con la protección en tiempo real, aquí hay algunas soluciones para los problemas más comunes.

### Alto consumo de recursos

Si Amaru está utilizando demasiada CPU o memoria:

1. Ve a "Configuración" > "Protección en Tiempo Real"
2. Reduce el nivel de protección a "Medio" o "Bajo"
3. Ajusta la configuración del escudo de archivos:
   - Limita los tipos de archivos analizados
   - Reduce el nivel de análisis heurístico
4. Añade exclusiones para carpetas con muchos archivos que cambien frecuentemente

### Conflictos con otras aplicaciones

Si algunas aplicaciones no funcionan correctamente con la protección activa:

1. Identifica qué componente causa el conflicto desactivando temporalmente cada escudo
2. Añade la aplicación a la lista de exclusiones
3. Actualiza la aplicación problemática a la última versión
4. Verifica si hay actualizaciones disponibles para Amaru Antivirus

### Falsos positivos

Si archivos legítimos son detectados erróneamente como amenazas:

1. Ve a "Cuarentena" para verificar si el archivo está allí
2. Selecciona el archivo y elige "Restaurar y añadir a exclusiones"
3. Reporta el falso positivo al equipo de Amaru usando la opción "Reportar"
4. Actualiza la base de virus a la última versión

### La protección se desactiva sola

Si la protección en tiempo real se desactiva inesperadamente:

1. Verifica si hay otro software de seguridad instalado que pueda causar conflictos
2. Comprueba los registros del sistema para identificar errores
3. Asegúrate de que Amaru tiene los permisos necesarios del sistema
4. Reinstala Amaru Antivirus si el problema persiste

## Preguntas Frecuentes

### ¿Puedo desactivar temporalmente la protección?

Sí, puedes desactivar la protección en tiempo real temporalmente:

1. Haz clic derecho en el icono de Amaru en la bandeja del sistema
2. Selecciona "Desactivar protección en tiempo real"
3. Elige la duración (10 minutos, 30 minutos, 1 hora)

La protección se reactivará automáticamente después del tiempo seleccionado. No es recomendable desactivarla por períodos prolongados.

### ¿La protección en tiempo real afecta el rendimiento de juegos o aplicaciones exigentes?

El impacto en el rendimiento es mínimo, pero si experimentas problemas:

1. Activa el "Modo juego" desde el icono de la bandeja del sistema antes de jugar
2. Añade la carpeta de tus juegos a las exclusiones (solo si es necesario)
3. Programa los análisis completos cuando no estés usando el equipo

### ¿Cómo sé si la protección está funcionando correctamente?

Puedes verificar el estado de la protección de varias formas:

1. El icono en la bandeja del sistema debe mostrar un escudo verde
2. En la ventana principal, verás el estado de cada componente
3. En "Informes" podrás ver el registro de actividad reciente
4. Puedes usar el "Test de protección" seguro desde el menú "Herramientas"

### ¿La protección en tiempo real analiza dispositivos externos?

Sí, cuando conectas un dispositivo USB o disco externo:

1. El Escudo de Archivos analizará automáticamente cualquier archivo al que se acceda
2. Opcionalmente, puedes configurar un análisis automático de todo el dispositivo
3. Las mismas reglas de exclusión pueden aplicarse a dispositivos externos

### ¿Qué hacer si la protección bloquea un programa que necesito usar?

Si estás seguro de que el programa es seguro:

1. Restaura el archivo de la cuarentena si fue bloqueado
2. Añade el programa a la lista de exclusiones
3. Añade el desarrollador a la lista de "Proveedores confiables"
4. Reporta el falso positivo al equipo de Amaru

---

Para más información sobre la protección en tiempo real, consulta nuestra [documentación técnica](../technical/realtime-engine.md) o contacta con nuestro [equipo de soporte](../support/contact.md) si tienes preguntas específicas. 