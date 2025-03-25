# Gestión de la Cuarentena

La cuarentena es una herramienta fundamental en Amaru Antivirus que te permite aislar archivos potencialmente peligrosos en un entorno seguro, impidiendo que dañen tu sistema mientras decides qué hacer con ellos.

## Índice

1. [¿Qué es la Cuarentena?](#qué-es-la-cuarentena)
2. [Acceso a la Cuarentena](#acceso-a-la-cuarentena)
3. [Elementos en Cuarentena](#elementos-en-cuarentena)
4. [Acciones con Archivos en Cuarentena](#acciones-con-archivos-en-cuarentena)
5. [Configuración de la Cuarentena](#configuración-de-la-cuarentena)
6. [Gestión Automática](#gestión-automática)
7. [Cuarentena y Protección en Tiempo Real](#cuarentena-y-protección-en-tiempo-real)
8. [Preguntas Frecuentes](#preguntas-frecuentes)

## ¿Qué es la Cuarentena?

La cuarentena es un área aislada y segura donde Amaru Antivirus almacena archivos sospechosos o maliciosos. Cuando un archivo se pone en cuarentena:

- Se cifra y aísla para que no pueda ejecutarse ni infectar otros archivos
- Se mantiene bajo vigilancia para futuras decisiones
- Se conserva información detallada sobre su origen, comportamiento y nivel de amenaza

La cuarentena proporciona un equilibrio entre la seguridad (eliminar archivos potencialmente dañinos) y la precaución (evitar eliminar archivos que puedan ser falsos positivos o importantes).

## Acceso a la Cuarentena

Puedes acceder a la cuarentena de Amaru Antivirus de las siguientes maneras:

### Desde la Interfaz Principal

1. Abre Amaru Antivirus
2. Haz clic en el botón "Cuarentena" en el panel de navegación lateral
3. Alternativamente, puedes ir a "Herramientas" > "Cuarentena"

### Desde el Icono de la Bandeja del Sistema

1. Haz clic derecho en el icono de Amaru Antivirus en la bandeja del sistema
2. Selecciona "Abrir Cuarentena" en el menú contextual

### Desde la Notificación de Detección

Cuando Amaru detecta y pone en cuarentena un archivo, aparecerá una notificación. Puedes:
- Hacer clic en "Ver en Cuarentena" en la notificación para ir directamente a ese elemento
- Hacer clic en "Detalles" para ver más información sobre la amenaza detectada

## Elementos en Cuarentena

Al abrir la cuarentena, verás una lista de todos los elementos aislados con la siguiente información:

- **Nombre del archivo**: Nombre original del archivo infectado
- **Ruta**: Ubicación original en el sistema antes de ser puesto en cuarentena
- **Tipo de amenaza**: El malware o tipo de amenaza identificado
- **Nivel de riesgo**: Clasificación de la gravedad (Alto, Medio, Bajo)
- **Fecha de detección**: Cuándo fue detectado y puesto en cuarentena
- **Tamaño**: Tamaño del archivo
- **Estado**: Estado actual (En cuarentena, Pendiente de análisis, etc.)
- **Origen**: Cómo fue detectado (Análisis programado, Protección en tiempo real, etc.)

### Vista Detallada

Para ver información detallada sobre un elemento específico:

1. Selecciona el elemento en la lista
2. Haz clic en el botón "Detalles" o doble clic en el elemento
3. Se abrirá una ventana con información avanzada:
   - Hash del archivo (MD5, SHA1, SHA256)
   - Comportamiento detectado
   - Técnicas de evasión utilizadas (si corresponde)
   - Actividades sospechosas registradas
   - Programas o procesos afectados

## Acciones con Archivos en Cuarentena

Desde la interfaz de cuarentena, puedes realizar varias acciones con los archivos aislados:

### Restaurar

Si crees que un archivo es un falso positivo o necesitas acceder a él:

1. Selecciona el archivo en la lista de cuarentena
2. Haz clic en el botón "Restaurar"
3. Selecciona una de las siguientes opciones:
   - **Restaurar y excluir**: Devuelve el archivo a su ubicación original y lo añade a la lista de exclusiones
   - **Restaurar solo**: Devuelve el archivo a su ubicación original sin excluirlo de futuros análisis
   - **Restaurar a...**: Te permite elegir una nueva ubicación para el archivo restaurado

**Nota de seguridad**: Solo restaura archivos cuando estés absolutamente seguro de que son seguros o cuando el soporte técnico te lo indique.

### Eliminar

Para eliminar permanentemente un archivo en cuarentena:

1. Selecciona el archivo o archivos
2. Haz clic en el botón "Eliminar"
3. Confirma la acción en el diálogo de confirmación

**Importante**: La eliminación es permanente y no se puede deshacer.

### Enviar a Análisis

Si no estás seguro sobre la naturaleza de un archivo:

1. Selecciona el archivo
2. Haz clic en "Enviar a análisis"
3. El archivo se enviará al laboratorio de Amaru para un análisis más profundo
4. Recibirás una notificación con los resultados (esto puede tardar entre 24-48 horas)

### Analizar de Nuevo

Para volver a analizar un archivo con las últimas definiciones de virus:

1. Selecciona el archivo
2. Haz clic en "Volver a analizar"
3. Amaru analizará el archivo con las definiciones más recientes y actualizará su estado

### Acciones por Lotes

Puedes realizar acciones en múltiples archivos simultáneamente:

1. Selecciona varios archivos manteniendo pulsada la tecla Ctrl mientras haces clic
2. Utiliza Ctrl+A para seleccionar todos los elementos
3. Haz clic derecho y selecciona la acción deseada en el menú contextual

## Configuración de la Cuarentena

Amaru te permite personalizar el comportamiento de la cuarentena según tus necesidades:

### Ajustes Generales

Para acceder a la configuración:

1. Abre Amaru Antivirus
2. Ve a "Configuración" > "Protección" > "Cuarentena"

Opciones disponibles:

- **Ubicación de cuarentena**: Cambia la ubicación donde se almacenan los archivos en cuarentena (requiere permisos de administrador)
- **Tamaño máximo**: Establece el espacio máximo para la cuarentena (por defecto 1 GB)
- **Compresión**: Activa/desactiva la compresión de archivos en cuarentena para ahorrar espacio

### Retención de Archivos

Puedes configurar cuánto tiempo se conservan los archivos en cuarentena:

- **Retención automática**: Elimina automáticamente los archivos después de un período específico
  - 7 días (predeterminado)
  - 30 días
  - 90 días
  - Indefinidamente (no eliminar automáticamente)
- **Notificación de eliminación**: Recibe una notificación antes de que se eliminen archivos automáticamente

## Gestión Automática

Amaru ofrece opciones para gestionar automáticamente los archivos en cuarentena:

### Reglas Automáticas

Puedes crear reglas para gestionar automáticamente ciertos tipos de amenazas:

1. Ve a "Configuración" > "Protección" > "Cuarentena" > "Reglas automáticas"
2. Haz clic en "Añadir nueva regla"
3. Configura los criterios:
   - **Tipo de amenaza**: Por ejemplo, "Troyano", "Adware", "PUP" (Programas potencialmente no deseados)
   - **Nivel de riesgo**: Alto, Medio o Bajo
   - **Acción automática**: Eliminar después de X días, Enviar a análisis, etc.

### Programación de Limpieza

Configura la limpieza programada de la cuarentena:

1. Ve a "Configuración" > "Protección" > "Cuarentena" > "Programación"
2. Activa "Limpieza automática"
3. Establece la frecuencia: Diaria, Semanal o Mensual
4. Configura qué tipos de amenazas se eliminarán automáticamente

## Cuarentena y Protección en Tiempo Real

La protección en tiempo real de Amaru trabaja en conjunto con la cuarentena:

### Configuración de Respuesta Automática

Puedes configurar cómo responde automáticamente Amaru a diferentes tipos de amenazas:

1. Ve a "Configuración" > "Protección en tiempo real" > "Respuesta a amenazas"
2. Para cada tipo de amenaza, selecciona la acción predeterminada:
   - **Poner en cuarentena**: Aísla automáticamente (predeterminado para la mayoría de amenazas)
   - **Preguntar**: Consulta qué hacer cuando se detecta
   - **Bloquear**: Impide el acceso sin mover a cuarentena
   - **Reparar si es posible**: Intenta limpiar el archivo primero, si no es posible, lo pone en cuarentena
   - **Ignorar**: No realiza ninguna acción (no recomendado)

### Notificaciones

Personaliza las notificaciones relacionadas con la cuarentena:

1. Ve a "Configuración" > "General" > "Notificaciones"
2. Activa o desactiva las siguientes opciones:
   - Mostrar notificación cuando se pone un archivo en cuarentena
   - Mostrar resumen diario de actividad de cuarentena
   - Alertar cuando la cuarentena alcance cierto porcentaje de capacidad

## Preguntas Frecuentes

### ¿Los archivos en cuarentena ocupan mucho espacio?

No. Los archivos se comprimen y cifran, lo que normalmente reduce su tamaño. Además, puedes configurar un límite máximo para el espacio utilizado.

### ¿Puedo perder archivos importantes en cuarentena?

Sí, es posible que haya falsos positivos. Por eso Amaru no elimina automáticamente los archivos y te permite restaurarlos. Si recibes una alerta sobre un archivo que sabes que es seguro, puedes restaurarlo desde la cuarentena.

### ¿La cuarentena es 100% segura?

Sí. Los archivos en cuarentena están cifrados y no pueden ejecutarse ni infectar otros archivos mientras permanezcan allí.

### ¿Qué ocurre si restauro un archivo malicioso por error?

Si restauras un archivo malicioso, la protección en tiempo real de Amaru debería detectarlo nuevamente si intentas ejecutarlo. Sin embargo, es recomendable tener cuidado al restaurar archivos y solo hacerlo cuando estés seguro de su seguridad.

### ¿Por qué algunos archivos se ponen automáticamente en cuarentena?

La protección en tiempo real de Amaru puede poner archivos en cuarentena automáticamente cuando:
- Detecta comportamiento malicioso
- Identifica firmas de virus conocidos
- Detecta actividad sospechosa mediante el análisis heurístico

### ¿Cómo gestiono un falso positivo?

Si crees que un archivo es un falso positivo:
1. Restaura el archivo (opción "Restaurar y excluir")
2. Reporta el falso positivo a nuestro equipo utilizando la opción "Reportar falso positivo"
3. Añade el archivo a las exclusiones para evitar futuras detecciones

### ¿Puedo programar la limpieza automática de la cuarentena?

Sí, como se explica en la sección "Programación de Limpieza", puedes configurar Amaru para que limpie automáticamente la cuarentena según una programación específica y basándose en el tipo y edad de las amenazas.

---

La gestión adecuada de la cuarentena es una parte importante de tu estrategia de seguridad. Te recomendamos revisar periódicamente los elementos en cuarentena y mantener actualizado Amaru Antivirus para una protección óptima. 