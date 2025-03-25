# Guía de Inicio Rápido de Amaru Antivirus

¡Bienvenido a Amaru Antivirus! Esta guía te ayudará a comenzar a utilizar nuestro software de protección contra malware, explicando la instalación básica, configuración inicial y primeros pasos.

## Índice

1. [Requisitos del Sistema](#requisitos-del-sistema)
2. [Instalación](#instalación)
3. [Primeros Pasos](#primeros-pasos)
4. [Realizar un Primer Escaneo](#realizar-un-primer-escaneo)
5. [Configurar la Protección en Tiempo Real](#configurar-la-protección-en-tiempo-real)
6. [Configuración Recomendada](#configuración-recomendada)
7. [Solución de Problemas Comunes](#solución-de-problemas-comunes)

## Requisitos del Sistema

Antes de instalar Amaru Antivirus, asegúrate de que tu sistema cumple con los siguientes requisitos:

- **Sistema Operativo**: Windows 10 o Windows 11 (64-bit)
- **Procesador**: 2 GHz dual-core o superior
- **Memoria**: 4 GB RAM mínimo (8 GB recomendado)
- **Espacio en Disco**: 500 MB para la instalación
- **Conexión a Internet**: Requerida para actualizaciones
- **Resolución de Pantalla**: 1280 x 720 o superior

## Instalación

1. **Descarga el Instalador**:
   - Visita [www.amaru-antivirus.com/download](https://www.amaru-antivirus.com/download)
   - Selecciona la versión más reciente para tu sistema operativo
   - Descarga el archivo `amaru-installer.exe`

2. **Ejecuta el Instalador**:
   - Haz clic derecho en el archivo descargado y selecciona "Ejecutar como administrador"
   - Si aparece una advertencia de Windows Defender, haz clic en "Más información" y luego en "Ejecutar de todos modos"

3. **Sigue el Asistente de Instalación**:
   - Selecciona el idioma de instalación
   - Lee y acepta los términos de licencia
   - Elige la ubicación de instalación (se recomienda mantener la ubicación predeterminada)
   - Selecciona los componentes a instalar:
     - Protección del Sistema (obligatorio)
     - Protección del Navegador (recomendado)
     - Análisis Heurístico (recomendado)

4. **Finaliza la Instalación**:
   - Haz clic en "Instalar" y espera a que se complete el proceso
   - Cuando finalice, selecciona "Iniciar Amaru Antivirus" y haz clic en "Finalizar"

![Pantalla de instalación](../assets/images/installation-screen.png)

## Primeros Pasos

Al iniciar Amaru Antivirus por primera vez, se realizará una configuración inicial:

1. **Asistente de Bienvenida**:
   - Selecciona si deseas enviar datos anónimos para mejorar el producto
   - Decide si quieres recibir notificaciones sobre actualizaciones y consejos

2. **Actualización Inicial**:
   - El sistema descargará las definiciones de virus más recientes
   - Este proceso puede tardar unos minutos dependiendo de tu conexión a internet

3. **Configuración de la Protección**:
   - La protección en tiempo real se activa automáticamente
   - Se configuran las carpetas que serán monitoreadas por defecto

## Realizar un Primer Escaneo

Es recomendable realizar un escaneo completo del sistema después de la instalación:

1. **Inicia un Escaneo Completo**:
   - En la pantalla principal, haz clic en el botón "Escaneo"
   - Selecciona "Escaneo Completo" de las opciones disponibles
   - Haz clic en "Iniciar Escaneo"

2. **Durante el Escaneo**:
   - Puedes ver el progreso en tiempo real
   - El escaneo completo puede tardar entre 30 minutos y varias horas, dependiendo del tamaño de tu disco y la cantidad de archivos
   - Puedes continuar usando tu computadora durante el escaneo, aunque podría funcionar un poco más lento

3. **Revisar Resultados**:
   - Al finalizar, se mostrará un resumen con los archivos analizados y las amenazas encontradas
   - Si se encuentran amenazas, se recomendarán acciones para cada una
   - Puedes elegir entre cuarentena, eliminación o ignorar para cada archivo

![Pantalla de escaneo](../assets/images/scan-screen.png)

## Configurar la Protección en Tiempo Real

La protección en tiempo real es tu primera línea de defensa contra malware:

1. **Accede a la Configuración**:
   - Haz clic en el icono de engranaje en la esquina superior derecha
   - Selecciona "Protección en Tiempo Real"

2. **Ajusta el Nivel de Protección**:
   - **Estándar** (predeterminado): Equilibrio entre protección y rendimiento
   - **Alto**: Mayor protección, puede afectar ligeramente al rendimiento
   - **Personalizado**: Configura manualmente qué eventos monitorear

3. **Configura Exclusiones**:
   - Puedes añadir archivos, carpetas o procesos que deseas excluir del análisis en tiempo real
   - Útil para aplicaciones de confianza que generan falsos positivos

4. **Activa el Análisis Heurístico**:
   - Esta función permite detectar amenazas nuevas o desconocidas basándose en su comportamiento
   - Recomendado para una protección más completa

## Configuración Recomendada

Para la mayoría de los usuarios, recomendamos:

- **Protección en Tiempo Real**: Activada
- **Nivel de Protección**: Estándar
- **Análisis Heurístico**: Activado
- **Escaneo Programado**: Semanal (configúralo en un momento en que tu computadora esté encendida pero no la estés usando intensivamente)
- **Actualizaciones Automáticas**: Activadas

Para equipos con hardware limitado o antiguo:

- **Protección en Tiempo Real**: Activada
- **Nivel de Protección**: Estándar
- **Análisis Heurístico**: Desactivado
- **Escaneo Programado**: Mensual
- **Modo de Bajo Impacto**: Activado (en Configuración > Rendimiento)

## Solución de Problemas Comunes

### El programa se inicia lentamente

- Verifica si hay otros programas antivirus instalados (no se recomienda tener más de uno)
- Comprueba el modo de inicio en Configuración > General > Inicio

### Alto uso de recursos

- Activa el "Modo de Bajo Impacto" en Configuración > Rendimiento
- Reduce la frecuencia de escaneos programados
- Excluye del análisis las carpetas de programas confiables que accedes con frecuencia

### Falsos Positivos

Si Amaru detecta como amenaza un archivo que sabes que es seguro:

1. Ve a "Cuarentena" en el menú principal
2. Selecciona el archivo marcado erróneamente
3. Selecciona "Restaurar y Excluir" para añadirlo a la lista de exclusiones

### Problemas de Actualización

Si las actualizaciones fallan:

1. Verifica tu conexión a internet
2. Asegúrate de que el firewall no está bloqueando a Amaru
3. Intenta actualizar manualmente desde Configuración > Actualizaciones > Actualizar Ahora

## Próximos Pasos

Ahora que has configurado Amaru Antivirus, te recomendamos:

- Explorar las opciones avanzadas en el panel de configuración
- Revisar la guía completa de usuario para conocer todas las funcionalidades
- Configurar el escaneo programado según tus necesidades
- Familiarizarte con la sección de Cuarentena para gestionar amenazas

Si necesitas ayuda adicional, consulta nuestra [documentación completa](../index.md) o ponte en contacto con nuestro [soporte técnico](../support/contact.md).

---

¿Esta guía te resultó útil? [Envíanos tus comentarios](mailto:feedback@amaru-antivirus.com) para ayudarnos a mejorarla. 