# Preguntas Frecuentes (FAQ)

Consulta el alcance de la versión que estás evaluando, los artefactos de desarrollo y las validaciones de Windows. [Estado del proyecto](../../status_development.md) · [Distribución](../../README.md)

## Índice

1. [Información General](#información-general)
2. [Instalación y Activación](#instalación-y-activación)
3. [Análisis y Protección](#análisis-y-protección)
4. [Actualizaciones](#actualizaciones)
5. [Cuarentena y Amenazas](#cuarentena-y-amenazas)
6. [Rendimiento](#rendimiento)
7. [Licencias y Planes](#licencias-y-planes)
8. [Privacidad y Datos](#privacidad-y-datos)
9. [Desinstalación](#desinstalación)
10. [Soporte Técnico](#soporte-técnico)

## Información General

### ¿Qué es Amaru Antivirus?

Amaru es un antivirus experimental de código abierto para Windows 11. El motor analiza archivos con reglas YARA, heurística y análisis estático de PE. Puede usar Radare2 cuando está instalado. El monitor de archivos alimenta el mismo motor y el escritorio Tauri/Svelte muestra sesiones y cuarentena. [Estado del desarrollo](../../status_development.md)

### ¿En qué sistemas operativos funciona Amaru Antivirus?

El objetivo del producto es Windows 11 de 64 bits. El soporte para Windows anteriores, sistemas de 32 bits, macOS, Linux, Android e iOS requiere sus propias implementaciones y pruebas. Algunas herramientas para desarrolladores pueden ejecutarse por separado en Linux. [Requisitos del proyecto](../../README.md)

### ¿Qué diferencia a Amaru de otros antivirus?

Puedes inspeccionar el código y las reglas, añadir firmas personalizadas y repetir pruebas de detección en archivos locales. La evaluación con YARA-X dispone de una herramienta independiente. El aprendizaje automático, las actualizaciones desde la nube y la gestión centralizada forman parte del diseño a validar. [Reglas](../../signatures) · [Prueba con YARA-X](../technical/yara-x.md)

### ¿Amaru Antivirus reemplaza al Firewall de Windows?

El diseño de Amaru se centra en los archivos y sus indicadores de amenaza. El cortafuegos de Windows mantiene su función de control del tráfico de red.

## Instalación y Activación

### ¿Cómo instalo Amaru Antivirus?

Consulta las versiones publicadas y los artefactos del flujo de Windows para la revisión que quieras probar. El instalador de desarrollo incluye el escritorio, el núcleo, la CLI y el catálogo. Para registrar el servicio requiere una ubicación protegida. [Instalación](./getting-started.md#instalación) · [Guía del instalador](../../installer/README.md) · [GitHub Releases](https://github.com/CripterHack/Amaru/releases)

### ¿Debo desinstalar otro antivirus antes de instalar Amaru?

Mantén activa tu protección habitual. Usa un entorno de pruebas para evaluar la versión experimental. La coexistencia con otros productos y la herramienta de limpieza propuesta requieren validación en Windows.

### ¿Cómo activo mi licencia de Amaru?

El código del repositorio se distribuye bajo GPL v2. Para consultar el código y ejecutar las pruebas puedes usar el repositorio directamente. El flujo de activación con clave o cuenta pertenece al diseño de posibles servicios comerciales. [Licencia](../../LICENSE)

### He perdido mi clave de licencia, ¿cómo puedo recuperarla?

La recuperación por correo o desde una cuenta se contempla para posibles licencias comerciales. El repositorio público es el punto de acceso actual al código. [Proyecto Amaru](https://github.com/CripterHack/Amaru)

## Análisis y Protección

### ¿Qué tipos de análisis ofrece Amaru?

El escritorio ofrece análisis rápido, completo de la unidad del sistema y personalizado de una carpeta. La CLI analiza un archivo o directorio. YARA-X permite comprobar el catálogo con una herramienta independiente. [Guía de análisis](./analyzing.md) · [Escáner YARA-X](../technical/yara-x.md)

### ¿Con qué frecuencia debo realizar un análisis completo?

Elige una frecuencia según el volumen de datos, el uso del equipo y el tiempo disponible. La tarea de usuario integrada admite análisis rápidos o de una ruta concreta con frecuencia diaria o semanal. El análisis completo puede iniciarse desde el escritorio. [Análisis programados](./analyzing.md#análisis-programados)

### ¿La protección en tiempo real está siempre activa?

El servicio carga la vigilancia según su configuración de arranque. Consulta **Real-time Protection** en el panel y verifica la carpeta que quieres vigilar. Para comprobar el recorrido completo, usa una muestra benigna en una ruta admitida y revisa el evento y la acción aplicada. [Guía del monitor](./real-time-protection.md)

### ¿Amaru protege contra ransomware?

El catálogo incluye reglas de ransomware y el motor puede encontrar indicadores estáticos en un archivo. Revisa la regla o el comportamiento que motivó la detección. La protección de carpetas frente al cifrado activo y la recuperación desde copias temporales forman parte del diseño pendiente. [Firmas de ransomware](../../signatures/official/ransomware.yar)

## Actualizaciones

### ¿Con qué frecuencia se actualiza Amaru?

Los cambios de desarrollo se publican en GitHub. El diseño distingue actualizaciones de firmas, correcciones de seguridad y versiones de la aplicación. La frecuencia de un servicio de distribución aún está por establecer. [Guía de actualizaciones](./updates.md)

### ¿Las actualizaciones son automáticas?

El comando `amaru.exe update --rules` comprueba el manifiesto y aplica un paquete más reciente si supera las verificaciones. Requiere una URL HTTPS y la clave pública confiable configurada. El motor verifica los hashes, las firmas Ed25519 y la compilación de las reglas antes de activar el catálogo. La opción `auto_update` controla qué hace la comprobación del núcleo al encontrar una versión nueva. [Actualizador](../../updater) · [Guía de actualizaciones](./updates.md)

### ¿Las actualizaciones consumen mucho ancho de banda?

El diseño contempla actualizaciones incrementales y opciones para conexiones limitadas. El tamaño transferido dependerá del paquete publicado y de la versión instalada. La primera distribución permitirá medirlo.

### Mi Amaru no se actualiza, ¿qué puedo hacer?

Comprueba primero que existe un paquete publicado para tu versión. En un entorno de desarrollo, registra la versión, el comando y el error exacto. Con esa información se puede distinguir un fallo de la herramienta de la falta de un canal de distribución. [Versiones](https://github.com/CripterHack/Amaru/releases) · [Guía de actualización](./updates.md#solución-de-problemas)

## Cuarentena y Amenazas

### ¿Qué sucede cuando Amaru detecta una amenaza?

El motor genera un hallazgo. En el escritorio puedes revisarlo y confirmar su aislamiento. La vigilancia conserva el original por defecto. Con `auto_quarantine = true` intenta aislar las detecciones de riesgo alto o crítico tras verificar su contenido. [Guía de cuarentena](./quarantine.md)

### ¿Cómo recupero un archivo de la cuarentena?

En **Quarantine**, selecciona la entrada y confirma **Restore Selected**. El motor verifica el contenido y lo devuelve a la ruta original cuando está disponible. La restauración conserva las reglas de vigilancia vigentes. [Restaurar](./quarantine.md#restaurar)

### ¿Qué debo hacer si creo que tengo un falso positivo?

Abre un issue e incluye el identificador de la regla, la versión o revisión de Amaru y una descripción del resultado esperado. Una muestra sintética reproducible permite evaluar el caso. El formulario integrado de falsos positivos figura entre los flujos previstos. [GitHub Issues](https://github.com/CripterHack/Amaru/issues)

### ¿Amaru puede detectar todos los virus?

Las pruebas EICAR documentan qué muestras de prueba reconoce una firma concreta. Para estimar la detección de amenazas reales y los falsos positivos hacen falta corpus representativos y evaluaciones reproducibles. El proyecto tiene pendiente esa medición. [Cobertura EICAR](../technical/eicar-corpus.md)

## Rendimiento

### ¿Amaru ralentizará mi computadora?

El uso eficiente de CPU, memoria y disco forma parte del diseño. La repercusión sobre el equipo depende del volumen de archivos, las reglas y el tipo de análisis. Las mediciones comparables en Windows están pendientes. [Pruebas de rendimiento del repositorio](../../tests/performance_tests.rs)

### ¿Cómo puedo mejorar el rendimiento si noto ralentización?

Para delimitar el problema, anota el hardware, la ruta, el número y tamaño de archivos, las reglas y la duración. Compara una carpeta concreta con el análisis rápido y revisa las carpetas programadas. Un análisis completo puede recorrer muchos más archivos. [Guía de análisis](./analyzing.md)

### ¿Puedo usar Amaru en un equipo con recursos limitados?

El objetivo mínimo documentado es Windows 11 de 64 bits con 4 GB de RAM y 1 GB de espacio libre. El proyecto recomienda 8 GB de RAM, 2 GB de espacio y una unidad SSD. El perfil ligero propuesto requiere mediciones separadas. [Requisitos](../../README.md)

### ¿Amaru afecta el rendimiento de los juegos o aplicaciones exigentes?

El modo de juego propuesto pospondría tareas, limitaría notificaciones y ajustaría la frecuencia de escaneo. Su activación automática y su efecto en aplicaciones a pantalla completa quedan por verificar.

## Licencias y Planes

### ¿Qué planes de licencia ofrece Amaru?

El proyecto declara GPL v2 para su código. La documentación de producto contempla Free, Essential, Premium, Ultimate y Business, con distintos números de dispositivos y opciones de gestión. La disponibilidad comercial y sus condiciones están pendientes de confirmación. [Licencia del repositorio](../../LICENSE)

### ¿Puedo transferir mi licencia a otro dispositivo?

El uso y redistribución del código se rigen por GPL v2. La transferencia a otro equipo mediante una cuenta y un límite de dispositivos corresponde al diseño de suscripciones. [GNU GPL v2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.es.html)

### ¿Qué sucede cuando expira mi licencia?

La licencia del código fuente es GPL v2. Los avisos de caducidad, la renovación y el paso a un plan gratuito se plantean para una futura suscripción comercial. [Licencia](../../LICENSE)

### ¿Ofrecen reembolso si no estoy satisfecho?

La propuesta comercial contempla un plazo de 30 días. La publicación de una oferta con vendedor identificado, condiciones de compra y procedimiento de reembolso está pendiente.

## Privacidad y Datos

### ¿Qué datos recopila Amaru?

El análisis nativo lee los archivos seleccionados. El escritorio almacena en el perfil local registros de sesión que pueden incluir rutas, fechas, SHA-256, detecciones y errores. La cuarentena conserva el archivo cifrado y su catálogo. La consulta de actualizaciones se comunica con el servidor configurado. [Historial local](../../gui/src-tauri/src/session.rs) · [Cuarentena](./quarantine.md) · [Actualizador](../../updater)

### ¿Amaru comparte mis datos con terceros?

La documentación de diseño contempla proveedores de soporte, servicios de pago e intercambio voluntario de indicadores de amenazas. Los destinatarios y las condiciones aplicables deberán identificarse al habilitar esos servicios.

### ¿Cómo desactivo la recopilación de datos?

Las opciones previstas incluyen gestión del consentimiento para muestras, estadísticas y protección en la nube, además de solicitudes de borrado. La disponibilidad de controles efectivos deberá comprobarse en la versión que introduzca esos servicios.

### ¿Amaru cumple con el GDPR?

La minimización de datos, el consentimiento para los envíos opcionales y la atención de derechos de privacidad son objetivos del diseño. Para afirmar conformidad con el RGPD hace falta evaluar el tratamiento real y publicar la información aplicable.

## Desinstalación

### ¿Cómo desinstalo Amaru Antivirus?

Cierra la aplicación y usa el desinstalador de esa instalación de Windows. Antes de quitar datos, revisa si debes recuperar archivos de la cuarentena. El instalador describe qué componentes y tareas retira y qué datos conserva según el modo elegido. [Guía del instalador](../../installer/README.md)

### ¿Qué sucede con mi licencia si desinstalo Amaru?

Puedes volver a obtener el código fuente bajo los términos de GPL v2. La persistencia de una activación personal en otros equipos pertenece al diseño de las suscripciones comerciales.

### ¿Cómo elimino completamente Amaru y todos sus archivos?

Las pruebas del instalador deben comprobar qué archivos, registros, servicios y elementos de cuarentena conserva o retira la desinstalación. Una herramienta de limpieza completa está prevista y requiere validar también la recuperación de datos antes de publicarse.

## Soporte Técnico

### ¿Cómo contacto al soporte técnico?

Para incidencias reproducibles sobre el proyecto, indica la revisión de Amaru, la versión del sistema y los pasos que producen el fallo. El canal público actual es GitHub Issues. El chat, el teléfono y el formulario comercial figuran en el diseño de soporte. [GitHub Issues](https://github.com/CripterHack/Amaru/issues) · [Contacto](../support/contact.md)

### ¿El soporte técnico está disponible en mi idioma?

La documentación se mantiene en español e inglés. La planificación de soporte contempla además francés, alemán, portugués, italiano y ruso. Los horarios y tiempos de respuesta dependerán de los servicios que lleguen a publicarse.

### ¿Hay algún foro de usuarios donde pueda obtener ayuda?

Puedes consultar incidencias, proponer mejoras y compartir resultados reproducibles en el repositorio. La apertura de un foro dedicado sigue pendiente de confirmación. [GitHub Issues](https://github.com/CripterHack/Amaru/issues)

### ¿Ofrecen soporte remoto?

La propuesta de los planes Premium y Ultimate contempla sesiones de asistencia remota con autorización del usuario. Su disponibilidad, los canales para solicitar una sesión y las condiciones de acceso quedan por confirmar. [Contacto del proyecto](../support/contact.md)

## Funciones y servicios previstos

Los perfiles de juego, el análisis de memoria y arranque, los servicios comerciales con cuenta y facturación, la asistencia remota y el envío voluntario de muestras pertenecen al diseño del producto. Su disponibilidad, condiciones y pruebas de funcionamiento se documentarán con las versiones que los integren. [Estado de desarrollo](../../status_development.md)
