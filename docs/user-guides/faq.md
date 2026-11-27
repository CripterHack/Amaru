# Preguntas Frecuentes (FAQ)

Bienvenido a las Preguntas Frecuentes de Amaru Antivirus. Aquí encontrarás respuestas a las dudas más comunes sobre la versión experimental y su diseño.

Las funciones, planes comerciales y canales de soporte descritos corresponden al alcance previsto. Consulta el estado de la versión experimental y el canal de distribución en el [README](../../README.md).

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

Amaru es un proyecto experimental de antivirus de código abierto para Windows 11. Combina reglas YARA y análisis estático con Radare2. El proyecto desarrolla también la monitorización de archivos y una interfaz de escritorio con Tauri y Svelte. [Estado del desarrollo](../../status_development.md)

### ¿En qué sistemas operativos funciona Amaru Antivirus?

El objetivo del producto es Windows 11 de 64 bits. El soporte para Windows anteriores, sistemas de 32 bits, macOS, Linux, Android e iOS requiere sus propias implementaciones y pruebas. Algunas herramientas para desarrolladores pueden ejecutarse por separado en Linux. [Requisitos del proyecto](../../README.md)

### ¿Qué diferencia a Amaru de otros antivirus?

Puedes inspeccionar el código y las reglas, añadir firmas personalizadas y repetir pruebas de detección en archivos locales. La evaluación con YARA-X dispone de una herramienta independiente. El aprendizaje automático, las actualizaciones desde la nube y la gestión centralizada forman parte del diseño a validar. [Reglas](../../signatures) · [Prueba con YARA-X](../technical/yara-x.md)

### ¿Amaru Antivirus reemplaza al Firewall de Windows?

El diseño de Amaru se centra en los archivos y sus indicadores de amenaza. El cortafuegos de Windows mantiene su función de control del tráfico de red.

## Instalación y Activación

### ¿Cómo instalo Amaru Antivirus?

A fecha del 27 de noviembre de 2026 está pendiente la primera distribución publicada y validada para Windows. El repositorio describe la preparación del entorno de desarrollo y el flujo de instalación previsto. [Instalación](./getting-started.md#instalación) · [GitHub Releases](https://github.com/CripterHack/Amaru/releases)

### ¿Debo desinstalar otro antivirus antes de instalar Amaru?

Mantén activa tu protección habitual. Usa un entorno de pruebas para evaluar la versión experimental. La coexistencia con otros productos y la herramienta de limpieza propuesta requieren validación en Windows.

### ¿Cómo activo mi licencia de Amaru?

El código del repositorio se distribuye bajo GPL v2. Para consultar el código y ejecutar las pruebas puedes usar el repositorio directamente. El flujo de activación con clave o cuenta pertenece al diseño de posibles servicios comerciales. [Licencia](../../LICENSE)

### He perdido mi clave de licencia, ¿cómo puedo recuperarla?

La recuperación por correo o desde una cuenta se contempla para posibles licencias comerciales. El repositorio público es el punto de acceso actual al código. [Proyecto Amaru](https://github.com/CripterHack/Amaru)

## Análisis y Protección

### ¿Qué tipos de análisis ofrece Amaru?

La herramienta YARA-X permite analizar un archivo local con las reglas del proyecto. La interfaz proyecta análisis rápidos, completos, personalizados, de unidades extraíbles y de arranque. La validación de esos modos en Windows se registra por separado. [Escáner local](../technical/yara-x.md) · [Guía de análisis](./analyzing.md)

### ¿Con qué frecuencia debo realizar un análisis completo?

La programación de análisis completos está pendiente de integración en la aplicación. La guía contempla análisis periódicos y comprobaciones tras restaurar copias de seguridad o conectar medios extraíbles. La frecuencia adecuada depende del uso del equipo.

### ¿La protección en tiempo real está siempre activa?

La vigilancia continua es un objetivo del monitor. Para acreditarla en un sistema instalado se debe verificar el arranque del servicio, la recepción de eventos, el análisis y la notificación. [Guía de protección en tiempo real](./realtime-protection.md)

### ¿Amaru protege contra ransomware?

El catálogo contiene firmas de ransomware. Que una regla compile permite probarla en archivos concretos. El bloqueo del cifrado, la protección de carpetas y la recuperación mediante copias temporales requieren validación independiente. [Firmas de ransomware](../../signatures/official/ransomware.yar)

## Actualizaciones

### ¿Con qué frecuencia se actualiza Amaru?

Los cambios de desarrollo se publican en GitHub. El diseño distingue actualizaciones de firmas, correcciones de seguridad y versiones de la aplicación. La frecuencia de un servicio de distribución aún está por establecer. [Guía de actualizaciones](./updates.md)

### ¿Las actualizaciones son automáticas?

El actualizador y sus pruebas forman parte del repositorio. Las preferencias para programar comprobaciones, seleccionar una frecuencia o limitar descargas según la conexión describen el flujo previsto. La configuración efectiva en un cliente instalado sigue pendiente de verificación. [Componente de actualización](../../updater)

### ¿Las actualizaciones consumen mucho ancho de banda?

El diseño contempla actualizaciones incrementales y opciones para conexiones limitadas. El tamaño transferido dependerá del paquete publicado y de la versión instalada. La primera distribución permitirá medirlo.

### Mi Amaru no se actualiza, ¿qué puedo hacer?

Comprueba primero que existe un paquete publicado para tu versión. En un entorno de desarrollo, registra la versión, el comando y el error exacto. Con esa información se puede distinguir un fallo de la herramienta de la falta de un canal de distribución. [Versiones](https://github.com/CripterHack/Amaru/releases) · [Guía de actualización](./updates.md#solución-de-problemas)

## Cuarentena y Amenazas

### ¿Qué sucede cuando Amaru detecta una amenaza?

El escáner YARA-X escribe los nombres de las reglas coincidentes. El diseño de la aplicación prevé avisar, registrar la detección y aplicar una acción configurada como bloqueo o cuarentena. La secuencia completa en Windows requiere una prueba de extremo a extremo. [Escaneo con YARA-X](../technical/yara-x.md) · [Diseño de cuarentena](./quarantine.md)

### ¿Cómo recupero un archivo de la cuarentena?

La guía de cuarentena describe cómo seleccionar un elemento, restaurarlo o añadir una exclusión. La recuperación tras instalar la aplicación en Windows está pendiente de validación. [Guía de cuarentena](./quarantine.md)

### ¿Qué debo hacer si creo que tengo un falso positivo?

Abre un issue e incluye el identificador de la regla, la versión o revisión de Amaru y una descripción del resultado esperado. Una muestra sintética reproducible permite evaluar el caso. El formulario integrado de falsos positivos figura entre los flujos previstos. [GitHub Issues](https://github.com/CripterHack/Amaru/issues)

### ¿Amaru puede detectar todos los virus?

Las pruebas EICAR documentan qué muestras de prueba reconoce una firma concreta. Para estimar la detección de amenazas reales y los falsos positivos hacen falta corpus representativos y evaluaciones reproducibles. El proyecto tiene pendiente esa medición. [Cobertura EICAR](../technical/eicar-corpus.md)

## Rendimiento

### ¿Amaru ralentizará mi computadora?

El uso eficiente de CPU, memoria y disco forma parte del diseño. La repercusión sobre el equipo depende del volumen de archivos, las reglas y el tipo de análisis. Las mediciones comparables en Windows están pendientes. [Pruebas de rendimiento del repositorio](../../tests/performance_tests.rs)

### ¿Cómo puedo mejorar el rendimiento si noto ralentización?

Para investigar una ralentización en una prueba, registra el hardware, el número y tamaño de los archivos, las reglas usadas y el tiempo transcurrido. El diseño contempla horarios, exclusiones y perfiles de rendimiento. Su efecto debe medirse en la versión evaluada.

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

El escáner local de YARA-X lee el archivo indicado y escribe los identificadores de las reglas que coinciden. Para la aplicación, el diseño distingue registros de diagnóstico, datos de licencia y envíos opcionales de muestras o estadísticas. La evaluación de privacidad del producto completo requiere revisar qué datos procesa cada versión y dónde se conservan. [Escáner local](../../scripts/scan_yarax.py)

### ¿Amaru comparte mis datos con terceros?

La documentación de diseño contempla proveedores de soporte, servicios de pago e intercambio voluntario de indicadores de amenazas. Los destinatarios y las condiciones aplicables deberán identificarse al habilitar esos servicios.

### ¿Cómo desactivo la recopilación de datos?

Las opciones previstas incluyen gestión del consentimiento para muestras, estadísticas y protección en la nube, además de solicitudes de borrado. La disponibilidad de controles efectivos deberá comprobarse en la versión que introduzca esos servicios.

### ¿Amaru cumple con el GDPR?

La minimización de datos, el consentimiento para los envíos opcionales y la atención de derechos de privacidad son objetivos del diseño. Para afirmar conformidad con el RGPD hace falta evaluar el tratamiento real y publicar la información aplicable.

## Desinstalación

### ¿Cómo desinstalo Amaru Antivirus?

El desinstalador previsto para Windows se iniciará desde Aplicaciones instaladas. La instalación y la retirada completas necesitan validación con un paquete publicado. El soporte para macOS y la herramienta avanzada de desinstalación pertenecen a propuestas posteriores. [Instalador del proyecto](../../installer/README.md)

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
