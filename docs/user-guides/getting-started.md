# Guía de inicio rápido de Amaru Antivirus

Amaru reúne el escáner nativo y la línea de comandos en `amaru.exe`. La interfaz de escritorio se ejecuta con `amaru-antivirus.exe`. Para comprobar una instalación, prueba el catálogo de firmas, analiza una carpeta conocida y consulta el estado del servicio por separado.

## Requisitos del sistema

El objetivo de escritorio es Windows 11 de 64 bits. El proyecto indica 4 GB de RAM y 1 GB de espacio libre como mínimos y recomienda 8 GB de RAM, 2 GB libres y SSD. La interfaz necesita Microsoft Edge WebView2 Runtime. La instalación y la administración del servicio requieren permisos de administrador. [Requisitos del proyecto](../../README.md) · [Requisitos del instalador](../../installer/README.md)

## Instalación

1. Comprueba en GitHub Releases si existe una versión publicada. Para evaluar una compilación de desarrollo, utiliza el artefacto del flujo de Windows de la revisión elegida y conserva su identificador.
2. Comprueba que Windows tenga WebView2 Runtime. Ejecuta el instalador de desarrollo con permisos de administrador en el equipo de evaluación. Consulta las instrucciones del paquete si necesitas construirlo desde el repositorio.
3. Abre la carpeta de instalación y comprueba la firma EICAR del catálogo desde PowerShell.

```powershell
.\amaru.exe test-eicar
.\amaru.exe service --action status
```

La primera comprobación usa una muestra benigna y un control limpio en memoria. La segunda consulta al administrador de servicios de Windows. La activación comercial pertenece al diseño de producto. [Versiones](https://github.com/CripterHack/Amaru/releases) · [Compilaciones de Windows](https://github.com/CripterHack/Amaru/actions/workflows/windows-build.yml) · [Preparación y validación del paquete](../../installer/README.md)

## Primeros pasos

Abre **Amaru Antivirus** desde el acceso creado por el instalador o ejecuta `amaru-antivirus.exe`. El panel principal consulta al servicio para mostrar **Real-time Protection**. En **Scan** puedes lanzar análisis, revisar su progreso y consultar sesiones anteriores. **Quarantine** muestra los elementos aislados por el motor de escritorio.

## Realizar un primer escaneo

1. Prepara una carpeta accesible con un archivo de texto de contenido conocido.
2. En **Scan**, selecciona **Start Custom scan** y elige esa carpeta.
3. Espera a que termine la sesión. Revisa los contadores de analizados, omitidos y fallidos junto con los hallazgos.

También puedes pasar el archivo directamente a la CLI.

```powershell
.\amaru.exe scan --path "C:\Amaru-Pruebas\documento.txt"
```

Para verificar la regla EICAR instalada, utiliza `test-eicar`. Para comprobar la vigilancia continua, realiza además la prueba con una carpeta vigilada explicada en la guía del monitor. [Guía de análisis](./analyzing.md) · [Protección en tiempo real](./real-time-protection.md)

## Configurar la protección en tiempo real

En el TOML de la instancia del servicio, revisa las rutas vigiladas, las extensiones y las exclusiones. Tras cambiar el archivo, reinicia el servicio para que lea los valores. Desde el panel, **Real-time Protection** permite cambiar la vigilancia de la instancia en ejecución con los permisos correspondientes. La política predeterminada informa de las detecciones y mantiene el archivo en origen. [Configuración del monitor](./real-time-protection.md#configuración) · [Cuarentena](./quarantine.md)

## Solución de problemas comunes

| Síntoma | Comprobación |
| --- | --- |
| El instalador indica que falta WebView2 | Instala el runtime de Microsoft y repite la instalación. |
| El panel indica que el servicio no está disponible | Consulta `amaru.exe service --action status`, el estado del servicio de Windows y los permisos de la cuenta. |
| La prueba EICAR falla | Revisa qué configuración cargó el comando y que el catálogo instalado contenga la regla de prueba. |
| La sesión terminó con errores | Conserva la ruta, el mensaje y el estado parcial. Comprueba permisos, espacio y límites configurados. |
| Aparece un hallazgo inesperado | Anota regla, SHA-256 y versión de Amaru. Consulta el procedimiento para revisar un falso positivo. |

[Preguntas frecuentes](./faq.md) · [Gestión de falsos positivos](./quarantine.md#cómo-gestiono-un-falso-positivo)

## Flujos previstos

El diseño contempla un asistente de primera ejecución, activación mediante cuenta o clave comercial, perfiles de protección y servicios de soporte integrados. La disponibilidad y la validación de esos recorridos se documentarán con su entrega. [Estado de desarrollo](../../status_development.md)
