# Cambios Realizados en el Sistema de Instalación

## Resumen de Cambios

Se ha implementado un sistema de instalación unificado que resuelve los problemas de sincronización entre los scripts NSIS y PowerShell. Los principales cambios incluyen:

1. **Unificación de Scripts NSIS**:
   - Se creó `unified_installer.nsi` combinando las funcionalidades de `setup.nsi` e `installer.nsi`.
   - Se mantuvieron copias de seguridad de los scripts originales (*.nsi.bak).

2. **Mejoras en PowerShell (package.ps1)**:
   - Se actualizó para utilizar el nuevo script NSIS unificado.
   - Se implementó detección y gestión mejorada de iconos y recursos.
   - Se agregó creación automática de la licencia si no existe.
   - Se mejoró la gestión de errores y la detección del compilador NSIS.

3. **Sincronización de Parámetros**:
   - Se definieron parámetros consistentes entre package.ps1 y unified_installer.nsi.
   - Se implementaron valores por defecto para parámetros no definidos.
   - Se mejoró el manejo de rutas de archivos para evitar problemas de acceso.

4. **Herramienta de Verificación**:
   - Se creó el script `build_installer.ps1` para verificar la integración entre todos los componentes.
   - Implementa verificaciones previas al proceso de compilación.
   - Ofrece la posibilidad de crear un instalador de prueba tras la verificación.

5. **Documentación**:
   - Se creó un README.md explicando el funcionamiento del nuevo sistema.
   - Se documentaron los parámetros y el flujo de trabajo entre scripts.
   - Se incluyó una sección de resolución de problemas.

## Aspectos Técnicos

### Parámetros NSIS Unificados

El script unified_installer.nsi ahora acepta los siguientes parámetros desde package.ps1:

- `OUTDIR`: Directorio donde se generará el instalador
- `LICENSEFILE`: Ruta al archivo de licencia
- `EXEDIR`: Directorio donde se encuentran los recursos ejecutables

### Detección Mejorada de Recursos

Se mejoró el proceso de búsqueda de recursos necesarios:

- Búsqueda en múltiples ubicaciones para iconos, ejecutables y licencias
- Creación automática de recursos faltantes cuando es posible
- Copia de respaldo de los scripts originales

### Gestión de Arquitecturas

El script unificado ahora detecta automáticamente la arquitectura del sistema y ajusta las rutas de instalación según corresponda:

- 64 bits: `$PROGRAMFILES64\Amaru Antivirus`
- 32 bits: `$PROGRAMFILES32\Amaru Antivirus`

### Desinstalación Mejorada

Se implementó un proceso de desinstalación más robusto que:

- Detecta instalaciones previas en múltiples ubicaciones
- Detiene procesos en ejecución antes de la desinstalación
- Limpia completamente registros y archivos tras la desinstalación 