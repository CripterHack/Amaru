; Script unificado para Amaru Antivirus
; Implementado siguiendo mejores prácticas de NSIS y principios SOLID
Unicode true
!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"

; Definiciones del producto
!define PRODUCT_NAME "Amaru Antivirus"
!define PRODUCT_VERSION "1.0.0"
!define PUBLISHER "Amaru Security Team"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\amaru.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define REGKEY "SOFTWARE\Amaru Antivirus"

; Verificar que se pasaron los parámetros requeridos o usar valores por defecto
!ifndef OUTDIR
  !define OUTDIR "."
!endif

!ifndef LICENSEFILE
  !define LICENSEFILE "license.txt"
!endif

!ifndef EXEDIR
  !define EXEDIR "."
!endif

; Configuración del instalador
Name "${PRODUCT_NAME}"
OutFile "${OUTDIR}\AmaruAV-Setup.exe"
InstallDir "$PROGRAMFILES\${PRODUCT_NAME}"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
RequestExecutionLevel admin

; Información del producto
VIProductVersion "${PRODUCT_VERSION}.0"
VIAddVersionKey "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "LegalCopyright" "© 2025 ${PUBLISHER}"
VIAddVersionKey "FileDescription" "Instalador de ${PRODUCT_NAME}"
VIAddVersionKey "FileVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "ProductVersion" "${PRODUCT_VERSION}"

; Variables
Var PreviousInstallDir
Var PreviousIsX86

; Configuración de la interfaz
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\amaru.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Iniciar Amaru Antivirus ahora"

; Usar iconos personalizados si están disponibles
!define MUI_ICON "${EXEDIR}\amaru-app.ico"
!define MUI_UNICON "${EXEDIR}\amaru-app.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Header\win.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Wizard\win.bmp"

; Definir páginas del instalador
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${LICENSEFILE}"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Definir páginas del desinstalador
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Definir idioma
!insertmacro MUI_LANGUAGE "Spanish"

; Función de inicialización
Function .onInit
  ; Asegurar que no haya múltiples instancias del instalador
  System::Call 'kernel32::CreateMutexA(i 0, i 0, t "AmaruAntivirusInstaller") i .r1 ?e'
  Pop $R0
  ${If} $R0 != 0
    MessageBox MB_OK|MB_ICONEXCLAMATION "El instalador de Amaru Antivirus ya está en ejecución."
    Abort
  ${EndIf}

  ; Buscar instalaciones previas en diferentes ubicaciones
  
  ; Primero en la ruta estándar de 64 bits
  ReadRegStr $PreviousInstallDir HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "InstallLocation"
  ${If} $PreviousInstallDir != ""
    StrCpy $PreviousIsX86 "0"
    ; Mostrar diálogo de desinstalación previa
    MessageBox MB_YESNO|MB_ICONQUESTION "Se ha detectado una instalación previa de Amaru Antivirus en:$\n$PreviousInstallDir$\n$\n¿Desea desinstalarla antes de continuar?" IDYES uninstall_previous
    Goto skip_uninstall
    
    uninstall_previous:
      ; Cerrar cualquier instancia en ejecución
      ExecWait 'taskkill /F /IM amaru.exe'
      DetailPrint "Desinstalando versión previa..."
      ReadRegStr $0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "UninstallString"
      ${If} $0 != ""
        ExecWait '"$0" /S _?=$PreviousInstallDir'
        ; Esperar a que termine la desinstalación
        Sleep 2000
      ${EndIf}
      
      ; Eliminar directorios y archivos manualmente por si acaso
      RMDir /r "$PreviousInstallDir"
      
      ; Limpiar registros
      DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
      DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}"
      DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}"
      
    skip_uninstall:
  ${EndIf}
  
  ; Luego en la ruta estándar de 32 bits
  ReadRegStr $PreviousInstallDir HKLM "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "InstallLocation"
  ${If} $PreviousInstallDir != ""
    StrCpy $PreviousIsX86 "1"
    ; Mostrar diálogo de desinstalación previa
    MessageBox MB_YESNO|MB_ICONQUESTION "Se ha detectado una instalación previa de Amaru Antivirus en:$\n$PreviousInstallDir$\n$\n¿Desea desinstalarla antes de continuar?" IDYES uninstall_previous_x86
    Goto skip_uninstall_x86
    
    uninstall_previous_x86:
      ; Cerrar cualquier instancia en ejecución
      ExecWait 'taskkill /F /IM amaru.exe'
      DetailPrint "Desinstalando versión previa (32 bits)..."
      ReadRegStr $0 HKLM "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "UninstallString"
      ${If} $0 != ""
        ExecWait '"$0" /S _?=$PreviousInstallDir'
        ; Esperar a que termine la desinstalación
        Sleep 2000
      ${EndIf}
      
      ; Eliminar directorios y archivos manualmente por si acaso
      RMDir /r "$PreviousInstallDir"
      
      ; Limpiar registros
      DeleteRegKey HKLM "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
      DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}"
      DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}"
      
    skip_uninstall_x86:
  ${EndIf}
  
  ; También verificar instalaciones en el disco D
  ${If} ${FileExists} "D:\Program Files\${PRODUCT_NAME}\uninstall.exe"
    StrCpy $PreviousInstallDir "D:\Program Files\${PRODUCT_NAME}"
    MessageBox MB_YESNO|MB_ICONQUESTION "Se ha detectado una instalación de Amaru Antivirus en disco D:$\n$PreviousInstallDir$\n$\n¿Desea desinstalarla antes de continuar?" IDYES uninstall_driveD
    Goto skip_driveD
    
    uninstall_driveD:
      ; Cerrar cualquier instancia en ejecución
      ExecWait 'taskkill /F /IM amaru.exe'
      DetailPrint "Desinstalando versión en disco D..."
      ExecWait '"$PreviousInstallDir\uninstall.exe" /S _?=$PreviousInstallDir'
      ; Esperar a que termine la desinstalación
      Sleep 2000
      
      ; Eliminar directorios y archivos manualmente
      RMDir /r "$PreviousInstallDir"
      
    skip_driveD:
  ${EndIf}
  
  ; Eliminar las entradas persistentes en el registro
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}"
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}"
  
  ; Detectar arquitectura del sistema y ajustar ruta si es necesario
  ${If} ${RunningX64}
    ; En 64 bits, usar la ruta estándar
    StrCpy $INSTDIR "$PROGRAMFILES64\${PRODUCT_NAME}"
  ${Else}
    ; En 32 bits, usar Program Files (x86)
    StrCpy $INSTDIR "$PROGRAMFILES32\${PRODUCT_NAME}"
  ${EndIf}
FunctionEnd

; Sección principal de instalación
Section "Instalación" SEC_MAIN
  SetOutPath "$INSTDIR"
  File "${EXEDIR}\amaru.exe"
  
  ; Crear estructura de directorios usando SetOutPath, que es más seguro
  SetOutPath "$INSTDIR\config"
  SetOutPath "$INSTDIR\signatures"
  SetOutPath "$INSTDIR\modules"
  SetOutPath "$INSTDIR\logs"
  SetOutPath "$INSTDIR\quarantine"
  
  ; Crear archivo .env con rutas correctas si viene de installer.nsi
  ${If} ${FileExists} "${EXEDIR}\config.toml"
    File /oname=$INSTDIR\config.toml "${EXEDIR}\config.toml"
  ${EndIf}
  
  ; Configuración de ambiente si es necesario
  FileOpen $0 "$INSTDIR\.env" w
  FileWrite $0 "# Configuración generada por el instalador$\r$\n"
  FileWrite $0 "AMARU_ROOT=$INSTDIR$\r$\n"
  FileWrite $0 "YARA_RULES_PATH=$INSTDIR\signatures$\r$\n"
  FileWrite $0 "QUARANTINE_PATH=$INSTDIR\quarantine$\r$\n"
  FileWrite $0 "LOGS_PATH=$INSTDIR\logs$\r$\n"
  ${If} ${RunningX64}
    FileWrite $0 "SYSTEM_ARCH=x64$\r$\n"
  ${Else}
    FileWrite $0 "SYSTEM_ARCH=x86$\r$\n"
  ${EndIf}
  FileWrite $0 "ENABLE_REALTIME_PROTECTION=true$\r$\n"
  FileWrite $0 "ENABLE_HEURISTIC_ANALYSIS=true$\r$\n"
  FileWrite $0 "LOW_RESOURCE_MODE=false$\r$\n"
  FileClose $0
  
  ; Volver a la carpeta principal
  SetOutPath "$INSTDIR"
  
  ; Crear uninstalador mejorado
  WriteUninstaller "$INSTDIR\uninstall.exe"
  
  ; Registrar información del programa
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayIcon" "$\"$INSTDIR\amaru.exe$\""
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "InstallLocation" "$\"$INSTDIR$\""
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "NoModify" "1"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "NoRepair" "1"
  
  ; Registrar en el inicio automático - dos métodos para mayor seguridad
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}" "$\"$INSTDIR\amaru.exe$\""
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}" "$\"$INSTDIR\amaru.exe$\""
  
  ; Crear accesos directos
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortcut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" "$INSTDIR\amaru.exe"
  CreateShortcut "$SMPROGRAMS\${PRODUCT_NAME}\Desinstalar ${PRODUCT_NAME}.lnk" "$INSTDIR\uninstall.exe"
  CreateShortcut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\amaru.exe"
SectionEnd

; Sección para iniciar la aplicación después de la instalación
Section -Post
  ExecShell "" "$INSTDIR\amaru.exe"
SectionEnd

; Sección de desinstalación
Section "Uninstall"
  ; Detener el proceso antes de desinstalar
  ExecWait 'taskkill /F /IM amaru.exe'
  
  ; Eliminar accesos directos
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Desinstalar ${PRODUCT_NAME}.lnk"
  Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT_NAME}"
  
  ; Borrar archivos principales
  Delete "$INSTDIR\amaru.exe"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$INSTDIR\.env"
  Delete "$INSTDIR\config.toml"
  
  ; Borrar directorios de datos
  RMDir /r "$INSTDIR\config"
  RMDir /r "$INSTDIR\signatures"
  RMDir /r "$INSTDIR\modules"
  RMDir /r "$INSTDIR\logs"
  RMDir /r "$INSTDIR\quarantine"
  
  ; Eliminar datos persistentes usando la variable de sistema adecuada
  ${If} ${RunningX64}
    RMDir /r "$PROGRAMDATA\${PRODUCT_NAME}"
  ${Else}
    RMDir /r "$APPDATA\${PRODUCT_NAME}"
  ${EndIf}
  
  ; Limpiar el directorio principal
  RMDir /r "$INSTDIR"
  
  ; Limpiar registros completamente
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
  DeleteRegKey HKLM "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}"
  
  ; Limpiar cualquier otra entrada que pueda quedar
  DeleteRegKey HKCU "Software\${PRODUCT_NAME}"
  DeleteRegKey HKLM "Software\${PRODUCT_NAME}"
  
  ; Mostrar mensaje de desinstalación completa
  MessageBox MB_OK|MB_ICONINFORMATION "Amaru Antivirus ha sido completamente desinstalado del sistema."
SectionEnd 