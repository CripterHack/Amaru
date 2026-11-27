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
  !error "EXEDIR must reference the Cargo release output. Use scripts/package.ps1."
!endif

; Configuración del instalador
Name "${PRODUCT_NAME}"
OutFile "${OUTDIR}\AmaruAV-Setup.exe"
InstallDir "$PROGRAMFILES64\${PRODUCT_NAME}"
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
Var Previous32Dir

; Older installers stored InstallLocation with quotes. Treat it only as data.
Function ReadInstallLocation
  ReadRegStr $0 HKLM "${PRODUCT_UNINST_KEY}" "InstallLocation"
  StrCpy $1 $0 1
  StrCpy $2 $0 1 -1
  ${If} $1 == '"'
  ${AndIf} $2 == '"'
    StrCpy $0 $0 -1 1
  ${EndIf}
FunctionEnd

Function SelectUpgradeLocation
  SetRegView 32
  Call ReadInstallLocation
  StrCpy $Previous32Dir $0
  SetRegView 64
  Call ReadInstallLocation
  StrCpy $PreviousInstallDir $0
  ${If} $PreviousInstallDir == ""
    StrCpy $PreviousInstallDir $Previous32Dir
  ${ElseIf} $Previous32Dir != ""
  ${AndIf} $Previous32Dir != $PreviousInstallDir
    MessageBox MB_OK|MB_ICONSTOP "Se encontraron dos instalaciones registradas en carpetas diferentes. Revise ambas antes de actualizar." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}

  ; Use the known Program Files location for a standard legacy installation.
  ; Custom locations must be selected on the directory page or supplied via /D.
  ${If} $PreviousInstallDir == "$PROGRAMFILES32\${PRODUCT_NAME}"
    StrCpy $INSTDIR "$PROGRAMFILES32\${PRODUCT_NAME}"
  ${EndIf}
FunctionEnd

Function CheckUpgradeLocation
  ${If} $PreviousInstallDir != ""
  ${AndIf} $PreviousInstallDir != $INSTDIR
    MessageBox MB_OK|MB_ICONSTOP "Para actualizar la instalación existente, seleccione su misma carpeta. En modo silencioso, indique la carpeta con /D." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
FunctionEnd

; Configuración de la interfaz
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\amaru.exe"
!define MUI_FINISHPAGE_RUN_NOTCHECKED
!define MUI_FINISHPAGE_RUN_TEXT "Iniciar Amaru Antivirus ahora"

; Usar iconos personalizados si están disponibles
!define MUI_ICON "amaru-app.ico"
!define MUI_UNICON "amaru-app.ico"
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
  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP "Este instalador requiere Windows de 64 bits."
    Abort
  ${EndIf}
  ; Asegurar que no haya múltiples instancias del instalador
  System::Call 'kernel32::CreateMutexA(i 0, i 0, t "AmaruAntivirusInstaller") i .r1 ?e'
  Pop $R0
  ${If} $R0 != 0
    MessageBox MB_OK|MB_ICONEXCLAMATION "El instalador de Amaru Antivirus ya está en ejecución."
    Abort
  ${EndIf}

  Call SelectUpgradeLocation
FunctionEnd

; Sección principal de instalación
Section "Instalación" SEC_MAIN
  Call CheckUpgradeLocation
  SetOutPath "$INSTDIR"
  File "${EXEDIR}\amaru.exe"
  SetOverwrite off
  File "..\config.toml"
  SetOverwrite on
  
  ; Crear estructura de directorios usando SetOutPath, que es más seguro
  SetOutPath "$INSTDIR\config"
  SetOutPath "$INSTDIR\signatures\official"
  File /r "..\signatures\official\*"
  SetOutPath "$INSTDIR\signatures\custom"
  SetOverwrite off
  File /r "..\signatures\custom\*"
  SetOverwrite on
  SetOutPath "$INSTDIR\modules"
  SetOutPath "$INSTDIR\logs"
  SetOutPath "$INSTDIR\quarantine"
  
  ; Configuración de ambiente si es necesario
  ${IfNot} ${FileExists} "$INSTDIR\.env"
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
  ${EndIf}
  
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
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "NoModify" "1"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "NoRepair" "1"
  
  ; Registrar en el inicio automático - dos métodos para mayor seguridad
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}" "$\"$INSTDIR\amaru.exe$\""
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}" "$\"$INSTDIR\amaru.exe$\""
  
  ; Migrate registration only after writing its replacement in the native view.
  ${If} $Previous32Dir != ""
    SetRegView 32
    DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
    DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}"
    SetRegView 64
  ${EndIf}

  ; Crear accesos directos
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortcut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" "$INSTDIR\amaru.exe"
  CreateShortcut "$SMPROGRAMS\${PRODUCT_NAME}\Desinstalar ${PRODUCT_NAME}.lnk" "$INSTDIR\uninstall.exe"
  CreateShortcut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\amaru.exe"
SectionEnd

; Sección de desinstalación
Section "Uninstall"
  SetRegView 64
  ; Detener el proceso antes de desinstalar
  ExecWait '"$SYSDIR\taskkill.exe" /F /IM amaru.exe'
  
  ; Eliminar accesos directos
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Desinstalar ${PRODUCT_NAME}.lnk"
  Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT_NAME}"
  
  ; Borrar archivos principales
  Delete "$INSTDIR\amaru.exe"
  Delete "$INSTDIR\uninstall.exe"
  RMDir /r "$INSTDIR\modules"
  RMDir /r "$INSTDIR\signatures\official"

  ; Silent uninstall keeps recoverable user data. An interactive purge requires consent.
  MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "¿Desea borrar también la cuarentena, los registros, la configuración y las firmas personalizadas?" /SD IDNO IDNO keep_data
  Delete "$INSTDIR\.env"
  Delete "$INSTDIR\config.toml"
  RMDir /r "$INSTDIR\config"
  RMDir /r "$INSTDIR\signatures"
  RMDir /r "$INSTDIR\logs"
  RMDir /r "$INSTDIR\quarantine"
  SetShellVarContext all
  RMDir /r "$APPDATA\${PRODUCT_NAME}"
  SetShellVarContext current
  keep_data:

  ; Limpiar el directorio principal
  RMDir "$INSTDIR"
  
  ; Limpiar registros completamente
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}"
  
  ; Limpiar cualquier otra entrada que pueda quedar
  DeleteRegKey HKCU "Software\${PRODUCT_NAME}"
  DeleteRegKey HKLM "Software\${PRODUCT_NAME}"
  
  ; Mostrar mensaje de desinstalación completa
  MessageBox MB_OK|MB_ICONINFORMATION "Se ha desinstalado Amaru Antivirus." /SD IDOK
SectionEnd 