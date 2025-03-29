; Instalador para Amaru Antivirus
; Versión optimizada con soporte UTF-8 mejorado e integración de módulos
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

; Configuración del instalador
Name "${PRODUCT_NAME}"
OutFile "${OUTDIR}\AmaruAV-Setup.exe"
; Asegurar la instalación en Program Files (x86) con ruta explícita
!define PROGRAMFILES_X86 "C:\Program Files (x86)"
InstallDir "${PROGRAMFILES_X86}\${PRODUCT_NAME}"
InstallDirRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\App Paths\amaru.exe" ""
RequestExecutionLevel admin

; Versiones
VIProductVersion "${PRODUCT_VERSION}.0"
VIAddVersionKey "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "LegalCopyright" "© 2025 ${PUBLISHER}"
VIAddVersionKey "FileDescription" "Instalador de ${PRODUCT_NAME}"
VIAddVersionKey "FileVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "ProductVersion" "${PRODUCT_VERSION}"

; Variables
Var PreviousInstallDir
Var IsUpdating
Var DoUninstall

; Configuración de la interfaz
!define MUI_ABORTWARNING
; Usar iconos personalizados si están disponibles
!define MUI_ICON "${EXEDIR}\amaru-app.ico"
!define MUI_UNICON "${EXEDIR}\amaru-app.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Header\win.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Wizard\win.bmp"

; Codificación para mejorar soporte de caracteres acentuados
!define SWP_NOSIZE 0x0001
!define SWP_NOMOVE 0x0002
!define SWP_NOZORDER 0x0004
!define SWP_NOACTIVATE 0x0010

; Página de finalización que ejecuta la aplicación
!define MUI_FINISHPAGE_RUN "$INSTDIR\amaru.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Iniciar Amaru Antivirus ahora"

; Páginas del instalador
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${LICENSEFILE}"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Páginas del desinstalador
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Idioma (asegurar soporte para caracteres acentuados)
!insertmacro MUI_LANGUAGE "Spanish"

; Inicialización
Function .onInit
  ; Inicializar variables
  StrCpy $IsUpdating "0"
  StrCpy $DoUninstall "0"
  
  ; Establecer explícitamente la ruta de instalación predeterminada
  ${If} ${RunningX64}
    StrCpy $INSTDIR "${PROGRAMFILES_X86}\${PRODUCT_NAME}"
  ${Else}
    StrCpy $INSTDIR "$PROGRAMFILES\${PRODUCT_NAME}"
  ${EndIf}
  
  ; Asegurar que no haya múltiples instancias del instalador
  System::Call 'kernel32::CreateMutexA(i 0, i 0, t "AmaruAntivirusInstaller") i .r1 ?e'
  Pop $R0
  ${If} $R0 != 0
    MessageBox MB_OK|MB_ICONEXCLAMATION "El instalador de Amaru Antivirus ya está en ejecución."
    Abort
  ${EndIf}
  
  ; Detectar instalación previa en registro standard
  ReadRegStr $R0 HKLM "${PRODUCT_UNINST_KEY}" "UninstallString"
  
  ${If} $R0 != ""
    ReadRegStr $PreviousInstallDir HKLM "${PRODUCT_UNINST_KEY}" "InstallLocation"
    ${If} $PreviousInstallDir != ""
      ; Preguntar al usuario qué hacer
      MessageBox MB_YESNO|MB_ICONQUESTION "Se ha detectado una instalación previa de ${PRODUCT_NAME}.$\n$\n¿Desea actualizarla?" IDYES update IDNO askUninstall
      
      update:
        StrCpy $IsUpdating "1"
        StrCpy $INSTDIR $PreviousInstallDir
        Goto endDecision
        
      askUninstall:
        MessageBox MB_YESNO|MB_ICONQUESTION "¿Desea desinstalar la versión anterior antes de continuar?" IDYES doUninstall IDNO endDecision
        
      doUninstall:
        StrCpy $DoUninstall "1"
        
      endDecision:
    ${EndIf}
  ${EndIf}
  
  ; Si hay que desinstalar, hacerlo ahora
  ${If} $DoUninstall == "1"
    ; Cerrar cualquier instancia en ejecución
    ExecWait 'taskkill /F /IM amaru.exe'
    DetailPrint "Desinstalando versión previa..."
    ExecWait '"$R0" /S _?=$PreviousInstallDir'
    ; Esperar a que termine
    Sleep 2000
    ; Limpiar registros
    DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
  ${EndIf}
  
  ; Buscar también en el registro WOW64 (para 32-bit en 64-bit Windows)
  ReadRegStr $R0 HKLM "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "UninstallString"
  ${If} $R0 != ""
  ${AndIf} $IsUpdating == "0"
    MessageBox MB_YESNO|MB_ICONQUESTION "Se ha detectado una instalación de 32 bits de ${PRODUCT_NAME}.$\n$\n¿Desea desinstalarla antes de continuar?" IDYES uninstallWow64 IDNO skipWow64
    
    uninstallWow64:
      ; Cerrar cualquier instancia en ejecución
      ExecWait 'taskkill /F /IM amaru.exe'
      DetailPrint "Desinstalando versión previa (32 bits)..."
      ExecWait '"$R0" /S'
      ; Esperar a que termine
      Sleep 2000
      ; Limpiar registros
      DeleteRegKey HKLM "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
    
    skipWow64:
  ${EndIf}

  ; Buscar otras instalaciones en disco D
  ${If} ${FileExists} "D:\Program Files\${PRODUCT_NAME}\uninstall.exe"
  ${AndIf} $IsUpdating == "0"
    MessageBox MB_YESNO|MB_ICONQUESTION "Se ha detectado una instalación en disco D:$\n$\n¿Desea desinstalarla antes de continuar?" IDYES uninstallDriveD IDNO skipDriveD
    
    uninstallDriveD:
      ; Cerrar cualquier instancia en ejecución
      ExecWait 'taskkill /F /IM amaru.exe'
      DetailPrint "Desinstalando versión del disco D..."
      ExecWait '"D:\Program Files\${PRODUCT_NAME}\uninstall.exe" /S'
      ; Esperar a que termine
      Sleep 2000
      
    skipDriveD:
  ${EndIf}
FunctionEnd

; Sección de instalación
Section "MainSection" SEC01
  SetOutPath "$INSTDIR"
  
  ; Si es actualización, primero cerrar cualquier instancia en ejecución
  ${If} $IsUpdating == "1"
    ExecWait 'taskkill /F /IM amaru.exe'
    Sleep 1000
  ${EndIf}
  
  ; Copiar archivos principales
  SetOverwrite on
  File "${EXEDIR}\amaru.exe"
  
  ; Copiar el icono si existe
  ${If} ${FileExists} "${EXEDIR}\amaru-app.ico"
    File "${EXEDIR}\amaru-app.ico"
  ${ElseIf} ${FileExists} "${EXEDIR}\amaru-isotipo-white.ico"
    File "${EXEDIR}\amaru-isotipo-white.ico"
  ${EndIf}
  
  ; Crear estructura de directorios para módulos
  CreateDirectory "$INSTDIR\modules"
  CreateDirectory "$INSTDIR\modules\yara-engine"
  CreateDirectory "$INSTDIR\modules\radare2-analyzer"
  CreateDirectory "$INSTDIR\modules\realtime-monitor"
  CreateDirectory "$INSTDIR\modules\clamav"
  CreateDirectory "$INSTDIR\signatures"
  CreateDirectory "$INSTDIR\signatures\custom"
  CreateDirectory "$INSTDIR\signatures\official"
  CreateDirectory "$INSTDIR\logs"
  CreateDirectory "$INSTDIR\quarantine"
  CreateDirectory "$INSTDIR\temp"
  
  ; Crear directorios comunes en ProgramData para archivos compartidos
  CreateDirectory "$PROGRAMDATA\Amaru"
  CreateDirectory "$PROGRAMDATA\Amaru\rules"
  CreateDirectory "$PROGRAMDATA\Amaru\db"
  
  ; Copiar archivos DLL y dependencias críticas
  ; YARA Engine
  ${If} ${FileExists} "${EXEDIR}\dist\yara\x64\libyara.dll"
    File /oname=$INSTDIR\modules\yara-engine\libyara.dll "${EXEDIR}\dist\yara\x64\libyara.dll"
  ${EndIf}
  
  ; Radare2
  ${If} ${FileExists} "${EXEDIR}\dist\radare2\x64\*.dll"
    File /oname=$INSTDIR\modules\radare2-analyzer\*.dll "${EXEDIR}\dist\radare2\x64\*.dll"
  ${EndIf}
  
  ; ClamAV/ClamWin
  ${If} ${FileExists} "${EXEDIR}\dist\clamav\x64\*.dll"
    File /oname=$INSTDIR\modules\clamav\*.dll "${EXEDIR}\dist\clamav\x64\*.dll"
  ${EndIf}
  
  ; Copiar archivos de configuración
  ${If} ${FileExists} "${EXEDIR}\config.toml"
    File /oname=$INSTDIR\config.toml "${EXEDIR}\config.toml"
  ${EndIf}
  
  ; Copiar reglas YARA
  ${If} ${FileExists} "${EXEDIR}\signatures\official\*.yar"
    File /oname=$INSTDIR\signatures\official\*.yar "${EXEDIR}\signatures\official\*.yar"
    ; También copiar a ProgramData para compatibilidad con rutas anteriores
    CopyFiles "$INSTDIR\signatures\official\*.yar" "$PROGRAMDATA\Amaru\rules\"
  ${EndIf}
  
  ; Copiar base de datos ClamAV si existe
  ${If} ${FileExists} "${EXEDIR}\dist\clamav\db\*.cvd"
    File /oname=$INSTDIR\modules\clamav\db\*.cvd "${EXEDIR}\dist\clamav\db\*.cvd"
    ; También copiar a ProgramData
    CopyFiles "$INSTDIR\modules\clamav\db\*.cvd" "$PROGRAMDATA\Amaru\db\"
  ${EndIf}
  
  ; Crear archivo .env con rutas correctas en Windows
  FileOpen $0 "$INSTDIR\.env" w
  FileWrite $0 "# Configuración generada por el instalador$\r$\n"
  FileWrite $0 "# Paths$\r$\n"
  FileWrite $0 "AMARU_ROOT=$INSTDIR$\r$\n"
  FileWrite $0 "AMARU_YARA_RULES_PATH=$INSTDIR\signatures$\r$\n"
  FileWrite $0 "AMARU_CUSTOM_RULES_PATH=$INSTDIR\signatures\custom$\r$\n"
  FileWrite $0 "AMARU_OFFICIAL_RULES_PATH=$INSTDIR\signatures\official$\r$\n"
  FileWrite $0 "AMARU_TEMP_PATH=$INSTDIR\temp$\r$\n"
  FileWrite $0 "AMARU_RADARE2_PATH=$INSTDIR\modules\radare2-analyzer$\r$\n"
  FileWrite $0 "$\r$\n# Compatibilidad con rutas antiguas$\r$\n"
  FileWrite $0 "CLAMWIN_NG_YARA_RULES_PATH=$PROGRAMDATA\Amaru\rules$\r$\n"
  FileWrite $0 "$\r$\n# Performance$\r$\n"
  FileWrite $0 "AMARU_MAX_THREADS=4$\r$\n"
  FileWrite $0 "AMARU_SCAN_MEMORY_LIMIT=512$\r$\n"
  FileWrite $0 "AMARU_FAST_SCAN=true$\r$\n"
  FileWrite $0 "$\r$\n# Logging$\r$\n"
  FileWrite $0 "RUST_LOG=info,amaru=debug$\r$\n"
  FileWrite $0 "AMARU_LOG_FILE=$INSTDIR\logs\amaru.log$\r$\n"
  FileWrite $0 "$\r$\n# Integration$\r$\n"
  FileWrite $0 "AMARU_CLAMAV_DB_PATH=$INSTDIR\modules\clamav\db$\r$\n"
  ${If} ${RunningX64}
    FileWrite $0 "SYSTEM_ARCH=x64$\r$\n"
  ${Else}
    FileWrite $0 "SYSTEM_ARCH=x86$\r$\n"
  ${EndIf}
  FileWrite $0 "ENABLE_REALTIME_PROTECTION=true$\r$\n"
  FileWrite $0 "ENABLE_HEURISTIC_ANALYSIS=true$\r$\n"
  FileWrite $0 "LOW_RESOURCE_MODE=false$\r$\n"
  FileClose $0
  
  ; Registrar en inicio automático
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}" "$INSTDIR\amaru.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}" "$INSTDIR\amaru.exe"
  
  ; Crear accesos directos
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  
  ; Usar icono personalizado si existe
  ${If} ${FileExists} "$INSTDIR\amaru-app.ico"
    CreateShortcut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" "$INSTDIR\amaru.exe" "" "$INSTDIR\amaru-app.ico"
    CreateShortcut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\amaru.exe" "" "$INSTDIR\amaru-app.ico"
  ${ElseIf} ${FileExists} "$INSTDIR\amaru-isotipo-white.ico"
    CreateShortcut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" "$INSTDIR\amaru.exe" "" "$INSTDIR\amaru-isotipo-white.ico"
    CreateShortcut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\amaru.exe" "" "$INSTDIR\amaru-isotipo-white.ico"
  ${Else}
    CreateShortcut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" "$INSTDIR\amaru.exe"
    CreateShortcut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\amaru.exe"
  ${EndIf}
  
  ; Registrar servicio Windows para protección en tiempo real
  ExecWait '"$INSTDIR\amaru.exe" service --action install'
  
  ; Crear desinstalador
  WriteUninstaller "$INSTDIR\uninstall.exe"
  
  ; Registrar información del programa
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\amaru.exe"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninstall.exe"
  
  ; Establecer el icono correcto
  ${If} ${FileExists} "$INSTDIR\amaru-app.ico"
    WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\amaru-app.ico"
  ${Else}
    WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\amaru.exe"
  ${EndIf}
  
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "InstallLocation" "$INSTDIR"
  
  ; Opcionalmente, registrar URLs
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "https://amaruantivirus.org"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "URLUpdateInfo" "https://amaruantivirus.org/updates"

  ; Verificar integridad de los archivos instalados
  ${If} ${VERIFICAR_INTEGRIDAD} == 1
    Call VerificarIntegridad
  ${EndIf}
SectionEnd

; Función de desinstalación
Section Uninstall
  ; Detener el proceso y el servicio
  ExecWait '"$INSTDIR\amaru.exe" service --action stop'
  ExecWait '"$INSTDIR\amaru.exe" service --action uninstall'
  ExecWait 'taskkill /F /IM amaru.exe'
  Sleep 1000
  
  ; Eliminar accesos directos
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk"
  Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT_NAME}"
  
  ; Eliminar archivos del programa y directorios
  Delete "$INSTDIR\amaru.exe"
  Delete "$INSTDIR\amaru-app.ico"
  Delete "$INSTDIR\amaru-isotipo-white.ico"
  Delete "$INSTDIR\.env"
  Delete "$INSTDIR\config.toml"
  Delete "$INSTDIR\uninstall.exe"
  
  ; Eliminar todos los módulos
  RMDir /r "$INSTDIR\modules"
  
  ; Preguntar si se desean conservar los logs y la cuarentena
  MessageBox MB_YESNO|MB_ICONQUESTION "¿Desea conservar los archivos de registro y cuarentena?" IDYES keepLogs IDNO removeLogs
  
  removeLogs:
    RMDir /r "$INSTDIR\logs"
    RMDir /r "$INSTDIR\quarantine"
    RMDir /r "$INSTDIR\signatures"
    Goto continueUninstall
    
  keepLogs:
    ; No eliminar logs ni cuarentena
    
  continueUninstall:
  ; Eliminar directorio principal si está vacío
  RMDir "$INSTDIR"
  
  ; Eliminar registros
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
  DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKCU "Software\${PRODUCT_NAME}"
  DeleteRegKey HKLM "${REGKEY}"
  
  ; Eliminar del inicio automático
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}"
  
  SetAutoClose true
SectionEnd

; Función para verificar la integridad de los archivos instalados
Function VerificarIntegridad
  CreateDirectory "$INSTDIR\logs"
  FileOpen $0 "$INSTDIR\logs\verificacion.log" "w"
  FileWrite $0 "Verificación de integridad - $(^Date) $(^Time)$\r$\n"
  FileWrite $0 "----------------------------------------$\r$\n"
  
  ; Calcular hashes SHA-256 de archivos críticos
  nsExec::ExecToStack 'powershell -Command "Get-FileHash \"$INSTDIR\amaru.exe\" -Algorithm SHA256 | Select-Object -ExpandProperty Hash"'
  Pop $1 ; return value (ignored)
  Pop $2 ; output
  FileWrite $0 "amaru.exe: $2$\r$\n"
  
  nsExec::ExecToStack 'powershell -Command "Get-FileHash \"$INSTDIR\amaru-service.exe\" -Algorithm SHA256 | Select-Object -ExpandProperty Hash"'
  Pop $1 ; return value (ignored)
  Pop $2 ; output
  FileWrite $0 "amaru-service.exe: $2$\r$\n"
  
  nsExec::ExecToStack 'powershell -Command "Get-FileHash \"$INSTDIR\amaru-scanner.dll\" -Algorithm SHA256 | Select-Object -ExpandProperty Hash"'
  Pop $1 ; return value (ignored)
  Pop $2 ; output
  FileWrite $0 "amaru-scanner.dll: $2$\r$\n"
  
  ; Verificar contra hashes esperados (estos deberían generarse durante la compilación)
  Call VerificarHashEsperado
  
  FileWrite $0 "$\r$\nVerificación completada.$\r$\n"
  FileClose $0
FunctionEnd

Function VerificarHashEsperado
  ; Esta función sería reemplazada en tiempo de compilación
  ; con los hashes esperados de los binarios
  FileWrite $0 "$\r$\nNota: Esta es una verificación de integridad básica.$\r$\n"
  FileWrite $0 "Para una verificación completa, esta sección debería$\r$\n"
  FileWrite $0 "comparar contra hashes generados durante la compilación.$\r$\n"
FunctionEnd

; Sección para firmar digitalmente el instalador (procesada post-compilación)
!system 'signcode.exe -spc "certificado.spc" -v "clave.pvk" -n "Amaru Antivirus" -i "https://amaru.example.com" -t "http://timestamp.digicert.com" -tr 10 "${INSTALADOR_SALIDA}"'

!define VERIFICAR_INTEGRIDAD 1 