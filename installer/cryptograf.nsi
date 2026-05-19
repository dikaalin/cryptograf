Unicode true
ManifestDPIAware true

; ── Defines ───────────────────────────────────────────────────────────────────
!define APP_NAME    "Cryptograf"
!define APP_VERSION "1.0"
!define APP_EXE     "cryptograf-gui.exe"
; Regenerate GUID at https://www.guidgenerator.com/ for each new major version
!define APP_GUID    "{8B7A3F2E-1C5D-4890-B6A1-FD234E8C9071}"

; ── Installer metadata ────────────────────────────────────────────────────────
; NOTE: all paths are relative to the CWD when makensis is invoked.
; Always run from the project root:
;   makensis installer\cryptograf.nsi
Name             "${APP_NAME} ${APP_VERSION}"
OutFile          "Cryptograf-Setup.exe"
InstallDir       "$PROGRAMFILES64\${APP_NAME}"
InstallDirRegKey HKLM "Software\${APP_NAME}" "InstallDir"
RequestExecutionLevel admin
SetCompressor    /SOLID lzma

; ── Modern UI ─────────────────────────────────────────────────────────────────
!include "MUI2.nsh"

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN      "$INSTDIR\${APP_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "Запустить Cryptograf"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE   "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Russian"
!insertmacro MUI_LANGUAGE "English"

; ── Install ───────────────────────────────────────────────────────────────────
Section "" SecMain
    SectionIn RO

    SetOutPath "$INSTDIR"
    ; Bundle everything from the staging directory (populated by stage.ps1 / CI):
    ;   cryptograf-gui.exe, cryptograf.exe
    ;   Qt6*.dll, libssl*.dll, libcrypto*.dll
    ;   platforms\, styles\, iconengines\, imageformats\, tls\, …
    File /r "dist\*"

    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; Registry — Add/Remove Programs entry
    WriteRegStr   HKLM "Software\${APP_NAME}" \
                  "InstallDir" "$INSTDIR"
    WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_GUID}" \
                  "DisplayName"     "Cryptograf — AES-256 шифрование файлов"
    WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_GUID}" \
                  "DisplayVersion"  "${APP_VERSION}"
    WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_GUID}" \
                  "Publisher"       "${APP_NAME}"
    WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_GUID}" \
                  "InstallLocation" "$INSTDIR"
    WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_GUID}" \
                  "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_GUID}" \
                  "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_GUID}" \
                  "NoRepair" 1

    ; Start Menu + Desktop shortcuts
    CreateDirectory "$SMPROGRAMS\${APP_NAME}"
    CreateShortCut  "$SMPROGRAMS\${APP_NAME}\Cryptograf.lnk" \
                    "$INSTDIR\${APP_EXE}"
    CreateShortCut  "$SMPROGRAMS\${APP_NAME}\Удалить Cryptograf.lnk" \
                    "$INSTDIR\Uninstall.exe"
    CreateShortCut  "$DESKTOP\Cryptograf.lnk" \
                    "$INSTDIR\${APP_EXE}"
SectionEnd

; ── Uninstall ─────────────────────────────────────────────────────────────────
Section "Uninstall"
    Delete "$SMPROGRAMS\${APP_NAME}\Cryptograf.lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\Удалить Cryptograf.lnk"
    RMDir  "$SMPROGRAMS\${APP_NAME}"
    Delete "$DESKTOP\Cryptograf.lnk"

    RMDir /r "$INSTDIR"

    DeleteRegKey HKLM "Software\${APP_NAME}"
    DeleteRegKey HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_GUID}"
SectionEnd
