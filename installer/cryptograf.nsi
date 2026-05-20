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

; ── Pages ─────────────────────────────────────────────────────────────────────
Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

; ── Install ───────────────────────────────────────────────────────────────────
Section "" SecMain
    SectionIn RO

    SetOutPath "$INSTDIR"
    ; Bundle everything from the staging directory (populated by stage.ps1 / CI):
    ;   cryptograf-gui.exe, cryptograf.exe
    ;   Qt6*.dll, libssl*.dll, libcrypto*.dll, vcruntime*.dll
    ;   platforms\, styles\, iconengines\, imageformats\, tls\, ...
    File /r "dist\*"

    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; Registry - Add/Remove Programs entry
    WriteRegStr   HKLM "Software\${APP_NAME}" \
                  "InstallDir" "$INSTDIR"
    WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_GUID}" \
                  "DisplayName"     "Cryptograf - AES-256 file encryption"
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
    CreateShortcut  "$SMPROGRAMS\${APP_NAME}\Cryptograf.lnk" \
                    "$INSTDIR\${APP_EXE}"
    CreateShortcut  "$SMPROGRAMS\${APP_NAME}\Uninstall Cryptograf.lnk" \
                    "$INSTDIR\Uninstall.exe"
    CreateShortcut  "$DESKTOP\Cryptograf.lnk" \
                    "$INSTDIR\${APP_EXE}"
SectionEnd

; ── Uninstall ─────────────────────────────────────────────────────────────────
Section "Uninstall"
    Delete "$SMPROGRAMS\${APP_NAME}\Cryptograf.lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\Uninstall Cryptograf.lnk"
    RMDir  "$SMPROGRAMS\${APP_NAME}"
    Delete "$DESKTOP\Cryptograf.lnk"

    RMDir /r "$INSTDIR"

    DeleteRegKey HKLM "Software\${APP_NAME}"
    DeleteRegKey HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_GUID}"
SectionEnd
