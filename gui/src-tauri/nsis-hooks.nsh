; Sentinella NSIS installer hooks
; Runs with elevated privileges during install/uninstall.
;
; INSTDIR = where Tauri installs the GUI app (e.g., C:\Program Files\Sentinella)
; Resources are at $INSTDIR\daemon\*

!macro NSIS_HOOK_POSTINSTALL
  ; === Create ProgramData directory structure ===
  CreateDirectory "$COMMONFILES\..\ProgramData\Sentinella"
  CreateDirectory "$COMMONFILES\..\ProgramData\Sentinella\config"
  CreateDirectory "$COMMONFILES\..\ProgramData\Sentinella\signatures"
  CreateDirectory "$COMMONFILES\..\ProgramData\Sentinella\state"
  CreateDirectory "$COMMONFILES\..\ProgramData\Sentinella\logs"
  CreateDirectory "$COMMONFILES\..\ProgramData\Sentinella\quarantine"
  CreateDirectory "$COMMONFILES\..\ProgramData\Sentinella\cache"
  CreateDirectory "$COMMONFILES\..\ProgramData\Sentinella\argus"
  CreateDirectory "$COMMONFILES\..\ProgramData\Sentinella\argus\rules"
  CreateDirectory "$COMMONFILES\..\ProgramData\Sentinella\argus\rules\yara"
  CreateDirectory "$COMMONFILES\..\ProgramData\Sentinella\argus\manifests"
  CreateDirectory "$COMMONFILES\..\ProgramData\Sentinella\rules"
  CreateDirectory "$COMMONFILES\..\ProgramData\Sentinella\clamav_tmp"
  CreateDirectory "$COMMONFILES\..\ProgramData\Sentinella\diagnostics"

  ; === Copy config templates (don't overwrite existing) ===
  IfFileExists "$COMMONFILES\..\ProgramData\Sentinella\config\freshclam.conf" +2 0
    CopyFiles /SILENT "$INSTDIR\daemon\runtime\config\freshclam.conf" "$COMMONFILES\..\ProgramData\Sentinella\config\"
  IfFileExists "$COMMONFILES\..\ProgramData\Sentinella\config\sentinelld.toml" +2 0
    CopyFiles /SILENT "$INSTDIR\daemon\runtime\config\sentinelld.toml" "$COMMONFILES\..\ProgramData\Sentinella\config\"

  ; === Copy YARA rules ===
  CopyFiles /SILENT "$INSTDIR\daemon\runtime\argus\rules\yara\*.yar" "$COMMONFILES\..\ProgramData\Sentinella\argus\rules\yara\"

  ; === Copy manifests ===
  CopyFiles /SILENT "$INSTDIR\daemon\runtime\argus\manifests\*.*" "$COMMONFILES\..\ProgramData\Sentinella\argus\manifests\"

  ; === Copy IOC hashes ===
  CopyFiles /SILENT "$INSTDIR\daemon\runtime\rules\*.*" "$COMMONFILES\..\ProgramData\Sentinella\rules\"

  ; === Copy TLS certs for freshclam ===
  CreateDirectory "$INSTDIR\daemon\certs"

  ; === Stop existing service if running (upgrade scenario) ===
  nsExec::ExecToLog 'sc stop SentinellaDaemon'
  Sleep 2000

  ; === Delete old service if exists (upgrade) ===
  nsExec::ExecToLog 'sc delete SentinellaDaemon'
  Sleep 1000

  ; === Register Windows service (no --foreground → uses Windows Service API) ===
  nsExec::ExecToLog 'sc create SentinellaDaemon binPath= "\"$INSTDIR\daemon\sentinelld.exe\" --log-level info --runtime-root \"$COMMONFILES\..\ProgramData\Sentinella\" --dll-dir \"$INSTDIR\daemon\" --db-dir \"$COMMONFILES\..\ProgramData\Sentinella\signatures\"" DisplayName= "Sentinella Protection Service" start= delayed-auto obj= "LocalSystem"'

  ; === Set service description ===
  nsExec::ExecToLog 'sc description SentinellaDaemon "Sentinella antivirus daemon with ClamAV signatures and ARGUS heuristic intelligence engine."'

  ; === Configure failure recovery: restart on failure ===
  nsExec::ExecToLog 'sc failure SentinellaDaemon reset= 86400 actions= restart/5000/restart/10000/restart/30000'

  ; === Download ClamAV signatures in background ===
  ; freshclam runs detached — user doesn't wait. Signatures download while they explore the GUI.
  nsExec::Exec '"$INSTDIR\daemon\freshclam.exe" --config-file="$COMMONFILES\..\ProgramData\Sentinella\config\freshclam.conf" --datadir="$COMMONFILES\..\ProgramData\Sentinella\signatures"'

  ; === Start the service ===
  nsExec::ExecToLog 'sc start SentinellaDaemon'

!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; === Stop and remove service ===
  nsExec::ExecToLog 'sc stop SentinellaDaemon'
  Sleep 3000
  nsExec::ExecToLog 'sc delete SentinellaDaemon'
  Sleep 1000
!macroend
