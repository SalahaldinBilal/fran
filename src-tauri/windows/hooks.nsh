; Uninstalling Fran also removes its VPN service, which lives outside Fran's own folder. That needs admin rights,
; so Windows asks. Refusing leaves the service in place.
!macro NSIS_HOOK_PREUNINSTALL
  IfFileExists "$PROGRAMFILES64\Fran\vpn\fran-vpn.exe" 0 +2
    ExecShellWait "runas" "$INSTDIR\fran-vpn.exe" "--uninstall" SW_HIDE
!macroend
