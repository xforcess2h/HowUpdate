@echo off

NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotAdmin ) else ( powershell start -verb runas '"%~0"' & exit /b )
:gotAdmin

REM Blank/Color Character
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (set "DEL=%%a" & set "COL=%%b")

REM Add ANSI escape sequences
set "ESC=" & for /F %%A in ('echo prompt $E ^| cmd') do set "ESC=%%A"

REM Color/Menu
set "GREY=%COL%[90m"
set "RED=%COL%[91m"
set "GREEN=%COL%[92m"
set "YELLOW=%COL%[93m"
set "BLUE=%COL%[94m"
set "PURPLE=%COL%[95m"
set "CYAN=%COL%[96m"
set "WHITE=%COL%[97m"
set "RESET=%COL%[0m"

set "basePath=C:\2HCTRL\scheckvalues"
mkdir "%basePath%" 2>nul
mkdir "%basePath%\%fileName%" 2>nul
copy nul "%basePath%\%fileName%" >nul


color 0f
title 2HTweaker
cls
echo.
echo.
echo.
echo       %COL%[91m2H Tweaker CTRL%COL%[0m
echo.
echo.
echo.
echo       %COL%[96mWelcome!%COL%[0m
echo       %COL%[97mThis tweaker is still under development, so it may
echo       cause system errors and instability. Use the settings at your
echo       Some Tweakers are marked with markers:%COL%[0m
echo       %COL%[94m[Beta]%COL%[0m - May have side effects.
echo       %COL%[92m[PowerH]%COL%[0m - Consumption of more energy.
echo       %COL%[93m[Danger]%COL%[0m - Can do serious damage to the system.
echo       ------------------------------------------------------------
echo       %COL%[94mIf you understand what you are doing,%COL%[0m	
echo       %COL%[94mconfirm the action:%COL%[0m %COL%[91m[ 1 ]%COL%[0m
echo       ------------------------------------------------------------
echo       %COL%[90mRecommended%COL%[0m: %COL%[94mIntel%COL%[0m + %COL%[92mNVIDIA%COL%[0m
echo       %COL%[90mRecommended%COL%[0m: %COL%[91mUse ReviPlayBook%COL%[0m
echo.
echo.
echo.
echo       [Version]     - v.1.4
echo       [L.Update]    - 16.11.2023
echo.
set /p "input=%DEL%                                             >: %COL%[96m"
if /i "%input%" neq "1" (
    echo.
    echo   Denied.
    timeout /nobreak /t 3 >nul
    exit /b 1
)

cls
color 0f

REM Main Menu
:menu
cls
echo.
echo.
echo   %COL%[94m[1]%COL%[0m System
echo   %COL%[94m[2]%COL%[0m Graphics
echo   %COL%[94m[3]%COL%[0m Internet
echo   %COL%[94m[4]%COL%[0m Interface
echo   %COL%[94m[5]%COL%[0m Privacy
echo   %COL%[94m[6]%COL%[0m Others
echo.
echo   %COL%[93m[clean]%COL%[0m %COL%[93mJunkClean%COL%[0m
echo.
echo   [x] Close
echo   [sdv] Set default values

set /p choice=Select 

	if "%choice%"=="1" goto submenu1
	if "%choice%"=="2" goto submenu2
	if "%choice%"=="3" goto submenu3
	if "%choice%"=="4" goto submenu4
	if "%choice%"=="5" goto submenu5
	if "%choice%"=="6" goto submenu6
	if "%choice%"=="clean" goto junkclean
if "%choice%"=="sdv" goto restoresettings
if "%choice%"=="x" (
    echo Close.
    exit /b 0
) else (
    echo Enter a number to select an item.
    timeout /nobreak /t 2 >nul
    goto menu
)

REM [Menu: System] - 1
:submenu1
cls
echo  [1] - Disabling Services
echo  [2] - Disabling Windows PowerThrottling
echo  [3] - Disabling Windows Telemetry
echo  [4] - Optimize NetSH %COL%[93m[Danger]%COL%[0m
echo  [5] - Disabling Paging Files
echo  [6] - Optimize Windows Sound %COL%[94m[Beta]%COL%[0m
echo  [7] - Optimize Windows Explorer
echo  [8] - Optimize Integrated Intel GPU %COL%[94m[Beta]%COL%[0m
echo  [9] - Disable Mitigations %COL%[94m[Beta]%COL%[0m
echo.
echo  %COL%[91m[x]%COL%[0m - %COL%[97mBack%COL%[0m

set /p choice=Select Option: 

if "%choice%"=="1" (
    call :Script1_1
    echo.
    echo Complete!
    pause
    goto submenu1
) else if "%choice%"=="2" (
    call :Script1_2
    echo.
    echo Complete!
    pause
    goto submenu1
) else if "%choice%"=="3" (
    call :Script1_3
    echo.
    echo Complete!
    pause
    goto submenu1
) else if "%choice%"=="4" (
    call :Script1_4
    echo.
    echo Complete!
    pause
    goto submenu1
) else if "%choice%"=="5" (
    call :Script1_5
    echo.
    echo Complete!
    pause
    goto submenu1
) else if "%choice%"=="6" (
    call :Script1_6
    echo.
    echo Complete!
    pause
    goto submenu1
) else if "%choice%"=="7" (
    call :Script1_7
    echo.
    echo Complete!
    pause
    goto submenu1
) else if "%choice%"=="8" (
    call :Script1_8
    echo.
    echo Скрипт 1-8 выполнен.
    pause
    goto submenu1
) else if "%choice%"=="9" (
    call :Script1_9
    echo.
    echo Скрипт 1-9 выполнен.
    pause
    goto submenu1
) else if "%choice%"=="x" (
    goto menu
) else (
    echo Wha... What?
    timeout /nobreak /t 2 >nul
    goto submenu1
)

REM [Menu: Graphics] - 2
:submenu2
cls
echo  [1] - Disable NVIDIA Telemetry
echo  [2] - Disable NVIDIA (HDCP)
echo  [3] - %COL%[91mNVIDIA Optimization (Development) (NOT USE)%COL%[0m
echo  [4] - %COL%[91mNVIDIA All GPU Tweaks (Development) (NOT USE)%COL%[0m
echo  [5] - Run Script
echo  [6] - Run Script
echo.
echo  %COL%[91m[x]%COL%[0m - %COL%[97mBack%COL%[0m

set /p choice=Select Option: 

if "%choice%"=="1" (
    call :Script2_1
    echo.
    echo Скрипт 2-1 выполнен.
    pause
    goto submenu2
) else if "%choice%"=="2" (
    call :Script2_2
    echo.
    echo Скрипт 2-2 выполнен.
    pause
    goto submenu2
) else if "%choice%"=="3" (
    call :Script2_3
    echo.
    echo Скрипт 2-3 выполнен.
    pause
    goto submenu2
) else if "%choice%"=="4" (
    call :Script2_4
    echo.
    echo Скрипт 2-4 выполнен.
    pause
    goto submenu2
) else if "%choice%"=="5" (
    call :Script2_5
    echo.
    echo Скрипт 2-5 выполнен.
    pause
    goto submenu2
) else if "%choice%"=="6" (
    call :Script2_6
    echo.
    echo Скрипт 2-6 выполнен.
    pause
    goto submenu2
) else if "%choice%"=="x" (
    goto menu
) else (
    echo Введите корректную цифру.
    timeout /nobreak /t 2 >nul
    goto submenu2
)

REM [Menu: Internet] - 3
:submenu3
cls
echo [1] 1
echo [2] 2
echo [3] 3
echo [4] 4
echo [5] 5
echo x. Close

set /p choice=Select 

if "%choice%"=="1" (
    call :Script3_1
    echo.
    echo Скрипт 3-1 выполнен.
    pause
    goto submenu3
) else if "%choice%"=="2" (
    call :Script3_2
    echo.
    pause
    goto submenu3
) else if "%choice%"=="3" (
    call :Script3_3
    echo.
    pause
    goto submenu3
) else if "%choice%"=="4" (
    call :Script3_4
    echo.
    pause
    goto submenu3
) else if "%choice%"=="5" (
    call :Script3_5
    echo.
    pause
    goto submenu3
) else if "%choice%"=="x" (
    goto menu
) else (
    echo Введите корректную цифру.
    timeout /nobreak /t 2 >nul
    goto submenu3
)

REM [Menu: Interface] - 4
:submenu4
cls
echo  [1] - Disable Key Sticking
echo  [2] - Disable Windows Search IND %COL%[94m(Beta)%COL%[0m
echo  [3] - Wallpaper High Quality
echo  [4] - Optimize Mouse %COL%[94m(Beta)%COL%[0m
echo  [5] - Disable Windows GameBar %COL%[94m(Beta)%COL%[0m
echo  [6] - Disable "Shortcut"
echo  [7] - Enable Explorer "Compact Mode" %COL%[94m(Beta)%COL%[0m
echo.
echo  %COL%[91m[x]%COL%[0m - %COL%[97mBack%COL%[0m
set /p choice=Select 

if "%choice%"=="1" (
    call :Script4_1
    echo.
    echo DISABLE
    pause
    goto submenu4
) else if "%choice%"=="2" (
    call :Script4_2
    echo.
    pause
    goto submenu4
) else if "%choice%"=="3" (
    call :Script4_3
    echo.
    pause
    goto submenu4
) else if "%choice%"=="4" (
    call :Script4_4
    echo.
    pause
    goto submenu4
) else if "%choice%"=="5" (
    call :Script4_5
    echo.
    pause
    goto submenu4
) else if "%choice%"=="6" (
    call :Script4_6
    echo.
    pause
    goto submenu4
) else if "%choice%"=="7" (
    call :Script4_7
    echo.
    pause
    goto submenu4
) else if "%choice%"=="x" (
    goto menu
) else (
    echo Введите корректную цифру.
    timeout /nobreak /t 2 >nul
    goto submenu4
)

REM [Menu: Privacy] - 5
:submenu5
cls
echo 1. Run Script
echo 2. Run Script
echo 3. Run Script
echo 4. Run Script
echo 5. Run Script
echo 6. Run Script
echo x. Back

set /p choice=Выберите опцию: 

if "%choice%"=="1" (
    call :Script2_1
    echo.
    echo Скрипт 2-1 выполнен.
    pause
    goto submenu5
) else if "%choice%"=="2" (
    call :Script5_2
    echo.
    echo Скрипт 2-2 выполнен.
    pause
    goto submenu5
) else if "%choice%"=="3" (
    call :Script5_3
    echo.
    echo Скрипт 5-3 выполнен.
    pause
    goto submenu5
) else if "%choice%"=="4" (
    call :Script5_4
    echo.
    echo Скрипт 2-4 выполнен.
    pause
    goto submenu5
) else if "%choice%"=="5" (
    call :Script5_5
    echo.
    echo Скрипт 2-5 выполнен.
    pause
    goto submenu5
) else if "%choice%"=="6" (
    call :Script5_6
    echo.
    echo Скрипт 2-6 выполнен.
    pause
    goto submenu5
) else if "%choice%"=="x" (
    goto menu
) else (
    echo Введите корректную цифру.
    timeout /nobreak /t 2 >nul
    goto submenu5
)

REM [Menu: Other] - 6
:submenu6
cls
echo 1. Run Script
echo 2. Run Script
echo 3. Run Script
echo 4. Run Script
echo x. Back

set /p choice=Выберите опцию: 

if "%choice%"=="1" (
    call :Script6_1
    echo.
    echo Скрипт 2-1 выполнен.
    pause
    goto submenu6
) else if "%choice%"=="2" (
    call :Script6_2
    echo.
    echo Скрипт 2-2 выполнен.
    pause
    goto submenu6
) else if "%choice%"=="3" (
    call :Script6_3
    echo.
    echo Скрипт 5-3 выполнен.
    pause
    goto submenu6
) else if "%choice%"=="4" (
    call :Script6_4
    echo.
    echo Скрипт 2-4 выполнен.
    pause
    goto submenu6
) else if "%choice%"=="x" (
    goto menu
) else (
    echo Введите корректную цифру.
    timeout /nobreak /t 2 >nul
    goto submenu6
)

:Script1_1
echo Disabling unnecessary services.
REM Stop & Disable Services
sc stop vmms
sc stop vmcompute
sc stop vmicguestinterface
sc stop vmicshutdown
sc stop vmicvmsession
sc stop vmicheartbeat
sc stop vmickvpexchange
sc stop vmicrdv
sc stop vmictimesync
sc stop vmicvss
sc stop HvHost
sc stop wsearch
sc stop wuauserv
sc stop sysmain
sc stop WinDefend
sc stop DiagTrack
sc stop bthserv
sc stop fax
sc stop vds
sc stop lfsvc
sc stop GraphicsPerfSvc
sc stop AppVClient
sc stop edgeupdate
sc stop edgeupdatem
sc stop ssh-agent
sc stop XblAuthManager
sc stop XboxGipSvc
sc stop XblGameSave
sc stop XboxNetApiSvc
sc stop WbioSrvc
sc stop SgrmBroker
sc stop autotimesvc
sc stop RasAuto
sc stop SEMgrSvc
sc stop MapsBroker
sc stop EventLog
sc stop pla
sc stop KeyIso
sc stop NgcCtnrSvc
sc stop RpcLocator
sc stop RemoteAccess
sc stop SCPolicySvc
sc stop NcbService
sc stop NaturalAuthentication
sc stop PhoneSvc
sc stop TapiSrv
sc stop VSS
sc stop WdiSystemHost
sc stop SCardSvr
sc stop RemoteRegistry
sc stop wscsvc
sc stop SensorDataService
sc stop SensorService
sc stop SensrSvc
sc stop seclogon
sc stop AJRouter
sc stop KeyIso
sc config AJRouter start=disabled
sc config AppVClient start=disabled
sc config autotimesvc start=disabled
sc config bthserv start=disabled
sc config edgeupdate start=disabled
sc config edgeupdatem start=disabled
sc config EventLog start=disabled
sc config fax start=disabled
sc config GraphicsPerfSvc start=disabled
sc config lfsvc start=disabled
sc config MapsBroker start=disabled
sc config NcbService start=disabled
sc config NaturalAuthentication start=disabled
sc config pla start=disabled
sc config PhoneSvc start=disabled
sc config RasAuto start=disabled
sc config RemoteAccess start=disabled
sc config RemoteRegistry start=disabled
sc config RpcLocator start=disabled
sc config SCardSvr start=disabled
sc config SCPolicySvc start=disabled
sc config seclogon start=disabled
sc config SEMgrSvc start=disabled
sc config SensorDataService start=disabled
sc config SensorService start=disabled
sc config SensrSvc start=disabled
sc config ssh-agent start=disabled
sc config sysmain start=disabled
sc config TapiSrv start=disabled
sc config VDS start=disabled
sc config vmicheartbeat start=disabled
sc config vmicguestinterface start=disabled
sc config vmicheartbeat start=disabled
sc config vmicrdv start=disabled
sc config vmicshutdown start=disabled
sc config vmicvmsession start=disabled
sc config vmictimesync start=disabled
sc config vmicvss start=disabled
sc config vmickvpexchange start=disabled
sc config WbioSrvc start=disabled
sc config WdiSystemHost start=disabled
sc config wiaRpc start=disabled
sc config wsearch start=disabled
sc config wuauserv start=disabled
sc config XblAuthManager start=disabled
sc config XboxGipSvc start=disabled
sc config XboxNetApiSvc start=disabled
cls
exit /b

:Script1_2
echo Disable PowerThrottling
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v PowerThrottlingOff /t REG_DWORD /d 1 /f
cls
exit /b

:Script1_3
echo Disable Telemetry
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d 0 /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d 4 /f
	schtasks /change /tn "Microsoft\Windows\Maintenance\WinSAT" /disable
	schtasks /change /tn "Microsoft\Windows\Autochk\Proxy" /disable
	schtasks /change /tn "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
	schtasks /change /tn "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
	schtasks /change /tn "Microsoft\Windows\Application Experience\StartupAppTask" /disable
	schtasks /change /tn "Microsoft\Windows\PI\Sqm-Tasks" /disable
	schtasks /change /tn "Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
	schtasks /change /tn "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
	schtasks /change /tn "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
	schtasks /change /tn "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
	schtasks /change /tn "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable
	schtasks /change /tn "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
	schtasks /change /tn "Microsoft\Office\Office ClickToRun Service Monitor" /disable
	schtasks /change /tn "Microsoft\Office\OfficeTelemetry\AgentFallBack2016" /disable
	schtasks /change /tn "Microsoft\Office\OfficeTelemetry\AgentFallBack2016" /disable
	schtasks /change /tn "Microsoft\Office\OfficeTelemetry\OfficeTelemetryAgentLogOn2016" /disable
	schtasks /change /tn "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /disable
	schtasks /change /tn "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /disable
	schtasks /change /tn "Microsoft\Office\OfficeTelemetryAgentFallBack" /disable
	schtasks /change /tn "Microsoft\Office\OfficeTelemetryAgentLogOn" /disable
	schtasks /change /tn "Microsoft\Office\Office 15 Subscription Heartbeat" /disable
		reg delete "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /f
		reg delete "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /f
		reg delete "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /f
		reg delete "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /f
		reg delete "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /f
		reg delete "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /f
		reg delete "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /f
cls
exit /b

:Script1_4
echo Optimize NETsh
netsh interface tcp set global autotuninglevel=disabled
netsh interface tcp set global autotuninglevel=highlyrestricted
netsh interface tcp set global autotuninglevel=experimental
netsh interface tcp set global autotuninglevel=disabled
netsh interface tcp set global autotuninglevel=normal
set /p mtu_size=1500
netsh interface ipv4 set subinterface "Ethernet" mtu=%mtu_size% store=persistent
netsh int tcp set global initialRto=3000
netsh int tcp set global maxsynretransmissions=2
netsh int tcp set global nonsackrttresiliency=enable
cls
exit /b

:Script1_5
echo Disable Paging Files
wmic computersystem where caption='*' call setsetting "AutomaticManagedPagefile"="FALSE"
wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=0,MaximumSize=0
rem CLEAR PAGEFILE.SYS (C:\pagefile.sys)
pagefileconfig -c "C:\pagefile.sys"
cls
exit /b

:Script1_6
echo Optimize Windows Sound
reg add "HKLM\SOFTWARE\Realtek\Audio\AP" /v RaDelayApoPD /t REG_DWORD /d 50 /f
reg add "HKLM\SOFTWARE\Realtek\Audio\AP" /v RaDelayApoEP /t REG_DWORD /d 50 /f
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\Stereo3D" /v NvAPI_Stereo_PD /t REG_DWORD /d 50 /f
for /l %%i in (1, 1, 5) do (
	set "folder=HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}\000%%i"
	reg add "!folder!\PowerSettings" /v ConservationIdleTime /t REG_BINARY /d ff ff ff ff /f
	reg add "!folder!\PowerSettings" /v IdlePowerState /t REG_BINARY /d 00 00 00 00 /f
	reg add "!folder!\PowerSettings" /v PerformanceIdleTime /t REG_BINARY /d ff ff ff ff /f
cls
exit /b

:Script1_7
echo Optimize Windows Explorer
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisableThumbnailCache /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v AutoExpandFolders /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStrCmpLogical /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ExtendedUIHoverTime /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f
cls
exit /b

:Script1_8
echo Optimize Integrated Intel GPU
sc config "IntelCpHeciSvc" start=disabled
sc config "LMS" start=disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v TdrDelay /t REG_DWORD /d 10 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v TdrLevel /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v FlipFlopHwVsync /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v EnableAeroPeek /t REG_DWORD /d 0 /f
exit /b

:Script1_9
echo Disables Mitigations
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f
reg delete "HKCU\Software\Hone" /v MitigationsTweaks /f
REM Turn Core Isolation Memory Integrity ON
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "1" /f
REM Enable SEHOP
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /f
REM Enable Spectre And Meltdown
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettings /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /f
cd %TEMP%
if not exist "%TEMP%\NSudo.exe" curl -g -L -# -o "%TEMP%\NSudo.exe" "https://github.com/auraside/HoneCtrl/raw/main/Files/NSudo.exe"
NSudo -U:S -ShowWindowMode:Hide -wait cmd /c "reg add "HKLM\SYSTEM\CurrentControlSet\Services\TrustedInstaller" /v "Start" /t Reg_DWORD /d "2" /f"
NSudo -U:S -ShowWindowMode:Hide -wait cmd /c "sc start "TrustedInstaller"" 
NSudo -U:T -P:E -M:S -ShowWindowMode:Hide -wait cmd /c "ren %SYSTEMROOT%\System32\mcupdate_GenuineIntel.old mcupdate_GenuineIntel.dll"
NSudo -U:T -P:E -M:S -ShowWindowMode:Hide -wait cmd /c "ren %SYSTEMROOT%\System32\mcupdate_AuthenticAMD.old mcupdate_AuthenticAMD.dll"
REM Enable CFG Lock
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /f
REM Enable NTFS/ReFS and FS Mitigations
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /f
cls
 exit /b

REM VIDEO

:Script2_1
echo Disable NVidia Telemetry
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NvTelemetryContainer" /v "Start" /t REG_DWORD /d 4 /f
schtasks /change /tn NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /disable
schtasks /change /tn NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /disable
schtasks /change /tn NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /disable
net stop NvTelemetryContainer
sc config NvTelemetryContainer start= disabled
sc stop NvTelemetryContainer
	reg add "HKCU\Software\Hone" /v NVTTweaks /f
	reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f
	reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f
	reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f
	reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f
	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "NvBackend" /f
	schtasks /change /disable /tn "NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
	schtasks /change /disable /tn "NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
	schtasks /change /disable /tn "NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
	schtasks /change /disable /tn "NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
cls
exit /b

:Script2_2
Disable NVIDIA HDCP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Configuration" /v DigitalHDTVDefaultProtection /t REG_DWORD /d 0 /f
exit /b

:Script2_3
echo NVIDIA Optimization
	reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak\Devices\509901423-0\Color" /v "NvCplUseColorCorrection" /t Reg_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PlatformSupportMiracast" /t Reg_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /t Reg_DWORD /d "0" /f
	rem Unrestricted Clocks
	cd "%SYSTEMDRIVE%\Program Files\NVIDIA Corporation\NVSMI\"
	nvidia-smi -acp UNRESTRICTED
	nvidia-smi -acp DEFAULT
	rem Nvidia Registry Key
	for /f %%a in ('reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HKEY"') do (
		rem Disalbe Tiled Display
		reg add "%%a" /v "EnableTiledDisplay" /t REG_DWORD /d "0" /f
		rem Disable TCC
		reg add "%%a" /v "TCCSupported" /t REG_DWORD /d "0" /f
	)
	rem Silk Smoothness Option
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID61684" /t REG_DWORD /d "1" /f
) >nul 2>&1 else (
	reg delete "HKCU\Software\Hone" /v "NvidiaTweaks" /f
	rem Nvidia Reg
	reg delete "HKCU\Software\NVIDIA Corporation\Global\NVTweak\Devices\509901423-0\Color" /v "NvCplUseColorCorrection" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PlatformSupportMiracast" /t Reg_DWORD /d "1" /f
	reg delete "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /f
	rem Nvidia Registry Key
	for /f %%a in ('reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HKEY"') do (
		rem Reset Tiled Display
		reg delete "%%a" /v "EnableTiledDisplay" /f
		rem Reset TCC
		reg delete "%%a" /v "TCCSupported" /f
exit /b

:Script2_4
echo NVIDIA All GPU Tweaks
	rem Nvidia Reg
	reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak\Devices\509901423-0\Color" /v "NvCplUseColorCorrection" /t Reg_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PlatformSupportMiracast" /t Reg_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /t Reg_DWORD /d "0" /f
	rem Unrestricted Clocks
	cd "%SYSTEMDRIVE%\Program Files\NVIDIA Corporation\NVSMI\"
	nvidia-smi -acp UNRESTRICTED
	nvidia-smi -acp DEFAULT
	rem Nvidia Registry Key
	for /f %%a in ('reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HKEY"') do (
		rem Disalbe Tiled Display
		reg add "%%a" /v "EnableTiledDisplay" /t REG_DWORD /d "0" /f
		rem Disable TCC
		reg add "%%a" /v "TCCSupported" /t REG_DWORD /d "0" /f
	)
	reg delete "HKCU\Software\Hone" /v "AllGPUTweaks" /f
	REM Enable Hardware Accelerated Scheduling
	reg query "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" && reg add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t Reg_DWORD /d "1" /f
	REM Disable gdi hardware acceleration
	for /f %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class" /v "VgaCompatible" /s ^| findstr "HKEY"') do reg delete "%%a" /v "KMD_EnableGDIAcceleration" /f
	REM Enable GameMode
	reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t Reg_DWORD /d "1" /f
	reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t Reg_DWORD /d "1" /f
	REM FSO
	reg delete "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /f
	reg delete "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /f
	reg delete "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /f
	reg delete "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /f
	reg delete "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /f
	reg delete "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /f
	reg delete "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /f
	REM Disable GpuEnergyDrv
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t Reg_DWORD /d "2" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDr" /v "Start" /t Reg_DWORD /d "2" /f
	REM Disable Preemption
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t Reg_DWORD /d "1" /f



cls
echo.
echo.
echo         Successful!
exit /b

REM INTERFACE

:Script4_1
reg add "HKCU\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Keyboard" /v KeyboardSpeed /t REG_SZ /d 31 /f
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d "506" /f
cls
exit /b

:Script4_2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventIndexingOutlook" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventIndexingEncryptedFiles" /t REG_DWORD /d 1 /f
sc stop WSearch
sc config WSearch start=disabled
cls
exit /b

:Script4_3
reg add "HKCU\Control Panel\Desktop" /v JPEGImportQuality /t REG_DWORD /d 100 /f
cls
exit /b

:Script4_4
reg add "HKCU\Control Panel\Mouse" /v MouseAcceleration /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v DoubleClickSpeed /t REG_SZ /d 4 /f
cls
exit /b

:Script4_5
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
cls
exit /b

:Script4_6
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "link" /t REG_BINARY /d 00 00 00 00 /f
cls
exit /b

:Script4_7
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSmallIcons" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d 0 /f
cls
exit /b

:others
rem Memory Optimization
	reg add "HKLM\Software\Microsoft\FTH" /v "Enabled" /t Reg_DWORD /d "0" /f
	REM Disable Desktop Composition
	reg add "HKCU\Software\Microsoft\Windows\DWM" /v "Composition" /t REG_DWORD /d "0" /f
	REM Disable Background apps
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t Reg_DWORD /d "1" /f
	reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t Reg_DWORD /d "2" /f
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t Reg_DWORD /d "0" /f
	REM Disallow drivers to get paged into virtual memory
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t Reg_DWORD /d "1" /f
	REM Disable Page Combining and Memory Compression
	powershell -NoProfile -Command "Disable-MMAgent -PagingCombining -mc"
	reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d "1" /f
	REM Use Large System Cache to improve microstuttering
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t Reg_DWORD /d "1" /f
	REM Free unused ram
	reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "HeapDeCommitFreeBlockThreshold" /t REG_DWORD /d "262144" /f
	REM Auto restart Powershell on error
	reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoRestartShell" /t REG_DWORD /d "1" /f
	REM Disk Optimizations
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "0" /f
	REM Disable Prefetch and Superfetch
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t Reg_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t Reg_DWORD /d "0" /f
	REM Disable Hibernation + Fast Startup
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
	REM Wait time to kill app during shutdown
	reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t Reg_SZ /d "1000" /f
	REM Wait to end service at shutdown
	reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t Reg_SZ /d "1000" /f
	REM Wait to kill non-responding app
	reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t Reg_SZ /d "1000" /f
	REM fsutil
	if exist "%SYSTEMROOT%\System32\fsutil.exe" (
		REM Raise the limit of paged pool memory
		fsutil behavior set memoryusage 2
		REM https://www.serverbrain.org/solutions-2003/the-mft-zone-can-be-optimized.html
		fsutil behavior set mftzone 2
		REM Disable Last Access information on directories, performance/privacy
		fsutil behavior set disablelastaccess 1
		REM Disable Virtual Memory Pagefile Encryption
		fsutil behavior set encryptpagingfile 0
		REM Disables the creation of legacy 8.3 character-length file names on FAT- and NTFS-formatted volumes.
		fsutil behavior set disable8dot3 1
		REM Disable NTFS compression
		fsutil behavior set disablecompression 1
		REM Enable Trim
		fsutil behavior set disabledeletenotify 0 











:junkclean
del /q C:\Windows\Temp\*.*
rmdir /s /q %TEMP%
cls
exit /b

:restoresettings
set /p choice=At this time, this is not an available option.:
if "%choice%"=="x" (
    echo.
    pause
    goto menu
) else if "%choice%"=="x" (
    goto menu
) else (
    echo N/A
    timeout /nobreak /t 2 >nul
    goto menu
)