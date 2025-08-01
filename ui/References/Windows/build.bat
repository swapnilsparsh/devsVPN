@echo off

setlocal
set SCRIPTDIR=%~dp0

set CERT_SHA1=%1

rem ==================================================
rem DEFINE path to NSIS binary here
SET MAKENSIS="C:\Program Files (x86)\NSIS\makensis.exe"
rem Update this line if using another version of VisualStudio or it is installed in another location
set _VS_VARS_BAT="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
rem ==================================================
SET INSTALLER_OUT_DIR=%SCRIPTDIR%bin
set INSTALLER_TMP_DIR=%INSTALLER_OUT_DIR%\temp
SET FILE_LIST=%SCRIPTDIR%Installer\release-files.txt
SET FILE_LIST_CI_TEST=%SCRIPTDIR%Installer\release-files-CI-build-Test.txt

set APPVER=???
set SERVICE_REPO=%SCRIPTDIR%..\..\..\daemon
set CLI_REPO=%SCRIPTDIR%..\..\..\cli

rem Checking if msbuild available
WHERE msbuild >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
	echo [!] 'msbuild' is not recognized as an internal or external command
	echo [!] Ensure you are running this script from Developer Cammand Prompt for Visual Studio
	
	if not defined VSCMD_VER (
        if "%VSCMD_ARG_TGT_ARCH%" NEQ "x64" (
            echo [*] Initialising x64 VS build environment ...
            if not exist %_VS_VARS_BAT% (
                echo [!] File '%_VS_VARS_BAT%' not exists! 
                echo [!] Please install Visual Studio or update file location in '%~f0'
                goto :error
            )
            call %_VS_VARS_BAT% x64 || goto :error
        )
    ) else (
		goto :error
	)
)

rem Checking if NSIS  available
if not exist %MAKENSIS% (
    echo [!] NSIS binary not found [%MAKENSIS%]
	echo [!] Install NSIS [https://nsis.sourceforge.io/] or\and modify MAKENSIS variable of this script
	goto :error
)

call :read_app_version 				|| goto :error
echo     APPVER         : '%APPVER%'
echo     SOURCES Service: %SERVICE_REPO%
echo     SOURCES CLI    : %CLI_REPO%

call :build_service						|| goto :error
call :build_cli								|| goto :error
call :build_ui								|| goto :error

call :copy_files 							|| goto :error
call :build_installer					|| goto :error

rem THE END
goto :success

:read_app_version
	echo [*] Reading App version ...

	set VERSTR=???
	set PackageJsonFile=%SCRIPTDIR%..\..\package.json
	set VerRegExp=^ *\"version\": *\".*\", *

	set cmd=findstr /R /C:"%VerRegExp%" "%PackageJsonFile%"
	rem Find string in file
	FOR /F "tokens=* USEBACKQ" %%F IN (`%cmd%`) DO SET VERSTR=%%F
	if	"%VERSTR%" == "???" (
		echo [!] ERROR: The file shall contain '"version": "X.X.X"' string
		exit /b 1
 	)
	rem Get substring in quotes
	for /f tokens^=3^ delims^=^" %%a in ("%VERSTR%") do (
			set APPVER=%%a
	)

	goto :eof

:build_service
	echo [*] Building privateline-connect-svc and dependencies...
	call %SERVICE_REPO%\References\Windows\scripts\build-all.bat %APPVER% %CERT_SHA1% || exit /b 1
	goto :eof

:build_cli
	echo [*] Building privateline-connect-cli...
	echo %CLI_REPO%\References\Windows\build.bat
	call %CLI_REPO%\References\Windows\build.bat %APPVER% %CERT_SHA1% || exit /b 1
	goto :eof

:build_ui
	echo ==================================================
	echo ======== BUILDING privateline-connect-ui =========
	echo ==================================================
  cd %SCRIPTDIR%\..\..  || exit /b 1

	@SET NODE_VER=
	FOR /F %%I IN ('node -v') DO @SET "NODE_VER=%%I"
	echo NODE=%NODE_VER%

	@SET NPM_VER=
	FOR /F %%I IN ('npm -v') DO @SET "NPM_VER=%%I"
	echo NPM=%NPM_VER%

	echo.
	echo [*] Installing NPM dependencies...
	call npm install  || exit /b 1

	echo [*] Building UI...
	cd %SCRIPTDIR%  || exit /b 1
	call npm run electron:build || exit /b 1

	goto :eof

:copy_files
	set UI_BINARIES_FOLDER=%SCRIPTDIR%..\..\dist\win-unpacked

	set TIMESTAMP_SERVER=http://timestamp.digicert.com
	if NOT "%CERT_SHA1%" == "" (
		echo.
		echo Signing binary by certificate:  %CERT_SHA1% timestamp: %TIMESTAMP_SERVER%
		echo.
		signtool.exe sign /tr %TIMESTAMP_SERVER% /td sha256 /fd sha256 /sha1 %CERT_SHA1% /v "%UI_BINARIES_FOLDER%\privateline-connect-ui.exe" || exit /b 1
		echo.
		echo Signing SUCCESS
		echo.
	)

	echo [*] Copying files...
	IF exist "%INSTALLER_TMP_DIR%" (
		rmdir /s /q "%INSTALLER_TMP_DIR%"
	)
	mkdir "%INSTALLER_TMP_DIR%"

	echo     Copying UI '%UI_BINARIES_FOLDER%' ...
	xcopy /E /I  "%UI_BINARIES_FOLDER%" "%INSTALLER_TMP_DIR%\ui" || goto :error
	echo     Renaming UI binary to 'privateline-connect-ui.exe' ...
	rename  "%INSTALLER_TMP_DIR%\ui\privateline-connect-ui.exe" "privateline-connect-ui.exe" || goto :error

	echo     Copying other files ...
	set BIN_FOLDER_SERVICE=%SERVICE_REPO%\bin\x86_64\
	set BIN_FOLDER_SERVICE_COMMON_REFS=%SERVICE_REPO%\References\common\
	set BIN_FOLDER_SERVICE_REFS=%SERVICE_REPO%\References\Windows\
	set BIN_FOLDER_CLI=%CLI_REPO%\bin\x86_64\

	set FILES_TO_INTEGRATE=%FILE_LIST%
	if "%GITHUB_ACTIONS%" == "true" (
	  echo "! GITHUB_ACTIONS detected ! It is just a build test."
	  echo "! Skipped compilation integration of some binatires into installer !"

		set FILES_TO_INTEGRATE=%FILE_LIST_CI_TEST%
	)

	setlocal EnableDelayedExpansion
	for /f "tokens=*" %%i in (%FILES_TO_INTEGRATE%) DO (
		set SRCPATH=???
		if exist "%BIN_FOLDER_SERVICE%%%i" set SRCPATH=%BIN_FOLDER_SERVICE%%%i
		if exist "%BIN_FOLDER_CLI%%%i" set SRCPATH=%BIN_FOLDER_CLI%%%i
		if exist "%BIN_FOLDER_SERVICE_COMMON_REFS%%%i" set SRCPATH=%BIN_FOLDER_SERVICE_COMMON_REFS%%%i
		if exist "%BIN_FOLDER_SERVICE_REFS%%%i" set SRCPATH=%BIN_FOLDER_SERVICE_REFS%%%i
		if exist "%BIN_FOLDER_APP%%%i"  set SRCPATH=%BIN_FOLDER_APP%%%i
		if exist "%SCRIPTDIR%Installer\%%i" set SRCPATH=%SCRIPTDIR%Installer\%%i
		if !SRCPATH! == ??? (
			echo FILE '%%i' NOT FOUND!
			exit /b 1
		)
		echo     !SRCPATH!

		IF NOT EXIST "%INSTALLER_TMP_DIR%\%%i\.." (
			MKDIR "%INSTALLER_TMP_DIR%\%%i\.."
		)

		copy /y "!SRCPATH!" "%INSTALLER_TMP_DIR%\%%i" > NUL
		IF !errorlevel! NEQ 0 (
			ECHO     Error: failed to copy "!SRCPATH!" to "%INSTALLER_TMP_DIR%"
			EXIT /B 1
		)
	)
	goto :eof

:build_installer
	echo [*] Building installer...

	echo [ ] Verifying files ...
	if NOT "%CERT_SHA1%" == "" (
		call "%PATH_UI_REPO%\References\Windows\verify-bin-signs.bat" || exit /b 1
	)

	for /F "tokens=1,2 delims=: " %%a in (%SCRIPTDIR%\Installer\release-files-SHA256.txt) do (
		call "%SCRIPTDIR%\verify-file-hashsum-sha256.bat" "%INSTALLER_TMP_DIR%\%%a" %%b || exit /b 1
	)
	
	cd %SCRIPTDIR%\Installer

	SET OUT_FILE="%INSTALLER_OUT_DIR%\privateLINE-Connect-v%APPVER%.exe"
	
	REM If this is a release build, then compress. If a debug build (called via build-debug.bat), then don't compress in order to build faster.
	echo:
	IF [%COMPRESS%] == [off] (
		echo COMPRESS=off
		echo:
		%MAKENSIS% /DPRODUCT_VERSION=%APPVER% /DOUT_FILE=%OUT_FILE% /DSOURCE_DIR=%INSTALLER_TMP_DIR% "/XSetCompress off" "privateLINE Connect.nsi"
	) ELSE (
		echo COMPRESS=lzma
		echo:
		%MAKENSIS% /DPRODUCT_VERSION=%APPVER% /DOUT_FILE=%OUT_FILE% /DSOURCE_DIR=%INSTALLER_TMP_DIR% "/XSetCompress auto" "/XSetCompressor /SOLID /FINAL lzma" "privateLINE Connect.nsi"
	)

	IF not ERRORLEVEL 0 (
		ECHO [!] Error: failed to create installer
		EXIT /B 1
	)
	goto :eof

:success
	goto :remove_tmp_vars_before_exit
	echo [*] SUCCESS
	exit /b 0

:error
	goto :remove_tmp_vars_before_exit
	echo [!] privateLINE Connect installer build FAILED with error #%errorlevel%.
	exit /b %errorlevel%

:remove_tmp_vars_before_exit
	endlocal
	goto :eof
