@echo off
setlocal

REM === Personal CONFIG PATHS ===
:: Path to get to the ghidra_string_sniper directory.  Example: C:\Users\RPI\Documents\GitHub\ghidra-string-sniper\ghidra_string_sniper_ext\dist
:: If you do not have a \dist folder inside ghidra_string_sniper, make one before running this script and make sure to include the \dist folder at the end of your path below.
set "DIST=ENTER PATH HERE"
:: Path to get to your Ghidra's extensions folder.  Example: C:\Users\RPI\AppData\Roaming\ghidra\ghidra_11.4.2_PUBLIC\Extensions
set "GHIDRA_EXT_PARENT=ENTER PATH HERE"
:: Path to get to your folder that contains your ghidraRun.bat file.  Example: C:\Users\RPI\PC\Desktop\ghidra_11.4.2_PUBLIC"
set "GHIDRA_INSTALL=ENTER PATH HERE"

:: NOTE Pt1: When launching Ghidra for the first time with this extension, you will need to enable the plugin when prompted.  
:: NOTE Pt2: If no prompt is provided, you must go to file, configure, miscellaneous configure, and then check off the plugin.

echo Step 1: Delete dist folder contents
if exist "%DIST%" (
    rmdir /S /Q "%DIST%"
)
mkdir "%DIST%"



echo Step 2: Run Gradle build
:: Will make dist folder in your ghidra string sniper directory.
call gradle -PGHIDRA_INSTALL_DIR="%GHIDRA_INSTALL%"


echo Step 3: Remove previous Ghidra extension
if exist "%GHIDRA_EXT_PARENT%\ghidra_string_sniper_ext" (
    rmdir /S /Q "%GHIDRA_EXT_PARENT%\ghidra_string_sniper_ext"
)


echo Step 4: Unzip all builds into Extensions
for %%F in ("%DIST%\*.zip") do (
    echo Extracting %%~nxF...
    powershell -Command "Expand-Archive -Path '%%~fF' -DestinationPath '%GHIDRA_EXT_PARENT%'"
)

echo endlocal
echo exit
