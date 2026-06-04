; SentinelCore - Inno Setup Installer Script
; Creates SentinelCoreSetup.exe
; Build with: ISCC.exe installer/setup.iss

#define MyAppName "SentinelCore"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "SentinelCore Security"
#define MyAppURL "https://sentinelcore.security"
#define MyAppDescription "AI-Powered Cybersecurity Platform"
#define MyAppExeName "SentinelCore.exe"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=..\README.md
; OutputDir is relative to the .iss file location
OutputDir=..\dist
OutputBaseFilename=SentinelCoreSetup
SetupIconFile=
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequiredOverridesAllowed=dialog
; Require admin for firewall/registry access
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";   Description: "{cm:CreateDesktopIcon}";  GroupDescription: "{cm:AdditionalIcons}"
Name: "quicklaunch";   Description: "Create &Quick Launch icon"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startupentry";  Description: "Start SentinelCore automatically with Windows"; GroupDescription: "Startup:"; Flags: unchecked

[Files]
; Main executable (built by PyInstaller)
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

; Config and database directories
Source: "..\config\*";        DestDir: "{app}\config";   Flags: ignoreversion recursesubdirs
Source: "..\models\";         DestDir: "{app}\models";   Flags: createallsubdirs

; README
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\{#MyAppName}";                IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}";          IconFilename: "{app}\{#MyAppExeName}";  Tasks: desktopicon

[Registry]
; Auto-start entry (only if user selected startup task)
Root: HKCU; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; \
     ValueType: string; ValueName: "{#MyAppName}"; \
     ValueData: """{app}\{#MyAppExeName}"""; \
     Flags: uninsdeletevalue; Tasks: startupentry

[Run]
Filename: "{app}\{#MyAppExeName}"; \
  Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; \
  Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=SentinelCore_Block_*"; \
  Flags: runhidden

[Code]
function InitializeSetup: Boolean;
begin
  Result := True;
  MsgBox('Welcome to ' + '{#MyAppName}' + ' ' + '{#MyAppVersion}' + '.' + #13#10 +
         'An AI-powered cybersecurity platform for Windows.' + #13#10#13#10 +
         'NOTE: Administrator privileges are required for firewall and registry access.',
         mbInformation, MB_OK);
end;
