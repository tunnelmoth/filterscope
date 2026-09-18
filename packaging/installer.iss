; Inno Setup script — builds filterscope-setup-<version>.exe on the Windows CI runner.
; Expects dist\filterscope-gui.exe and dist\filterscope.exe next to this repo root.
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define AppName "filterscope"

[Setup]
AppId={{7A0C1C1E-5E1B-4C1E-9C3B-FILTERSCOPE01}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=tunnelmoth
AppPublisherURL=https://github.com/tunnelmoth/filterscope
AppSupportURL=https://github.com/tunnelmoth/filterscope/issues
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
UninstallDisplayIcon={app}\filterscope-gui.exe
OutputDir=..\dist
OutputBaseFilename=filterscope-setup-{#AppVersion}
SetupIconFile=..\filterscope\assets\filterscope.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesInstallIn64BitMode=x64compatible
LicenseFile=..\LICENSE
ChangesEnvironment=yes

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"
Name: "addtopath"; Description: "Add the command-line tool to PATH (filterscope in any terminal)"; GroupDescription: "Command line:"; Flags: unchecked

[Files]
Source: "..\dist\filterscope-gui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\filterscope.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\filterscope"; Filename: "{app}\filterscope-gui.exe"
Name: "{group}\filterscope (terminal)"; Filename: "{app}\filterscope.exe"
Name: "{group}\Uninstall filterscope"; Filename: "{uninstallexe}"
Name: "{autodesktop}\filterscope"; Filename: "{app}\filterscope-gui.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath('{app}')

[Run]
Filename: "{app}\filterscope-gui.exe"; Description: "Launch filterscope"; Flags: nowait postinstall skipifsilent

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + ExpandConstant(Param) + ';', ';' + OrigPath + ';') = 0;
end;
