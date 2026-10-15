; Inno Setup 6 - BlackWorks
[Setup]
AppId={{8B1B679B-893C-4D2A-94B6-D4D2E555A201}
AppName=BlackWorks - Descoberta de Portas
AppVersion=1.1.0
AppPublisher=BlackWorks
DefaultDirName={autopf}\BlackWorks
DefaultGroupName=BlackWorks
OutputDir=Output
OutputBaseFilename=BlackWorks_Setup_v1.1
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\BlackWorks.exe
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "Criar atalho na Área de Trabalho"; GroupDescription: "Atalhos adicionais:"

[Files]
Source: "dist\BlackWorks\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "npcap-1.88.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
Name: "{group}\BlackWorks"; Filename: "{app}\BlackWorks.exe"; IconFilename: "{app}\icon.ico"
Name: "{group}\Desinstalar BlackWorks"; Filename: "{uninstallexe}"
Name: "{autodesktop}\BlackWorks"; Filename: "{app}\BlackWorks.exe"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Run]
Filename: "{tmp}\npcap-1.88.exe"; Parameters: "/loopback_support=yes"; StatusMsg: "Instalando o Npcap..."; Flags: waituntilterminated
Filename: "{app}\BlackWorks.exe"; Description: "Iniciar BlackWorks"; Flags: nowait postinstall skipifsilent
