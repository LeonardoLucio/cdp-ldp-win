# CDPR-WIN - WEB

Aplicativo desktop para descoberta de vizinhos de rede por CDP e LLDP no Windows.

## Requisitos

- Windows 10 ou posterior.
- Python 3.10 ou posterior para executar a partir do codigo.
- Npcap para captura de pacotes. O instalador gerado inclui o instalador do Npcap.
- WebView2 Runtime no Windows.
- Execute como administrador se o Npcap exigir permissao elevada para capturar.

## Executar do codigo

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

## Gerar o executavel e o instalador

Instale as dependencias de build e o Inno Setup 6. Antes do build, baixe o Npcap 1.88 em https://npcap.com/#download e salve-o na raiz como `npcap-1.88.exe`. Esse binario e excluido do Git.

```powershell
python -m pip install -r requirements-build.txt
pyinstaller --clean --noconfirm BlackWorks.spec
ISCC.exe BlackWorks.iss
```

O instalador e escrito em `Output/BlackWorks_Setup_v1.1.exe`. Builds, ambientes virtuais, banco local e executaveis sao ignorados pelo Git.

## Captura

O aplicativo captura quadros Ethernet CDP e LLDP na interface escolhida, mostra os dados decodificados e salva o historico local em SQLite. A descoberta depende de a interface receber anuncios do equipamento vizinho.
