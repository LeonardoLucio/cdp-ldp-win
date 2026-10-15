"""
BlackWorks Web
==============
Versão web do BlackWorks com suporte para empacotamento desktop (PyInstaller/PyWebView)
ou execução via servidor local FastAPI.

Como usar:
    Linux:   sudo python web_app.py
    Windows: abrir terminal como Administrador e rodar `python web_app.py`

Depois abra http://localhost:8000 no navegador.
"""

import sys
import sqlite3
import time
import os
import subprocess
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
import psutil

from scapy.sendrecv import sniff
from scapy.interfaces import get_working_ifaces

# Importa os decodificadores e constantes do CDP e LLDP
from core.cdp import (
    CDP_MULTICAST,
    decode_cdp_packet,
    LLDP_MULTICAST,
    decode_lldp_packet,
)


# ============================================================
# COMPATIBILIDADE DE DIRETÓRIOS (PyInstaller vs Script)
# ============================================================
if getattr(sys, "frozen", False):
    # Executando empacotado via PyInstaller
    BASE_DIR = Path(sys._MEIPASS)
else:
    # Executando como script Python normal
    BASE_DIR = Path(__file__).parent

# Banco de dados salvo no diretório atual de execução do usuário
DATA_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "BlackWorks"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "history.db"

app = FastAPI(title="BlackWorks Web")


# ============================================================
# HELPER: FORMATAR VELOCIDADE DO LINK
# ============================================================

def format_speed(speed_mbps: int) -> str:
    """Converte a velocidade retornada pelo psutil (em Mbps) para string legível."""
    if not speed_mbps or speed_mbps <= 0:
        return "Desconhecida / Down"
    if speed_mbps >= 1000:
        if speed_mbps % 1000 == 0:
            return f"{speed_mbps // 1000} Gbps"
        return f"{speed_mbps / 1000:.1f} Gbps"
    return f"{speed_mbps} Mbps"


# ============================================================
# BANCO DE DADOS (HISTÓRICO LOCAL)
# ============================================================

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Criar tabela caso não exista
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS discoveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            executed_by TEXT,
            interface TEXT NOT NULL,
            link_speed TEXT,
            protocol TEXT,
            hostname TEXT,
            remote_port TEXT,
            ip TEXT,
            platform TEXT,
            native_vlan TEXT,
            software TEXT,
            capabilities TEXT
        )
        """
    )
    
    # Migrações simples: Adiciona colunas faltantes caso o banco já existisse
    cursor.execute("PRAGMA table_info(discoveries)")
    columns = [col[1] for col in cursor.fetchall()]
    
    if "link_speed" not in columns:
        cursor.execute("ALTER TABLE discoveries ADD COLUMN link_speed TEXT")
        
    if "executed_by" not in columns:
        cursor.execute("ALTER TABLE discoveries ADD COLUMN executed_by TEXT")

    conn.commit()
    conn.close()


init_db()


# ============================================================
# RESOLUÇÃO DE INTERFACES (WINDOWS & SCAPY)
# ============================================================

def resolve_scapy_interface(interface_name: str) -> str:
    """
    Mapeia o nome amigável do psutil (ex: 'Ethernet 2') para o nome NPF
    reconhecido pelo Scapy/Npcap no Windows. Em outros SOs, retorna o próprio nome.
    """
    try:
        for iface in get_working_ifaces():
            if iface.name == interface_name or iface.description == interface_name:
                return iface.network_name
    except Exception:
        pass
    return interface_name


def get_interface_speed(interface_name: str) -> str:
    """Obtém a velocidade negociada da porta física via psutil."""
    try:
        stats = psutil.net_if_stats()
        if interface_name in stats:
            return format_speed(stats[interface_name].speed)
    except Exception:
        pass
    return "Desconhecida"


# ============================================================
# CAPTURA DE PACOTES (CDP & LLDP)
# ============================================================

def capture_once(interface: str, mode: str, timeout: int):
    """
    Roda a captura até encontrar UM vizinho do modo especificado (CDP ou LLDP)
    ou estourar o timeout.
    """
    target_iface = resolve_scapy_interface(interface)
    result = {}

    def on_packet(packet):
        raw = bytes(packet)

        neighbor = None
        if mode.lower() == "cdp":
            neighbor = decode_cdp_packet(raw)
        elif mode.lower() == "lldp":
            neighbor = decode_lldp_packet(raw)
        else:
            # Tenta ambos caso não especificado
            neighbor = decode_cdp_packet(raw) or decode_lldp_packet(raw)

        if neighbor:
            # Anexa a velocidade local negociada na porta física
            neighbor["link_speed"] = get_interface_speed(interface)
            result["neighbor"] = neighbor

    # Filtro BPF ajustado ao modo selecionado
    if mode.lower() == "cdp":
        bpf_filter = f"ether dst {CDP_MULTICAST}"
    elif mode.lower() == "lldp":
        bpf_filter = "ether proto 0x88cc or (vlan and ether proto 0x88cc)"
    else:
        bpf_filter = f"ether dst {CDP_MULTICAST} or ether proto 0x88cc or (vlan and ether proto 0x88cc)"

    sniff(
        iface=target_iface,
        filter=bpf_filter,
        prn=on_packet,
        stop_filter=lambda p: "neighbor" in result,
        timeout=timeout,
        store=False,
    )

    return result.get("neighbor")


def save_discovery(interface: str, neighbor: dict, executed_by: str = "Técnico"):
    capabilities = neighbor.get("capabilities", "")
    if isinstance(capabilities, list):
        capabilities = ", ".join(capabilities)

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        INSERT INTO discoveries
            (timestamp, executed_by, interface, link_speed, protocol, hostname, remote_port, ip,
             platform, native_vlan, software, capabilities)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            time.strftime("%Y-%m-%d %H:%M:%S"),
            executed_by,
            interface,
            neighbor.get("link_speed", "Desconhecida"),
            neighbor.get("protocol", "Desconhecido"),
            neighbor.get("hostname"),
            neighbor.get("remote_port"),
            neighbor.get("ip"),
            neighbor.get("platform"),
            neighbor.get("native_vlan"),
            neighbor.get("software"),
            capabilities,
        ),
    )
    conn.commit()
    conn.close()


# ============================================================
# ENDPOINTS DA API
# ============================================================

class DiscoverRequest(BaseModel):
    interface: str
    mode: Literal["cdp", "lldp"] = "cdp"
    timeout: int = Field(default=60, ge=1, le=300)
    executed_by: Optional[str] = "Técnico"


class ExportPayload(BaseModel):
    content: str
    filename: str
    file_type: str


@app.get("/api/interfaces")
def list_interfaces():
    """
    Lista interfaces de rede do sistema operacional utilizando o psutil.
    """
    interfaces = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for name, addr_list in addrs.items():
        is_up = stats[name].isup if name in stats else False
        speed_mbps = stats[name].speed if name in stats else 0
        
        mac = next(
            (a.address for a in addr_list if a.family.name in ("AF_LINK", "AF_PACKET")),
            "N/A",
        )
        ipv4 = next(
            (a.address for a in addr_list if a.family.name == "AF_INET"),
            "N/A",
        )
        interfaces.append(
            {
                "name": name,
                "status": "up" if is_up else "down",
                "speed": format_speed(speed_mbps),
                "mac": mac,
                "ipv4": ipv4,
            }
        )

    return interfaces


@app.post("/api/discover")
async def discover(req: DiscoverRequest):
    try:
        neighbor = await run_in_threadpool(capture_once, req.interface, req.mode, req.timeout)
    except Exception as exc:
        # Scapy/Npcap often raises an OS-specific exception when the selected
        # adapter is unavailable or cannot be opened. Return JSON the UI can show.
        message = str(exc).strip() or exc.__class__.__name__
        raise HTTPException(
            status_code=400,
            detail=(
                f"N\u00e3o foi poss\u00edvel capturar na interface '{req.interface}'. "
                "Selecione uma interface de rede v\u00e1lida e conectada e tente novamente. "
                f"Detalhe: {message}"
            ),
        ) from exc

    if not neighbor:
        mode_upper = req.mode.upper()
        raise HTTPException(
            status_code=408,
            detail=(
                f"Nenhum pacote {mode_upper} recebido em {req.timeout}s. "
                "Confira o cabo, a interface selecionada e se o switch "
                f"envia anúncios {mode_upper} nessa porta."
            ),
        )

    # Execução assíncrona da gravação no SQLite
    user_name = req.executed_by.strip() if req.executed_by and req.executed_by.strip() else "Técnico"
    await run_in_threadpool(save_discovery, req.interface, neighbor, user_name)
    return neighbor


@app.get("/api/history")
def get_history(mode: Optional[str] = Query(None), limit: int = 50):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    if mode:
        rows = conn.execute(
            "SELECT * FROM discoveries WHERE UPPER(protocol) = UPPER(?) ORDER BY id DESC LIMIT ?",
            (mode, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM discoveries ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        
    conn.close()
    return [dict(row) for row in rows]


@app.delete("/api/history")
def clear_history(mode: Optional[str] = Query(None)):
    conn = sqlite3.connect(DB_PATH)
    if mode:
        conn.execute("DELETE FROM discoveries WHERE UPPER(protocol) = UPPER(?)", (mode,))
    else:
        conn.execute("DELETE FROM discoveries")
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.post("/api/export")
def export_file(payload: ExportPayload):
    """
    Salva o arquivo exportado diretamente na pasta Downloads do usuário
    e abre o gerenciador de arquivos destacando o item.
    """
    try:
        downloads_dir = Path.home() / "Downloads"
        downloads_dir.mkdir(parents=True, exist_ok=True)
        filename = Path(payload.filename).name
        if not filename or filename in {".", ".."}:
            raise HTTPException(status_code=400, detail="Nome de arquivo inv?lido.")
        file_path = downloads_dir / filename

        # Se já existir arquivo com esse nome, adiciona um sufixo numérico (ex: nome_(1).csv)
        counter = 1
        base_name, ext = os.path.splitext(filename)
        while file_path.exists():
            file_path = downloads_dir / f"{base_name}_({counter}){ext}"
            counter += 1

        # Trata as quebras de linha enviadas pelo JS para garantir compatibilidade cross-platform
        formatted_content = payload.content.replace("\r\n", "\n")

        # Salva o arquivo no disco (utf-8-sig para acentuação e acentuação gráfica corretas no Excel)
        with open(file_path, 'w', encoding='utf-8-sig', newline='') as f:
            f.write(formatted_content)

        # Tenta abrir o gerenciador de arquivos e destacar o arquivo salvo
        try:
            if sys.platform == 'win32':
                subprocess.run(["explorer", f"/select,{file_path}"], check=False)
            elif sys.platform == 'darwin':
                subprocess.run(['open', '-R', file_path])
            else:
                subprocess.run(['xdg-open', os.path.dirname(file_path)])
        except Exception:
            pass

        return {"success": True, "path": str(file_path)}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Servir a página web (arquivos estáticos)
static_dir = BASE_DIR / "static"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
