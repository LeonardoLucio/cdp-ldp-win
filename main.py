import socket
import sys
import threading
import time
import uvicorn
import webview

# Importa o app FastAPI do seu web_app.py
from web_app import app


class Api:
    """Classe responsável por expor métodos Python para o JavaScript (pywebview)."""

    def __init__(self):
        self._window = None

    def set_window(self, window):
        self._window = window

    def save_file(self, content, filename, file_type):
        """Abre a caixa de diálogo nativa do SO para salvar o arquivo de exportação."""
        if not self._window:
            return {"success": False, "error": "Janela não inicializada"}

        # Define os filtros de extensão
        if file_type == 'csv':
            file_types = ('Arquivos CSV (*.csv)', 'Todos os arquivos (*.*)')
        else:
            file_types = ('Arquivos JSON (*.json)', 'Todos os arquivos (*.*)')

        # Abre o diálogo de salvamento nativo do SO
        save_path = self._window.create_file_dialog(
            webview.SAVE_DIALOG,
            directory='',
            save_filename=filename,
            file_types=file_types
        )

        # Se o usuário escolheu um caminho e confirmou
        if save_path:
            path = save_path[0] if isinstance(save_path, (list, tuple)) else save_path

            try:
                # Trata quebras de linha para manter formatação correta
                formatted_content = content.replace("\r\n", "\n")

                # Escreve o arquivo no disco (utf-8-sig garante suporte a acentos no Excel)
                with open(path, 'w', encoding='utf-8-sig', newline='') as f:
                    f.write(formatted_content)
                return {"success": True, "path": path}
            except Exception as e:
                return {"success": False, "error": str(e)}

        return {"success": False, "cancelled": True}


class ServerThread(threading.Thread):
    """Thread dedicada para gerenciar a execução e desligamento limpo do Uvicorn."""

    def __init__(self):
        super().__init__(daemon=True)
        config = uvicorn.Config(app, host="127.0.0.1", port=8000, log_level="error")
        self.server = uvicorn.Server(config)

    def run(self):
        self.server.run()

    def stop(self):
        self.server.should_exit = True


if __name__ == "__main__":
    # 1. Instância da API do pywebview
    api = Api()

    # 2. Inicia o servidor Uvicorn em segundo plano
    server_thread = ServerThread()
    server_thread.start()

    # Aguarda o servidor estar pronto para evitar uma janela em branco.
    deadline = time.monotonic() + 10
    while server_thread.is_alive() and time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", 8000), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    else:
        server_thread.stop()
        server_thread.join(timeout=2)
        raise RuntimeError("The local server failed to start on port 8000.")

    # 3. Abre a janela desktop nativa passando a API vinculada
    window = webview.create_window(
        title="BlackWorks - Descoberta de Porta",
        url="http://127.0.0.1:8000",
        width=1000,
        height=720,
        resizable=True,
        js_api=api  # <--- Expõe a classe Api para o frontend JS
    )

    # Passa a referência da janela para a API
    api.set_window(window)

    # 4. Inicia a interface gráfica
    webview.start()

    # Encerra o servidor local ao fechar o app
    server_thread.stop()
    sys.exit(0)