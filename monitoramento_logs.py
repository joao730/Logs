import os
import time
import csv
import platform
import subprocess
import hashlib
from datetime import datetime

    # Apenas Linux: usado para mapear UID para nome de usuário
try:
        import pwd
except ImportError:
        pwd = None

    # Caminho para o arquivo CSV de saída
LOG_FILE = "eventos_seguranca.csv"

    # Lista de arquivos críticos a monitorar
ARQUIVOS_CRITICOS = (
        ["/etc/passwd", "/etc/shadow"] if platform.system() != "Windows"
        else [r"C:\Windows\System32\drivers\etc\hosts"]
    )

    # Estado inicial dos arquivos monitorados
estado_anterior = {}

    # Usuários do sistema a ignorar
USUARIOS_SISTEMA = {
        "Debian-gdm", "gdm", "nobody", "systemd-network", "systemd-resolve",
        "systemd-timesync", "messagebus", "ntp", "sshd", "root"
    }

    # Controle de eventos do auditd
ULTIMO_EVENTO_HASH = None

    # Inicializa o CSV se ele não existir
if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode="w", newline="") as arquivo:
            csv.writer(arquivo).writerow(["Timestamp", "Evento", "Usuário", "Descrição"])

def log_event(tipo, usuario, descricao):
        timestamp = datetime.now().isoformat()
        with open(LOG_FILE, mode="a", newline="") as arquivo:
            csv.writer(arquivo).writerow([timestamp, tipo, usuario, descricao])
        print(f"[{timestamp}] {tipo} - Usuário: {usuario} - {descricao}")

    # ------------------------
    # MONITORAMENTO DE LOGIN - LINUX
    # ------------------------

def monitor_login_linux():
        try:
            ssh_output = subprocess.check_output("journalctl _COMM=sshd -n 20 --no-pager", shell=True).decode()
            for linha in ssh_output.splitlines():
                if "Failed password" in linha or "Accepted" in linha:
                    usuario = extrair_usuario_ssh(linha)
                    if usuario and usuario not in USUARIOS_SISTEMA:
                        tipo = "LOGIN_FAIL" if "Failed" in linha else "LOGIN_OK"
                        log_event(tipo, usuario, linha.strip())

            local_output = subprocess.check_output("journalctl _SYSTEMD_UNIT=systemd-logind.service -n 20 --no-pager", shell=True).decode()
            for linha in local_output.splitlines():
                if "New session" in linha or "FAILED LOGIN" in linha or "authentication failure" in linha:
                    usuario = extrair_usuario_local(linha)
                    if usuario and usuario not in USUARIOS_SISTEMA:
                        tipo = "LOGIN_FAIL" if "FAILED" in linha or "failure" in linha else "LOGIN_OK"
                        log_event(tipo, usuario, linha.strip())
        except Exception as e:
            log_event("ERRO", "N/A", f"Erro ao monitorar logins: {e}")

def extrair_usuario_ssh(linha):
        partes = linha.split()
        if "for" in partes:
            idx = partes.index("for")
            if idx + 1 < len(partes):
                return partes[idx + 1]
        return None

def extrair_usuario_local(linha):
        if "user" in linha:
            try:
                pos = linha.index("user")
                return linha[pos + 5:].split()[0].strip(".")
            except:
                return None
        return None

    # ------------------------
    # MONITORAMENTO DE LOGIN - WINDOWS
    # ------------------------

def monitor_login_windows():
        try:
            comando = 'wevtutil qe Security /q:"*[System[(EventID=4625)]]" /f:text /c:5'
            output = subprocess.check_output(comando, shell=True).decode("utf-8", errors="ignore")
            for linha in output.splitlines():
                if "Account Name:" in linha:
                    usuario = linha.split(":")[-1].strip()
                    if usuario and usuario not in USUARIOS_SISTEMA:
                        log_event("LOGIN_FAIL", usuario, linha.strip())
        except Exception as e:
            log_event("ERRO", "N/A", f"Erro ao ler eventos do Windows: {e}")

    # ------------------------
    # MONITORAMENTO DE MODIFICAÇÕES DE ARQUIVOS
    # ------------------------

def monitor_modificacao_arquivos():
        for arquivo in ARQUIVOS_CRITICOS:
            if os.path.exists(arquivo):
                try:
                    mtime = os.path.getmtime(arquivo)
                    if estado_anterior.get(arquivo) != mtime:
                        estado_anterior[arquivo] = mtime
                        log_event("FILE_MOD", "N/A", f"Modificação detectada em arquivo crítico: {arquivo}")
                except Exception as e:
                    log_event("ERRO", "N/A", f"Erro ao verificar {arquivo}: {e}")

    # ------------------------
    # MONITORAMENTO AUDITD
    # ------------------------

def extrair_usuario_auditd(evento):
    usuario = "N/A"
    for linha in evento.splitlines():
        if "auid=" in linha:
            try:
                auid_str = linha.split("auid=")[1].split()[0]
                auid = int(auid_str)
                if auid in (-1, 4294967295):
                    usuario = "SYSTEM"
                elif pwd:
                    usuario = pwd.getpwuid(auid).pw_name
                break
            except Exception:
                pass
    return usuario


def monitor_auditd_passwd():
    global ULTIMO_EVENTO_HASH
    try:
        output = subprocess.check_output("ausearch -k passwd_changes -ts recent -i", shell=True).decode()
        if not output.strip():
            return

        eventos = output.strip().split("----")
        for evento in eventos:
            if "/etc/passwd" in evento and "success=yes" in evento:
                evento_limpo = "\n".join(sorted(set(evento.strip().splitlines())))
                hash_evento = hashlib.md5(evento_limpo.encode()).hexdigest()
                if hash_evento == ULTIMO_EVENTO_HASH:
                    continue
                ULTIMO_EVENTO_HASH = hash_evento

                usuario = extrair_usuario_auditd(evento)

                log_event("AUDITD_MOD", usuario, "Alteração no /etc/passwd detectada via auditd")
    except Exception as e:
        log_event("ERRO", "N/A", f"Erro ao verificar auditd: {e}")

    # ------------------------
    # EXECUÇÃO PRINCIPAL
    # ------------------------

def main():
    exec_uma_vez = os.getenv("CI") == "true"  # GitHub Actions define CI=true
    print("Iniciando monitoramento...")

    try:
        while True:
            sistema = platform.system()
            monitor_modificacao_arquivos()

            if sistema == "Linux":
                monitor_login_linux()
                monitor_auditd_passwd()
            elif sistema == "Windows":
                monitor_login_windows()
            else:
                log_event("INFO", "N/A", f"Sistema {sistema} não suportado.")

            if exec_uma_vez:
                break  # para o loop se estiver rodando no CI
            
            time.sleep(900)
    except KeyboardInterrupt:
        print("Monitoramento encerrado pelo usuário.")