from scapy.all import *
import requests
import subprocess
import socket
import cloudflare
from colorama import Fore, Style

def instalar_bibliotecas():
    subprocess.call(['pip', 'install', 'requests', 'cloudflare', 'colorama', 'scapy'])

def verificar_portas(site):
    try:
        print(Fore.GREEN + "Verificando portas abertas...\n")
        for porta in range(1, 1025):  # Verificar as primeiras 1024 portas comuns
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            resultado = sock.connect_ex((site, porta))
            if resultado == 0:
                print(f"A porta {porta} está aberta.")
            sock.close()
    except socket.error as e:
        print(Fore.RED + f"Erro ao verificar portas: {e}")

    input(Fore.WHITE + "Pressione Enter para voltar ao menu...")

def verificar_protocolo(site):
    try:
        socket.gethostbyname(site)
        print(Fore.GREEN + "O site é TCP.")
    except socket.gaierror:
        print(Fore.GREEN + "O site é UDP.")

    input(Fore.WHITE + "Pressione Enter para voltar ao menu...")

def consultar_ip(site):
    try:
        ip = socket.gethostbyname(site)
        print(Fore.GREEN + f"O IP do site é: {ip}")
    except socket.gaierror:
        print(Fore.RED + "Não foi possível encontrar o IP do site.")

    input(Fore.WHITE + "Pressione Enter para voltar ao menu...")

def verificar_status(site):
    try:
        response = requests.get(site)
        print(Fore.GREEN + f"Status do site: {response.status_code}")
        print(f"Tempo de resposta: {response.elapsed.total_seconds()} segundos")
    except requests.ConnectionError:
        print(Fore.RED + "O site está fora do ar.")

    input(Fore.WHITE + "Pressione Enter para voltar ao menu...")

def verificar_cloudflare(site):
    try:
        cf = cloudflare.cloudflare()
        protection = cf.check(site)
        if protection:
            print(Fore.GREEN + "O site tem proteção Cloudflare.")
        else:
            print(Fore.RED + "O site não tem proteção Cloudflare.")
    except Exception as e:
        print(Fore.RED + f"Erro ao verificar proteção Cloudflare: {e}")

    input(Fore.WHITE + "Pressione Enter para voltar ao menu...")

def testar_vulnerabilidades(site):
    print(Fore.GREEN + "Testando vulnerabilidades...\n")
    print(Fore.RED + "Atenção: Este teste pode ser intrusivo e deve ser realizado com permissão do proprietário do site.\n")

    # Teste de DDoS (ataque de flood TCP SYN)
    print(Fore.YELLOW + "Realizando teste de vulnerabilidade a ataques DDoS (flood TCP SYN)...")
    pacote = IP(dst=site)/TCP(dport=80, flags="S")
    resposta = sr1(pacote, timeout=2, verbose=False)
    if resposta:
        print(Fore.RED + "O site parece ser vulnerável a ataques DDoS (flood TCP SYN).")
    else:
        print(Fore.GREEN + "O site parece não ser vulnerável a ataques DDoS (flood TCP SYN).")

    # Teste de SQL injection
    print(Fore.YELLOW + "Realizando teste de vulnerabilidade a ataques SQL injection...")
    try:
        # Substitua o payload pelo SQL injection adequado para o seu teste
        payload = "1' OR '1'='1"
        resposta = requests.get(f"{site}?id={payload}")
        if "error in your SQL syntax" in resposta.text:
            print(Fore.RED + "O site parece ser vulnerável a ataques SQL injection.")
        else:
            print(Fore.GREEN + "O site parece não ser vulnerável a ataques SQL injection.")
    except Exception as e:
        print(Fore.RED + f"Erro ao testar vulnerabilidade a ataques SQL injection: {e}")

    print(Fore.GREEN + "Teste de vulnerabilidades concluído.")

    input(Fore.WHITE + "Pressione Enter para voltar ao menu...")

def procurar_painel_admin(site):
    try:
        admin_panel_paths = [
            "admin/", "administrator/", "admin/login", "admin/login.php", "admin/login.html",
            "admin/index", "admin/index.php", "admin/index.html", "admin/home", "admin/home.php",
            "admin/home.html", "admin/controlpanel", "admin/controlpanel.php", "admin/controlpanel.html"
        ]
        
        print(Fore.GREEN + "Procurando por painel de administração...\n")
        for path in admin_panel_paths:
            url = f"http://{site}/{path}"
            response = requests.get(url)
            if response.status_code == 200:
                print(Fore.GREEN + f"Painel de administração encontrado: {url}")
                return
        print(Fore.RED + "Painel de administração não encontrado.")
    except Exception as e:
        print(Fore.RED + f"Erro ao procurar painel de administração: {e}")

    input(Fore.WHITE + "Pressione Enter para voltar ao menu...")

def exibir_menu():
    print(Fore.BLUE + "======= MENU =======")
    print("1. Verificar todas as portas abertas de um site")
    print("2. Verificar se o site é UDP ou TCP")
    print("3. Consultar o IP de um site")
    print("4. Verificar se um site está fora do ar e seu tempo de resposta")
    print("5. Verificar se o site tem proteção Cloudflare")
    print("6. Testar vulnerabilidades (DDoS, SQL injection)")
    print("7. Procurar por painel de administração")
    print("8. Créditos")
    print("9. Sair")
    print(Style.RESET_ALL)  # Resetar estilo para evitar cores indesejadas

def exibir_creditos():
    print("Criado por zedhacking, salve Alexandre")

def main():
    instalar_bibliotecas()

    while True:
        exibir_menu()
        escolha = input("Escolha uma opção: ")

        if escolha == "1":
            site = input("Digite o site: ")
            verificar_portas(site)
        elif escolha == "2":
            site = input("Digite o site: ")
            verificar_protocolo(site)
        elif escolha == "3":
            site = input("Digite o site: ")
            consultar_ip(site)
        elif escolha == "4":
            site = input("Digite o site: ")
            verificar_status(site)
        elif escolha == "5":
            site = input("Digite o site: ")
            verificar_cloudflare(site)
        elif escolha == "6":
            site = input("Digite o site:
