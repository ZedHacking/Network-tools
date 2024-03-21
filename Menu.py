import requests
import subprocess
import socket
from colorama import Fore, Style
from scapy.all import *

def instalar_bibliotecas():
    subprocess.call(['pip', 'install', 'requests', 'colorama', 'scapy'])

def verificar_portas(site):
    try:
        print(Fore.GREEN + "Verificando portas abertas...\n")
        for porta in range(1, 1025):
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

def testar_vulnerabilidades(site):
    print(Fore.GREEN + "Testando vulnerabilidades...\n")
    print(Fore.RED + "Atenção: Este teste pode ser intrusivo e deve ser realizado com permissão do proprietário do site.\n")

    print(Fore.YELLOW + "Realizando teste de vulnerabilidade a ataques DDoS (flood TCP SYN)...")
    pacote = IP(dst=site)/TCP(dport=80, flags="S")
    resposta = sr1(pacote, timeout=2, verbose=False)
    if resposta:
        print(Fore.RED + "O site parece ser vulnerável a ataques DDoS (flood TCP SYN).")
    else:
        print(Fore.GREEN + "O site parece não ser vulnerável a ataques DDoS (flood TCP SYN).")

    print(Fore.YELLOW + "Realizando teste de vulnerabilidade a ataques SQL injection...")
    try:
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

def verificar_servidor(site):
    try:
        endereco_ip = socket.gethostbyname(site)
        nome_servidor = socket.gethostbyaddr(endereco_ip)[0]
        print(Fore.GREEN + f"O servidor está hospedado em: {endereco_ip}")
        print(Fore.GREEN + f"Nome do servidor: {nome_servidor}")
    except socket.gaierror:
        print(Fore.RED + "Não foi possível encontrar informações sobre o servidor.")
    except Exception as e:
        print(Fore.RED + f"Erro ao verificar informações do servidor: {e}")

    input(Fore.WHITE + "Pressione Enter para voltar ao menu...")

def exibir_menu():
    print(Fore.BLUE + "======= MENU =======")
    print("1. Verificar portas abertas")
    print("2. Verificar protocolo")
    print("3. Consultar IP")
    print("4. Verificar status do site")
    print("5. Testar vulnerabilidades")
    print("6. Verificar informações do servidor")
    print("7. Créditos")
    print("8. Sair")
    print(Style.RESET_ALL)

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
            testar_vulnerabilidades(site)
        elif escolha == "6":
            site = input("Digite o site: ")
            verificar_servidor(site)
        elif escolha == "7":
            print("Criado por zedhacking, salve Alexandre")
        elif escolha == "8":
            print("Saindo...")
            break
        else:
            print(Fore.RED + "Opção inválida. Por favor, escolha uma opção válida.")

if __name__ == "__main__":
    main()
