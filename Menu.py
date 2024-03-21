import os
import requests
import subprocess
import socket
from colorama import Fore, Style

def limpar_tela():
    if os.name == 'posix':
        _ = os.system('clear')
    else:
        _ = os.system('cls')

def instalar_bibliotecas():
    subprocess.call(['pip', 'install', 'requests', 'colorama'])

def verificar_portas():
    limpar_tela()
    site = input("Digite o site: ")
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
    limpar_tela()

def verificar_protocolo():
    limpar_tela()
    site = input("Digite o site: ")
    try:
        socket.gethostbyname(site)
        print(Fore.GREEN + "O site é TCP.")
    except socket.gaierror:
        print(Fore.GREEN + "O site é UDP.")

    input(Fore.WHITE + "Pressione Enter para voltar ao menu...")
    limpar_tela()

def consultar_ip():
    limpar_tela()
    site = input("Digite o site: ")
    try:
        ip = socket.gethostbyname(site)
        print(Fore.GREEN + f"O IP do site é: {ip}")
    except socket.gaierror:
        print(Fore.RED + "Não foi possível encontrar o IP do site.")

    input(Fore.WHITE + "Pressione Enter para voltar ao menu...")
    limpar_tela()

def verificar_status():
    limpar_tela()
    site = input("Digite o site: ")
    try:
        response = requests.get(site)
        if response.status_code == 200:
            print(Fore.GREEN + "O site está online.")
            print(f"Tempo de resposta: {response.elapsed.total_seconds()} segundos")
        else:
            print(Fore.RED + f"O site está offline. Status do site: {response.status_code}")
    except requests.ConnectionError:
        print(Fore.RED + "O site está fora do ar ou não foi possível conectar.")

    input(Fore.WHITE + "Pressione Enter para voltar ao menu...")
    limpar_tela()

def verificar_servidor():
    limpar_tela()
    site = input("Digite o site: ")
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
    limpar_tela()

def exibir_menu():
    print(Fore.BLUE + "======= MENU =======")
    print("1. Verificar portas abertas")
    print("2. Verificar protocolo")
    print("3. Consultar IP")
    print("4. Verificar status do site")
    print("5. Verificar informações do servidor")
    print("6. Créditos")
    print("7. Sair")
    print(Style.RESET_ALL)

def main():
    instalar_bibliotecas()

    while True:
        limpar_tela()
        exibir_menu()
        escolha = input("Escolha uma opção: ")

        if escolha == "1":
            verificar_portas()
        elif escolha == "2":
            verificar_protocolo()
        elif escolha == "3":
            consultar_ip()
        elif escolha == "4":
            verificar_status()
        elif escolha == "5":
            verificar_servidor()
        elif escolha == "6":
            print("Criado por zedhacking, salve Alexandre")
            input("Pressione Enter para voltar ao menu...")
            limpar_tela()
        elif escolha == "7":
            print("Saindo...")
            break
        else:
            print(Fore.RED + "Opção inválida. Por favor, escolha uma opção válida.")
            input("Pressione Enter para voltar ao menu...")
            limpar_tela()

if __name__ == "__main__":
    main()
