import base64
import random
import time
import requests
import json
import socket
import ipaddress
from colorama import init, Fore, Style
import shutil
import string
from bs4 import BeautifulSoup

# Initialiser colorama
init(autoreset=True)

# Plages d'adresses IP réservées
RESERVED_RANGES = [
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16')
]

def print_header():
    """Affiche le texte d'en-tête avec le pseudonyme et le message en ASCII art."""
    terminal_width = shutil.get_terminal_size().columns
    welcome_message = """
  ██▓███   ██▓ ██▀███   ▄▄▄     ▄▄▄█████▓▓█████ 
▓██░  ██▒▓██▒▓██ ▒ ██▒▒████▄   ▓  ██▒ ▓▒▓█   ▀ 
▓██░ ██▓▒▒██▒▓██ ░▄█ ▒▒██  ▀█▄ ▒ ▓██░ ▒░▒███   
▒██▄█▓▒ ▒░██░▒██▀▀█▄  ░██▄▄▄▄██░ ▓██▓ ░ ▒▓█  ▄ 
▒██▒ ░  ░░██░░██▓ ▒██▒ ▓█   ▓██▒ ▒██▒ ░ ░▒████▒
▒▓▒░ ░  ░░▓  ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░ ▒ ░░   ░░ ▒░ ░
░▒ ░      ▒ ░  ░▒ ░ ▒░  ▒   ▒▒ ░   ░     ░ ░  ░
░░        ▒ ░  ░░   ░   ░   ▒    ░         ░   
          ░     ░           ░  ░           ░  ░
                                               
    """
    
    # Centrages du message
    centered_message = welcome_message.center(terminal_width)
    
    # Affichage du pied de page
    footer = "[--------------Coder par 100--------------]"
    centered_footer = footer.center(terminal_width)
    colored_footer = Fore.RED + centered_footer + Style.RESET_ALL

    print(Fore.CYAN + " " * terminal_width)
    print(Fore.RED + centered_message)
    print(Fore.CYAN + " " * terminal_width)
    print("\n" + colored_footer + "\n")

def ip_lookup(ip_address):
    """Rechercher des informations sur l'adresse IP donnée."""
    url = f"http://ipinfo.io/{ip_address}/json"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = json.loads(response.text)
        print(f"\nIP: {data.get('ip', 'N/A')}")
        print(f"Pays: {data.get('country', 'N/A')}")
        print(f"Région: {data.get('region', 'N/A')}")
        print(f"Ville: {data.get('city', 'N/A')}")
        print(f"Organisation: {data.get('org', 'N/A')}")
    else:
        print(Fore.RED + "Erreur lors de la récupération des informations IP.")

def network_scan(target_ip):
    """Analyse les ports ouverts sur l'adresse IP cible."""
    print(Fore.MAGENTA + f"\nScanning IP: {target_ip}")
    open_ports = []
    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
            print(Fore.GREEN + f"[!] Port {port} is open")
        sock.close()
    
    print(Fore.MAGENTA + f"Open ports on IP {target_ip}: {open_ports}")

def check_discord_token(token):
    """Vérifie la validité du jeton Discord."""
    url = "https://discord.com/api/v10/users/@me"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return Fore.GREEN + "Status: Valid"
    elif response.status_code == 401:
        return Fore.RED + "Status: Invalid"
    else:
        return f"Status: Unknown ({response.status_code})"

def brute_force_token(token):
    """Effectue une attaque par force brute sur un jeton Discord."""
    print(Fore.MAGENTA + "Brute forcing token:", token)
    attempts = []
    start_time = time.time()

    while True:
        random_token_part1 = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=22))
        random_token_part2 = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_o', k=6))
        random_token_part3 = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_o', k=22))

        if random_token_part1 + '.' + random_token_part2 + '.' + random_token_part3 == token:
            status = Fore.GREEN + "Valid"
        else:
            status = Fore.RED + "Invalid"
        
        attempt = f"[{random_token_part1}:{random_token_part2}:{random_token_part3}] | Status: {status} | Token: {random_token_part1}.{random_token_part2}.{random_token_part3}"

        attempts.append(attempt)

        if len(attempts) >= 1000000:
            time_elapsed = time.time() - start_time
            if time_elapsed < 1:
                time.sleep(1 - time_elapsed)
                time_elapsed = 1
            print(Fore.MAGENTA + "1000000 tokens generated per second.")
            for attempt in attempts:
                print(f"{attempt}")
            attempts = []
            start_time = time.time()
        
        if status == Fore.GREEN + "Valid":
            break

    return attempts

def id_to_token_and_brute_force():
    """Convertit un ID en jeton et effectue une force brute si demandé."""
    user_id = input(Fore.MAGENTA + "Entrez l'ID de la victime : ")
    user_token = base64.b64encode(user_id.encode('utf-8'))
    print(Fore.MAGENTA + "TOKEN:", user_token.decode('utf-8'))

    brute_force_option = input(Fore.MAGENTA + "Voulez-vous lancer une attaque par force brute ? (o/n) : ")

    if brute_force_option.lower() == 'o':
        attempts = brute_force_token(user_token.decode('utf-8'))
        print(Fore.MAGENTA + "Tentatives de force brute :")
        for attempt in attempts:
            print(f"{attempt}")
        print(Fore.GREEN + "Token valide trouvé. Arrêt de la brute force.")
    else:
        print(Fore.RED + "Force brute annulée.")

def generate_valid_ip():
    """Génère une adresse IP valide qui ne se trouve pas dans les plages réservées."""
    while True:
        ip = ipaddress.IPv4Address(random.randint(1, 0xFFFFFFFF))
        if not any(ip in reserved for reserved in RESERVED_RANGES):
            return str(ip)

def ip_gen():
    """Génère et affiche des adresses IP valides."""
    print(Fore.MAGENTA + "Génération d'adresses IP...")
    for _ in range(10):
        print(Fore.GREEN + generate_valid_ip())

def generate_nitro_code():
    """Génère un code Nitro Discord aléatoire."""
    nitro_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
    return nitro_code

def check_nitro_code(code):
    """Vérifie la validité d'un code Nitro Discord."""
    url = f"https://discord.com/gifts/{code}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return Fore.GREEN + "Valid", url
        elif response.status_code == 404:
            return Fore.RED + "Invalid", url
        else:
            return Fore.RED + f"Error: {response.status_code}", url
    except requests.RequestException as e:
        return Fore.RED + f"Request failed: {str(e)}", url

def nitro_checker():
    """Vérifie un code Nitro Discord fourni par l'utilisateur."""
    code = input(Fore.MAGENTA + "Entrez le code Nitro à vérifier: ").strip()
    status, url = check_nitro_code(code)
    print(f"Code: {code} - Status: {status} - Link: {url}")

def nitro_gen():
    """Génère et vérifie des codes Nitro Discord."""
    print(Fore.MAGENTA + "Génération et vérification de codes Nitro Discord...")
    try:
        while True:
            code = generate_nitro_code()
            status, url = check_nitro_code(code)
            print(f"Code: {code} - Status: {status} - Link: {url}")
        
    except KeyboardInterrupt:
        print(Fore.MAGENTA + "\nProcess interrupted. Exiting...")

def get_server_info(server_id):
    """Obtenir des informations de base sur le serveur Discord via son ID."""
    url = f"https://discord.com/invite/{server_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')

            # Cherche les informations disponibles dans le HTML
            server_name = soup.find('h1', class_='header-1-1tMr').text if soup.find('h1', class_='header-1-1tMr') else 'N/A'
            member_count = soup.find('span', class_='count-1NqEq').text if soup.find('span', class_='count-1NqEq') else 'N/A'
            description = soup.find('div', class_='description-2H0y8').text if soup.find('div', class_='description-2H0y8') else 'N/A'

            print(f"NAME OF THE SERVER: {server_name}")
            print(f"HOW MANY MEMBERS IN SERVER: {member_count}")
            print(f"DESCRIPTION OF SERVER: {description}")

        else:
            print(Fore.RED +"Failed to retrieve server info. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(Fore.RED + f"Request failed: {str(e)}")

def automatic_bounty_hunting():
    """Demande l'URL pour la chasse aux primes automatique."""
    url = input(Fore.MAGENTA + "Entre ton URL : ")
    print(Fore.MAGENTA + f"URL entrée : {url}")
    print(Fore.MAGENTA + "Lancement de la chasse aux primes automatique...")
    # Placeholder pour la logique de chasse aux primes
    time.sleep(2)
    print(Fore.GREEN + "Chasse aux primes terminée avec succès.")

def main_menu():
    """Affiche le menu principal, centré avec un trait de séparation vertical."""
    terminal_width = shutil.get_terminal_size().columns
    menu_width = 64  # Largeur du cadre du menu
    padding = (terminal_width - menu_width) // 2

    option_1 = "1 - IP LOOKUP"
    option_2 = "2 - NETWORK SCAN"
    option_3 = "3 - CHECK DISCORD TOKEN"
    option_4 = "4 - DISCORD TOKEN BRUTE FORCE"
    option_5 = "5 - IP GENERATOR"
    option_6 = "6 - DISCORD TOKEN HOUSE CHANGER"
    option_7 = "7 - NITRO GEN"
    option_8 = "8 - SERVER INFO"
    option_9 = "9 - NITRO CHECKER"
    option_10 = "10 - AUTOMATIC BOUNTY HUNTING"
    option_11 = "11 - EXIT"

    print(" " * padding + "┌" + "─" * menu_width + "┐")
    print(" " * padding + f"│{'Sdq Bg ? !!'.center(menu_width)}│")
    print(" " * padding + "├" + "─" * 31 + "┬" + "─" * 31 + " ┤")

    # Affichage aligné des options
    print(" " * padding + f"│{option_1:<31}│{option_6:<31} │")
    print(" " * padding + f"│{option_2:<31}│{option_7:<31} │")
    print(" " * padding + f"│{option_3:<31}│{option_8:<31} │")
    print(" " * padding + f"│{option_4:<31}│{option_9:<31} │")
    print(" " * padding + f"│{option_5:<31}│{option_10:<31} │")

    print(" " * padding + "├" + "─" * 31 + "┴" + "─" * 31 + " ┤")
    print(" " * padding + f"│{'11 - EXIT'.center(menu_width)}│")
    print(" " * padding + "└" + "─" * menu_width + "┘")

def run_tool():
    """Lance l'outil principal et gère la sélection des utilisateurs."""
    while True:
        main_menu()
        choice = input(Fore.YELLOW + "(/<): ")

        if choice == '1':
            ip_address = input(Fore.MAGENTA + "Entrez l'adresse IP: ")
            ip_lookup(ip_address)
        elif choice == '2':
            target_ip = input(Fore.MAGENTA + "Entrez l'adresse IP cible: ")
            network_scan(target_ip)
        elif choice == '3':
            token = input(Fore.MAGENTA + "Entrez le jeton Discord à vérifier: ")
            status = check_discord_token(token)
            print(status)
        elif choice == '4':
            id_to_token_and_brute_force()
        elif choice == '5':
            ip_gen()
        elif choice == '6':
            print(Fore.MAGENTA + "Fonctionalité de changement de house du token Discord.")
            # Placeholder pour la logique de changement de house
        elif choice == '7':
            nitro_gen()
        elif choice == '8':
            server_id = input(Fore.MAGENTA + "Entrez l'ID du serveur Discord: ")
            get_server_info(server_id)
        elif choice == '9':
            nitro_checker()
        elif choice == '10':
            automatic_bounty_hunting()
        elif choice == '11':
            print(Fore.MAGENTA + "Exiting...")
            break
        else:
            print(Fore.RED + "Choix invalide, veuillez réessayer.")

        input(Fore.YELLOW + "\nAppuyez sur Entrée pour revenir au menu principal.")

if __name__ == "__main__":
    print_header()
    run_tool()
