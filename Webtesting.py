import subprocess
import sys
import websocket
import ssl
import requests
import builtwith
from selenium import webdriver
import xml.etree.ElementTree as ET
import os

def print_status(message, status):
    if status == "running":
        print("\n[*] Running {}... ".format(message))
    elif status == "completed":
        print("\n[*] Completed {}! ".format(message))

def create_directory(target):
    try:
        os.mkdir(target)
        print(f"Directory '{target}' created successfully.")
    except OSError:
        print(f"Creation of the directory '{target}' failed.")

def nmap_scan(target):
    print_status("Nmap scan", "running")
    nmap_command = f"nmap -oX {target}/nmap.xml {target} > /dev/null 2>&1"
    subprocess.run(nmap_command, shell=True)
    print_status("Nmap scan", "completed")
    print("\033[91mNMAP Scan results located in {target}/nmap.xml\033[0m")

def print_open_ports(target):
    tree = ET.parse(f'{target}/nmap.xml')
    root = tree.getroot()
    open_ports = []

    for host in root.findall('host'):
        for ports in host.findall('ports'):
            for port in ports.findall('port'):
                state = port.find('state').attrib['state']
                if state == 'open':
                    open_ports.append(port.attrib['portid'])

    print("\n\033[92mOpen Ports:\033[0m ", end="")
    if open_ports:
        print(", ".join([f"\033[91m{port}\033[0m" for port in open_ports]))
    else:
        print("\033[91mNone\033[0m")

def convert_to_html(xml_file, html_file, target):
    print_status("XML to HTML conversion", "running")
    xsltproc_command = f"xsltproc {target}/{xml_file} -o {target}/{html_file}"
    subprocess.run(xsltproc_command, shell=True)
    print_status("XML to HTML conversion", "completed")
    print("\033[91mNMAP Scan results located in {target}/nmap.html\033[0m")

def testssl(target):
    print_status("testssl", "running")
    testssl_command = f"testssl -oH {target}/testssl.html {target} > /dev/null 2>&1"
    subprocess.run(testssl_command, shell=True)
    print_status("TestSSL", "completed")
    print("\033[91mTestSSL results found in {target}/testssl.html\033[0m")

def test_websocket(url):
    try:
        ws = websocket.create_connection(url, sslopt={"cert_reqs": ssl.CERT_NONE})
        ws.close()
        return True
    except Exception as e:
        return False

def test_http_methods(target):
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target

    methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD']
    print_status("HTTP methods test", "running")
    first_successful_method_printed = False
    for method in methods:
        try:
            response = requests.request(method, target)
            if response.ok:
                if not first_successful_method_printed:
                    print()
                    first_successful_method_printed = True
                print(f"\033[94mHTTP {method} request returned status code: {response.status_code}\033[0m")
        except Exception as e:
            print(f"\033[91mHTTP {method} request failed: {e}\033[0m")
    print_status("HTTP methods test", "completed")

def check_headers(url):
    headers_to_check = ['X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection', 
                        'Strict-Transport-Security', 'Content-Security-Policy', 
                        'Referrer-Policy', 'Feature-Policy']
    
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print_status("Headers check", "running")
    try:
        response = requests.head(url)
        for header in headers_to_check:
            if header in response.headers:
                print(f"\033[94m{header}: Present\033[0m")
            else:
                print(f"\033[91m{header}: Not Present\033[0m")
    except requests.exceptions.RequestException as e:
        print(f"Error occurred while accessing {url}: {e}")
    print_status("Headers check", "completed")

def check_websocket(url):
    print_status("WebSocket functionality test", "running")
    if test_websocket(url):
        print("\033[94mWebSocket functionality detected for:", url, "\033[0m")
        return True
    else:
        print("\033[91mWebSocket functionality not detected for:", url, "\033[0m")
        return False

def analyze_website(url):
    if not url.startswith("https://"):
        url = "https://" + url
    print_status("Website technology analysis", "running")
    result = builtwith.builtwith(url)
    print("\033[93mTechnologies used on the website:\033[0m")
    for key, value in result.items():
        print(f"\033[93m{key}:\033[0m {', '.join(value)}")
    print_status("Website technology analysis", "completed")

def check_ria_cross_domain_policy(url):
    print_status("RIA Cross Domain Policy tests", "running")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    crossdomain_url = url + "/crossdomain.xml"
    clientaccesspolicy_url = url + "/clientaccesspolicy.xml"
    
    try:
        response_crossdomain = requests.get(crossdomain_url, timeout=5)
        response_clientaccesspolicy = requests.get(clientaccesspolicy_url, timeout=5)

        if response_crossdomain.status_code == 200:
            print(f"\033[94mCross-domain policy file found at {crossdomain_url}\033[0m")
        else:
            print(f"\033[91mNo cross-domain policy file found at {crossdomain_url}\033[0m")

        if response_clientaccesspolicy.status_code == 200:
            print(f"\033[94mClient Access Policy file found at {clientaccesspolicy_url}\033[0m")
        else:
            print(f"\033[91mNo Client Access Policy file found at {clientaccesspolicy_url}\033[0m")

    except requests.exceptions.RequestException as e:
        print(f"Error occurred while accessing {crossdomain_url} or {clientaccesspolicy_url}: {e}")

    print_status("RIA Cross Domain Policy tests", "completed")

def check_web_messaging(url):
    print_status("Web Messaging check", "running")

    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    driver = webdriver.Chrome(options=options)

    try:
        driver.get(url)
        # Here you can inspect the page's source code or execute JavaScript to check
        # for web messaging usage using postMessage() or other related methods.
        # For example:
        web_messaging_used = driver.execute_script('''
            // Check if postMessage is defined on the window object
            return typeof window.postMessage === 'function';
        ''')

        if web_messaging_used:
            print(f"\033[94mThe web server at {url} is using web messaging.\033[0m")
        else:
            print(f"\033[91mThe web server at {url} is not using web messaging.\033[0m")

    except Exception as e:
        print(f"Error occurred while accessing {url}: {e}")

    finally:
        driver.quit()

    print_status("Web Messaging check", "completed")

def test_cross_site_flashing(url):
    print_status("Cross-Site Flashing test", "running")

    try:
        response = requests.get(url)

        if response.is_redirect and response.headers.get('Location').endswith('.swf'):
            print(f"\033[94mPotential cross-site flashing vulnerability found at {url}\033[0m")
        else:
            print(f"\033[91mNo potential cross-site flashing vulnerability found at {url}\033[0m")

    except requests.exceptions.RequestException as e:
        print(f"Error occurred while accessing {url}: {e}")

    print_status("Cross-Site Flashing test", "completed")

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <target_website>")
        sys.exit(1)
    
    target = sys.argv[1]

    create_directory(target)

    print('''
                                                                                         
                                           .:--===+++=-::.                                
                                     .-+*######%%%%%%%%%####**=-.                         
                                   =##%%%%%######%%%%%%%%%%%%%####=.                      
                                  +###%%%%######%%%%%%%%%%%%%%%%%%%#.                     
                                  *##%%%%%######%%%%%%%%%%%%%%%%%%%%-                     
                                 .*#%%%%%%######%%%%%%%%%%%%%%%%%%%#:                     
                                 -##%%%%%###**##%%%%%%%%%%%%%%%%%%%#.                     
                                 -=--:..         ...:::::--==+*#%%%#.                     
                                ==                     .........::=*                      
                               *#=                     ............##                     
                              *%*=                     ...........-##.                    
                             -%#%-.:::::::::-------------:::......=*#=                    
                             *%#%%#*=:..:::::::::-------=========+#+#*                    
                            .##%%%*=-...:-------------=========+#%%+##                    
                            :**%%%+-..:=++*#*++=---=+*****+++===%%%**#:                   
                            :+*%%%+-::::---+=++=::-=*#+=+=++===+%@%++#=                   
                            .+*%%%+*::::::----::::-=++++=======+%@%++#=                   
                             +#%%#+*-:::::::...:::-==------===+*@@%*=*-                   
                             +#%%*++=::::::::::::::===-----===+#@@%*=+-                   
                             =#%%*+%*-:-::::----::-=+++=---==+**@%%#=++                   
                             -#%%+%@%=---::-:::====++++=====++**@%%#=+#                   
                             :%%%%@@%*--------===+++**++===++*##%%%*=+*.                  
                              #%%%@%%%+=---=====+++++++++=++*#*%%%%*==+.                  
                              #%%@@%%=+++===-----=====++++*#%#%%%%%*==+:                  
                             -#%%@@%#. -++++=--=+++++++***#%##%%%%%===*+                  
                         .:+#%#%%@%%#.  .=+++=======++***##***#%%%#**+*+                  
                .:--=++*#%%#%%#%@@%%%-.   .-=+++++++**++==+**#%%%######+.                 
           :-+#######%%%%%#%%%%%@@%%#-       .:-====----:=+*#%@%%####%%#*=-.              
        -+##########%%%%%##%#%%%@%%@%*-.     ......:::::=+#%%@@@%#######%%%%##*+-:        
      =##########%%%%%%%##%%####%%%%%###+=-:::--==++*##%%@@@@@@@%#######%%%%%%%###+:     
    -#######%###%%%%%%%##%#####%%%%%################%%%%%%%%%%%%%%%#####%%%%%%%%%%####+.  
   +#%######%###%%%%%%##%#####%%%%%###################%#####%%%%%%%%%###@@%%%%%%%%%####: 
 .#%%%#########%%##%%%##%%####%%%%%###############################%%%%#%%%%%%%%%%%%####%# 
:##%%##%#######%###%%###%%####%%%%%###############################%%%%#%%%%%%%%%%%%###%%#*
##%%%##%######%%###%##**#####%%%%%####################################%%%%%%%%##%#%##%%%##
#%%%####%#############*####%%%%%################################################%#%#%#%##%
#%%######################%%%#################*####################################%#%#%%#
#%%###################################*######+**###################################%#%#%%#
#%%#######%##%##############################*==*##################################%%%##%%#
#%%%#######%####*##########################*:::-*############***#*#***#*########%%#####%%#
%#%%#######%##%############################*.:::*##########**#######*##*########%%####%%##
%#%%%#########%############################+.:--#############**###*#*#*#########%####%%##%
%##%%#########%############################+.:--##############*****#*###########%####%##%%
%###%########%%############################=::--###############*#*##############%##%%#####
%###%%#######%%##################+====+++++-::--*++++*****###################%%#%########%
%####%%###%##%%##################:..::::::::::::::::::-:--*##################%%%#########%
%%%##%%%##%##%%##################----------::::-----------###################%%%%#######%%
%%%##%%%%%%##%%###################%%%%%%%%%=::--@%%%%%%%%%%#################%%%%#######%%#
%%%%%%%%%%%##%%%###########################-::--@%##########################%%%%######%###
%%%%%%%%%%%###%%###########################-::-=@%#####################%####@%%%#######%#%
%%%%%#%%%%%%##%%###########################:::-=%%#####################%%##%@%%#####%%%%%
%%%%%%%%%%%%##%%###########################:::-=%%#####################%%##%@@%######%%%%%
%%%%%%%%%%%%##%%%##########################.::-+@%#####################%%#%@@%##########%%
%###%%%%%%%%%#%%%#########################*::--+@%#####################%%#%@@%##########%
%%%%%%%%%@@@%%#%%#########################*::--*@%%###############%###%%%%%@@%#######%%%%#
%%%%%%%%%%%@%%%%%#########################*:--=*@%%###############%###%%%%%@%#############
%%%%%%%%%%@@@%%%%%########################*:---*%%%###############%###%%%%%%##############
%%%%%%%%%%%%@%%%%%########%################**##%%%################%%##%@%%%###############
#%%%######%%%%%%%%###%####%%#################%%%%%####%###########%%#%@@%%################
          

 _______  _             _____   ______ __      __ ______  _____   ______  _   _  _____  
|__   __|| |           |  __ \ |  ____|\ \    / /|  ____||  __ \ |  ____|| \ | ||  __ \ 
   | |   | |__    ___  | |__) || |__    \ \  / / | |__   | |__) || |__   |  \| || |  | |
   | |   | '_ \  / _ \ |  _  / |  __|    \ \/ /  |  __|  |  _  / |  __|  | . ` || |  | |
   | |   | | | ||  __/ | | \ \ | |____    \  /   | |____ | | \ \ | |____ | |\  || |__| |
   |_|   |_| |_| \___| |_|  \_\|______|    \/    |______||_|  \_\|______||_| \_||_____/ 
''')
    print("Lets shine a light on this website..")

    
    nmap_scan(target)
    print_open_ports(target)
    convert_to_html("nmap.xml", "nmap.html", target)
    testssl(target)
    test_http_methods(target)
    check_headers(target)
    check_websocket("ws://" + target)
    check_websocket("wss://" + target)
    analyze_website(target)
    check_ria_cross_domain_policy(target)
    check_web_messaging("https://" + target)
    test_cross_site_flashing("https://" + target)
    

    print_status("Script Execution", "completed")

if __name__ == "__main__":
    main()
