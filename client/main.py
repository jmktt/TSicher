#client.py


import socket
import os
import json
from Crypto.Cipher import AES, DES, ChaCha20, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util import number


banner = '''

▄▄▄█████▓  ██████  ██▓ ▄████▄   ██░ ██ ▓█████  ██▀███  
▓  ██▒ ▓▒▒██    ▒ ▓██▒▒██▀ ▀█  ▓██░ ██▒▓█   ▀ ▓██ ▒ ██▒
▒ ▓██░ ▒░░ ▓██▄   ▒██▒▒▓█    ▄ ▒██▀▀██░▒███   ▓██ ░▄█ ▒
░ ▓██▓ ░   ▒   ██▒░██░▒▓▓▄ ▄██▒░▓█ ░██ ▒▓█  ▄ ▒██▀▀█▄  
  ▒██▒ ░ ▒██████▒▒░██░▒ ▓███▀ ░░▓█▒░██▓░▒████▒░██▓ ▒██▒
  ▒ ░░   ▒ ▒▓▒ ▒ ░░▓  ░ ░▒ ▒  ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░
    ░    ░ ░▒  ░ ░ ▒ ░  ░  ▒    ▒ ░▒░ ░ ░ ░  ░  ░▒ ░ ▒░
  ░      ░  ░  ░   ▒ ░░         ░  ░░ ░   ░     ░░   ░ 
               ░   ░  ░ ░       ░  ░  ░   ░  ░   ░     
                      ░                                
'''
HOST = 'localhost'
PORT = 65432
FILES_DIR = 'files/'

def generate_rsa_keypair():
    key = RSA.generate(2048)
    return key, key.publickey()

def generate_dh_keypair(p, g):
    a = number.getRandomRange(2, p - 2)
    A = pow(g, a, p)
    return a, A

def compute_dh_shared_key(p, a, B):
    shared_secret = pow(B, a, p)
    return shared_secret.to_bytes(32, 'big')[:16]

def upload_file(sock, filepath, algorithm, username, server_pubkey=None, shared_key=None):
    filename = os.path.basename(filepath)
    with open(filepath, 'rb') as f:
        data = f.read()

    if shared_key:
        key = shared_key
    else:
        key = get_random_bytes(16)

    if algorithm == 'AES':
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        nonce = cipher.nonce
    elif algorithm == 'DES':
        key = key[:8]
        cipher = DES.new(key, DES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        nonce = cipher.nonce
    elif algorithm == 'ChaCha20':
        cipher = ChaCha20.new(key=key)
        ciphertext = cipher.encrypt(data)
        nonce = cipher.nonce
        tag = b''
    else:
        raise ValueError("Algoritmo inválido")

    if shared_key:
        encrypted_key = b''
    else:
        encrypted_key = PKCS1_OAEP.new(server_pubkey).encrypt(key)

    sock.send(f'UPLOAD {filename} {len(ciphertext)} {algorithm} {username}'.encode())
    sock.send(len(encrypted_key).to_bytes(2, 'big'))
    if not shared_key:
        sock.send(encrypted_key)
    else:
        sock.send(b'\x00\x00')

    sock.send(nonce)
    sock.sendall(ciphertext)
    print(sock.recv(1024).decode())

def download_file(sock, filename):
    sock.send(f'DOWNLOAD {filename}'.encode())
    size_data = sock.recv(16)
    size_str = size_data.decode().strip()

    if size_str == 'NOTFOUND':
        print('Arquivo não encontrado no servidor.')
        return

    filesize = int(size_str)
    received = b''
    while len(received) < filesize:
        chunk = sock.recv(min(1024, filesize - len(received)))
        if not chunk:
            break
        received += chunk

    download_path = os.path.join(FILES_DIR, filename + ".enc")
    with open(download_path, 'wb') as f:
        f.write(received)
    print(f"Arquivo '{filename}.enc' baixado com sucesso.")

def list_files(sock):
    sock.send(b'LIST')
    print(sock.recv(4096).decode())
    

def perform_key_exchange(sock, method, username):
    server_pubkey = None
    shared_key = None
    if method == '1':
        client_key, client_pub = generate_rsa_keypair()
        sock.send(b'SET_CLIENT_PUBKEY')
        sock.send(client_pub.export_key())
        sock.send(b'GET_PUBKEY')
        server_pubkey = RSA.import_key(sock.recv(2048))
    elif method == '2':
        sock.send(b'DH_INIT')
        response = sock.recv(4096).decode()
        p, g, B = map(int, response.strip().split())
        a, A = generate_dh_keypair(p, g)
        sock.send(f'DH_FINAL {A}'.encode())
        confirm = sock.recv(1024).decode()
        if confirm == 'OK':
            shared_key = compute_dh_shared_key(p, a, B)
    else:
        print("Opção inválida.")
    return server_pubkey, shared_key

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        logged_in = False
        username = ""
        server_pubkey = None
        shared_key = None

        while True:
            if not logged_in:
                print(banner)
                print("Select from menu:\n")
                print("1) Register")
                print("2) Login")
                print("3) Exit")
                choice = input("\n\033[4mtsicher\033[0m> ").strip()

                if choice == '1':
                    username = input("user: ")
                    password = input("password: ")
                    sock.send(f'REGISTER {username} {password}'.encode())
                    print(sock.recv(1024).decode())

                    print("\nEscolha o método de troca de chaves:")
                    print("1) RSA (PKI)")
                    print("2) Diffie-Hellman (DH)")
                    method = input("Escolha (1 ou 2): ").strip()
                    server_pubkey, shared_key = perform_key_exchange(sock, method, username)
                    logged_in = True

                elif choice == '2':
                    username = input("user: ")
                    password = input("password: ")
                    sock.send(f'LOGIN {username} {password}'.encode())
                    response = sock.recv(1024).decode()
                    print(response)

                    if response == 'OK':
                        print("\nEscolha o método de troca de chaves:")
                        print("1. RSA (PKI)")
                        print("2. Diffie-Hellman (DH)")
                        method = input("Escolha (1 ou 2): ").strip()

                        if method == '1':
                            client_key, client_pub = generate_rsa_keypair()
                            sock.send(b'SET_CLIENT_PUBKEY')
                            sock.send(client_pub.export_key())
                            sock.send(b'GET_PUBKEY')
                            server_pubkey = RSA.import_key(sock.recv(2048))
                        elif method == '2':
                            sock.send(b'DH_INIT')
                            response = sock.recv(4096).decode()
                            try:
                                p_str, g_str, B_str = response.strip().split()
                                p = int(p_str)
                                g = int(g_str)
                                B = int(B_str)
                                a = number.getRandomRange(2, p - 2)
                                A = pow(g, a, p)
                                shared_key = compute_dh_shared_key(p, g, a, B)
                                sock.send(f'DH_FINAL {A}'.encode())
                                ok = sock.recv(1024).decode()
                                if ok != 'OK':
                                    print("[!] Erro na troca DH.")
                                    continue
                            except:
                                print("[!] Resposta inválida do servidor durante DH.")
                                continue
                        else:
                            print("[!] Tipo de chave inválido.")
                            sock.send(b'INVALID_METHOD')
                            continue
                        logged_in = True


                elif choice == '3':
                    print("Encerrando.")
                    break

            else:
                print(f"\n=== MENU DE USUÁRIO (\033[1m\033[34m{username}\033[0m) ===")
                print("1. Enviar arquivo")
                print("2. Baixar arquivo")
                print("3. Listar arquivos")
                print("4. Sair da conta")
                print("5. Encerrar programa")
                choice = input("Escolha uma opção: ").strip()

                if choice == '1':
                    filepath = input("Caminho do arquivo: ").strip()
                    algorithm = input("Algoritmo (AES, DES, ChaCha20): ").strip()
                    upload_file(sock, filepath, algorithm, username, server_pubkey, shared_key)

                elif choice == '2':
                    filename = input("Nome do arquivo: ").strip()
                    download_file(sock, filename)

                elif choice == '3':
                    list_files(sock)

                elif choice == '4':
                    print(f"Usuário {username} saiu.")
                    logged_in = False
                    username = ""
                    server_pubkey = None
                    shared_key = None

                elif choice == '5':
                    print("Encerrando programa.")
                    break

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] SAIU.")
