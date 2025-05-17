# Server.py


import socket
import threading
import json
import os
import hashlib
import bcrypt
from Crypto.Cipher import AES, DES, ChaCha20, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Util.number import getPrime

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

[!]SERVER[!]
'''

USERS_FILE = 'users.json'
FILES_DIR = 'files/'
META_FILE = 'files_meta.json'
PORT = 65432
HOST = 'localhost'

if not os.path.exists(FILES_DIR):
    os.makedirs(FILES_DIR)

if not os.path.exists(META_FILE):
    with open(META_FILE, 'w') as f:
        json.dump({}, f)

RSA_KEY = RSA.generate(2048)
PRIVATE_KEY = RSA_KEY
PUBLIC_KEY = RSA_KEY.publickey()

CLIENT_KEYS = {}
DH_SESSIONS = {}

DH_PRIME = getPrime(2048)
DH_GENERATOR = 2

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

def register_user(username, password):
    users = load_users()
    if username in users:
        return False
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = hashed
    save_users(users)
    return True

def authenticate_user(username, password):
    users = load_users()
    if username not in users:
        return False
    return bcrypt.checkpw(password.encode(), users[username].encode())

def save_file_meta(filename, username, algoritmo):
    with open(META_FILE, 'r') as f:
        metas = json.load(f)
    metas[filename] = {"user": username, "algo": algoritmo}
    with open(META_FILE, 'w') as f:
        json.dump(metas, f)

def handle_client(conn, addr):
    print(f"[+] Conectado a {addr}")
    user = None

    while True:
        try:
            data = conn.recv(2048).decode()
            if not data:
                break
            cmd, *args = data.split()

            if cmd == 'REGISTER':
                username, password = args
                success = register_user(username, password)
                conn.send(b'OK' if success else b'FAIL')

            elif cmd == 'LOGIN':
                username, password = args
                if authenticate_user(username, password):
                    user = username
                    conn.send(b'OK')
                    print(f"[!] LOGGED IN: {user}")
                else:
                    conn.send(b'FAIL')

            elif cmd == 'SET_CLIENT_PUBKEY':
                pubkey_data = conn.recv(2048)
                client_key = RSA.import_key(pubkey_data)
                CLIENT_KEYS[user] = client_key
                print(f"[DEBUG] Chave pública do cliente {user} armazenada.")

            elif cmd == 'GET_PUBKEY':
                conn.send(PUBLIC_KEY.export_key())

            elif cmd == 'DH_START':
                json_data = conn.recv(2048).decode()
                dh_params = json.loads(json_data)
                p = int(dh_params['p'])
                g = int(dh_params['g'])
                A = int(dh_params['A'])
                b = randint(2, p - 2)
                B = pow(g, b, p)
                shared = pow(A, b, p)
                DH_SESSIONS[user] = shared.to_bytes(32, 'big')[:16]
                conn.send(str(B).encode())

            elif cmd == 'UPLOAD' and user:
                filename, filesize, algo, sender = args[0], int(args[1]), args[2], args[3]
                raw_len = conn.recv(2)
                key_len = int.from_bytes(raw_len, 'big')
                if key_len > 0:
                    encrypted_key = conn.recv(key_len)
                    key = PKCS1_OAEP.new(PRIVATE_KEY).decrypt(encrypted_key)
                else:
                    key = DH_SESSIONS.get(user)
                    encrypted_key = b''
                nonce = conn.recv(16 if algo != 'ChaCha20' else 8)

                data = b''
                while len(data) < filesize:
                    chunk = conn.recv(min(1024, filesize - len(data)))
                    if not chunk:
                        break
                    data += chunk

                full_path = os.path.join(FILES_DIR, filename + ".enc")
                with open(full_path, 'wb') as f:
                    f.write(len(encrypted_key).to_bytes(2, 'big'))
                    f.write(encrypted_key)
                    f.write(nonce)
                    f.write(data)

                save_file_meta(filename + ".enc", sender, algo)
                conn.send(b'UPLOADED')

            elif cmd == 'LIST' and user:
                files = os.listdir(FILES_DIR)
                with open(META_FILE, 'r') as f:
                    metas = json.load(f)
                response = '\n'.join([
                    f"{f} (de \033[1;34m{metas.get(f, {}).get('user', 'desconhecido')}\033[0m usando \033[1;32m{metas.get(f, {}).get('algo', '???')}\033[0m)"
                    for f in files]).encode()
                conn.send(response)

            elif cmd == 'DOWNLOAD' and user:
                filename = args[0] + ".enc"
                path = os.path.join(FILES_DIR, filename)
                if os.path.exists(path):
                    with open(path, 'rb') as f:
                        data = f.read()
                    conn.send(str(len(data)).ljust(16).encode())
                    conn.sendall(data)
                else:
                    conn.send(b'NOTFOUND'.ljust(16))

        except Exception as e:
            print(f"[ERRO] {e}")
            break

    conn.close()
    print(f"[-] Desconectado de {addr}")

def start_server():
    print(banner)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("[+] Servidor iniciado em", HOST, PORT)

        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()

if __name__ == '__main__':
    start_server()
