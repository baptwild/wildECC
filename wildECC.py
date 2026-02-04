import sys
import random
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


# ==============================
# Aide
# ==============================

def show_help():
    print("""
Script wildECC par Baptiste Sauvage IW
Syntaxe :
    wildECC <commande> [<clé>] [<texte>] [switchs]

Commandes :
    keygen   : Génère une paire de clé
    crypt    : Chiffre <texte> pour la clé publique <clé>
    decrypt  : Déchiffre <texte> pour la clé privée <clé>
    help     : Affiche ce manuel

Switchs :
    -f <nom> : Nom de base des fichiers de clés (keygen)
""")


# ==============================
# MAIN
# ==============================

def main():
    if len(sys.argv) < 2 or sys.argv[1] == "help":
        show_help()
        return

    # ------------------------------
    # Gestion des switchs
    # ------------------------------
    filename = "monECC"

    args = sys.argv[1:]

    if "-f" in args:
        idx = args.index("-f")
        try:
            filename = args[idx + 1]
            args.pop(idx)
            args.pop(idx)
        except IndexError:
            print("Erreur : -f nécessite un nom de fichier")
            return

    command = args[0]

    # ==============================
    # KEYGEN
    # ==============================
    if command == "keygen":
        if len(args) != 1:
            print("Usage : wildECC keygen [-f <nom>]")
            return

        k, Q = generate_keypair()
        write_private_key(k, filename + ".priv")
        write_public_key(Q, filename + ".pub")
        print("Clés générées avec succès")

    # ==============================
    # CRYPT
    # ==============================
    elif command == "crypt":
        if len(args) != 3:
            print("Usage : wildECC crypt <clé_publique> <texte>")
            return

        pubkey_file = args[1]
        plaintext = args[2]

        Qb = read_public_key(pubkey_file)

        while True:
            k = random.randint(1, 1000)
            try:
                secret = derive_shared_secret(k, Qb)
                break
            except ValueError:
                continue

        Qe = scalar_mult(k, P)

        ciphertext = aes_encrypt(secret, plaintext)
        ciphertext_b64 = base64.b64encode(ciphertext).decode()

        Qe_x, Qe_y = Qe
        print(f"{Qe_x};{Qe_y}|{ciphertext_b64}")

    # ==============================
    # DECRYPT
    # ==============================
    elif command == "decrypt":
        if len(args) != 3:
            print("Usage : wildECC decrypt <clé_privée> <cryptogramme>")
            return

        privkey_file = args[1]
        cryptogram = args[2]

        k = read_private_key(privkey_file)
        plaintext = decrypt_message(k, cryptogram)

        print(plaintext)

    else:
        print("Commande inconnue")
        show_help()


# ==============================
# Paramètres ECC
# ==============================

p = 101
a = 35
b = 3

P = (2, 9)
O = None


# ==============================
# Maths ECC
# ==============================

def modinv(x):
    return pow(x, -1, p)


def point_add(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1

    x1, y1 = P1
    x2, y2 = P2

    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    if P1 == P2:
        m = (3 * x1 * x1 + a) * modinv(2 * y1) % p
    else:
        m = (y2 - y1) * modinv(x2 - x1) % p

    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return (x3, y3)


def scalar_mult(k, P):
    result = None
    addend = P

    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


# ==============================
# KEYGEN
# ==============================

def generate_keypair():
    k = random.randint(1, 1000)
    Q = scalar_mult(k, P)
    return k, Q


def write_private_key(k, filename):
    with open(filename, "w") as f:
        f.write("---begin monECC private key---\n")
        f.write(base64.b64encode(str(k).encode()).decode() + "\n")
        f.write("---end monECC key---\n")


def write_public_key(Q, filename):
    Qx, Qy = Q
    data = f"{Qx};{Qy}"
    with open(filename, "w") as f:
        f.write("---begin monECC public key---\n")
        f.write(base64.b64encode(data.encode()).decode() + "\n")
        f.write("---end monECC key---\n")


# ==============================
# Lecture clés
# ==============================

def read_public_key(filename):
    with open(filename, "r") as f:
        lines = f.read().splitlines()

    if lines[0] != "---begin monECC public key---":
        raise ValueError("Fichier de clé publique invalide")

    Qx, Qy = base64.b64decode(lines[1]).decode().split(";")
    return int(Qx), int(Qy)


def read_private_key(filename):
    with open(filename, "r") as f:
        lines = f.read().splitlines()

    if lines[0] != "---begin monECC private key---":
        raise ValueError("Fichier de clé privée invalide")

    return int(base64.b64decode(lines[1]).decode())


# ==============================
# Secret partagé
# ==============================

def derive_shared_secret(k, Qb):
    S = scalar_mult(k, Qb)
    if S is None:
        raise ValueError("Secret partagé invalide")

    Sx, Sy = S
    h = hashlib.sha256()
    h.update(str(Sx).encode())
    h.update(str(Sy).encode())
    return h.digest()


# ==============================
# AES
# ==============================

def aes_encrypt(key_material, plaintext):
    iv = key_material[:16]
    key = key_material[16:32]

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt(key_material, ciphertext):
    iv = key_material[:16]
    key = key_material[16:32]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()


# ==============================
# Decrypt EC-ElGamal
# ==============================

def decrypt_message(kb, cryptogram):
    try:
        point_part, cipher_part = cryptogram.split("|")
        Qe_x, Qe_y = point_part.split(";")
        Qe = (int(Qe_x), int(Qe_y))
    except Exception:
        raise ValueError("Format de cryptogramme invalide")

    ciphertext = base64.b64decode(cipher_part)

    S = scalar_mult(kb, Qe)
    if S is None:
        raise ValueError("Secret partagé invalide")

    Sx, Sy = S
    h = hashlib.sha256()
    h.update(str(Sx).encode())
    h.update(str(Sy).encode())
    return aes_decrypt(h.digest(), ciphertext)


if __name__ == "__main__":
    main()
