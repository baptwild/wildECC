import sys
import random
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def show_help():
    print("""
Script wildECC
Syntaxe :
    wildECC <commande> [<clé>] [<texte>] [switchs]

Commandes :
    keygen   : Génère une paire de clé
    crypt    : Chiffre <texte> pour la clé publique <clé>
    decrypt  : Déchiffre <texte> pour la clé privée <clé>
    help     : Affiche ce manuel
""")

def main():
    if len(sys.argv) < 2 or sys.argv[1] == "help":
        show_help()
        return

    command = sys.argv[1]

    if command == "keygen":
        k, Q = generate_keypair()
        write_private_key(k)
        write_public_key(Q)
        print("Clés générées avec succès")


    elif command == "crypt":

        if len(sys.argv) < 4:
            print("Usage : wildECC crypt <clé_publique> <texte>")

            return

        pubkey_file = sys.argv[2]

        plaintext = sys.argv[3]

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



    elif command == "decrypt":

        if len(sys.argv) < 4:
            print("Usage : wildECC decrypt <clé_privée> <cryptogramme>")

            return

        privkey_file = sys.argv[2]

        cryptogram = sys.argv[3]

        k = read_private_key(privkey_file)

        plaintext = decrypt_message(k, cryptogram)

        print(plaintext)

    else:
        print("Commande inconnue")
        show_help()



# ==============================
# Paramètres de la courbe ECC
# ==============================

p = 101
a = 35
b = 3

P = (2, 9)
O = None  # Point à l'infini


# ==============================
# Fonctions math ECC
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
        if k % 2 == 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k = k // 2

    return result

# ==============================
# KEYGEN – Génération des clés
# ==============================

def generate_keypair():
    """
    Génère une paire de clés ECC
    - k : clé privée
    - Q : clé publique (Q = kP)
    """
    k = random.randint(1, 1000)
    Q = scalar_mult(k, P)
    return k, Q


def write_private_key(k, filename="wildECC.priv"):
    """
    Écrit la clé privée dans un fichier au format monECC
    """
    with open(filename, "w") as f:
        f.write("---begin monECC private key---\n")
        f.write(base64.b64encode(str(k).encode()).decode() + "\n")
        f.write("---end monECC key---\n")


def write_public_key(Q, filename="wildECC.pub"):
    """
    Écrit la clé publique dans un fichier au format monECC
    """
    Qx, Qy = Q
    data = f"{Qx};{Qy}"
    with open(filename, "w") as f:
        f.write("---begin monECC public key---\n")
        f.write(base64.b64encode(data.encode()).decode() + "\n")
        f.write("---end monECC key---\n")


# ==============================
# Lecture des clés
# ==============================

def read_public_key(filename):
    with open(filename, "r") as f:
        lines = f.read().splitlines()

    if lines[0] != "---begin monECC public key---":
        raise ValueError("Fichier de clé publique invalide")

    data = base64.b64decode(lines[1]).decode()
    Qx, Qy = data.split(";")

    return int(Qx), int(Qy)


def read_private_key(filename):
    with open(filename, "r") as f:
        lines = f.read().splitlines()

    if lines[0] != "---begin monECC private key---":
        raise ValueError("Fichier de clé privée invalide")

    k = base64.b64decode(lines[1]).decode()
    return int(k)


# ==============================
# Secret partagé & Hash
# ==============================

def derive_shared_secret(k, Qb):
    """
    Calcule S = kQb puis retourne un hash SHA256 exploitable
    Refuse le point à l'infini
    """
    S = scalar_mult(k, Qb)

    if S is None:
        raise ValueError("Secret partagé invalide (point à l'infini)")

    Sx, Sy = S

    h = hashlib.sha256()
    h.update(str(Sx).encode())
    h.update(str(Sy).encode())

    return h.digest()


# ==============================
# AES – Chiffrement / Déchiffrement
# ==============================

def aes_encrypt(key_material, plaintext):
    iv = key_material[:16]
    key = key_material[16:32]

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode())
    padded_data += padder.finalize()

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext

# ==============================
# DÉCHIFFREMENT ECC
# ==============================

def aes_decrypt(key_material, ciphertext):
    iv = key_material[:16]
    key = key_material[16:32]

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext)
    plaintext += unpadder.finalize()

    return plaintext.decode()


# ==============================
# Décryptage EC-ElGamal
# ==============================
def decrypt_message(kb, cryptogram):
    """
    Déchiffre un message ECC-AES
    cryptogram = Qe_x;Qe_y|ciphertext_base64
    """

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
    key_material = h.digest()

    return aes_decrypt(key_material, ciphertext)

#
# ==============================
# Tests manuels (TEMPORAIRES)
# ==============================

if __name__ == "__main__":
    main()



