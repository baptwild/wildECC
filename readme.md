# -- MonECC - Sauvage Baptiste - Chiffrement & Déchiffrement --

## Présentation du projet 

Ce projet est réalisé dans le cadre du **TP MonECC** pour le cours de Cryptographie M2. 
L’objectif est de développer un programme simple de génération de clés privées/publiques et de chiffrement et déchiffrement de messages en ECC.

Pour des raisons pédagogiques et de performances, la taille des clés utilisées est volontairement faible et **non sécurisée pour un usage réel**. 

---

## Prérequis & installation

### Technologie
- Python
- Python **≥ 3.8** recommandé

### Dépendances Python

Seules les parties **AES / Hash** utilisent des bibliothèques externes (autorisé par le sujet).  
La partie **ECC est intégralement codée à la main**.

## Installation 




## Structure du projet

Le projet est volontairement contenu dans un seul fichier afin de faciliter la lecture lors de la correction.


---

## Découpage logique du code

Le fichier `wildECC.py` est structuré en sections clairement identifiées.

### 1. Interface CLI

Fonctions :
- main()
- show_help()

Responsabilités :
- parsing des arguments
- validation des commandes
- affichage de l’aide (help)

---

### 2. Paramètres ECC

Courbe elliptique définie sur un corps fini :

Y² = X³ + 35X + 3 (mod 101)

Point générateur :
- P = (2, 9)

Définition :
- du corps fini
- de la courbe elliptique
- du point générateur

---

### 3. Mathématiques ECC (from scratch)

Fonctions :
- point_add()
- scalar_mult()
- modinv()

Implémentations :
- addition de points
- doublement de points
- multiplication scalaire (méthode *double & add*)

Aucune bibliothèque ECC n’est utilisée, conformément aux consignes du TP.

---

### 4. Gestion des clés

Fonctions :
- generate_keypair()
- write_private_key()
- write_public_key()
- read_private_key()
- read_public_key()

Les clés sont stockées dans des fichiers texte respectant strictement le format imposé par le sujet :
- encodage Base64
- en-têtes fixes

---

### 5. Secret partagé & dérivation de clé

Fonction :
- derive_shared_secret()

Implémente :
- le calcul du secret partagé ECC : S = kQ
- le refus du point à l’infini
- le hachage SHA-256 servant de matière de clé AES

---

### 6. Chiffrement / Déchiffrement AES

Fonctions :
- aes_encrypt()
- aes_decrypt()

Algorithme utilisé :
- AES-128 en mode CBC
- padding PKCS7
- IV = 16 premiers octets du hash
- clé AES = 16 derniers octets du hash

---

### 7. Chiffrement ECC hybride

Fonctions :
- crypt
- decrypt
- decrypt_message()

Principe :
- génération d’un secret ECC éphémère
- dérivation d’une clé symétrique AES
- chiffrement du message avec AES

---
## Utilisation du programme

### Afficher l’aide

```bash 
python3 wildECC.py help
```

---
### Générer une paire de clés

Fichiers générés :
- wildECC.priv → clé privée
- wildECC.pub → clé publique

---

### Chiffrer un message
```bash
python3 wildECC.py crypt wildECC.pub "hello world"
```

Sortie :
Qe_x;Qe_y|ciphertext_base64


Exemple :
2;9|Y+yml/PjydomZDd+7aUxUA==


---

### Déchiffrer un message

```bash 
python3 wildECC.py decrypt wildECC.priv "2;9|Y+yml/PjydomZDd+7aUxUA=="

```

Sortie :
hello world


---

## Bonus – Sécurité & limites

ATTENTION : ce programme n’est PAS sécurisé pour un usage réel.

### Limitations connues :
- Taille du champ très faible (p = 101)
- Clés privées comprises entre 1 et 1000
- Courbe non standard
- Absence d’authentification du message
- Aucune protection contre :
  - attaques par force brute
  - attaques par rejeu
  - attaques par canaux auxiliaires (side-channel)

### Ce que le programme fait correctement :
- Calcul d’un secret partagé ECC valide
- Chiffrement hybride ECC + AES
- IV distinct à chaque chiffrement
- Hash cryptographiquement sûr (SHA-256)

---






## Présentation

Ce projet est réalisé dans le cadre du **TP MonECC**.  
L’objectif est de développer **from scratch** une application en ligne de commande permettant de **chiffrer et déchiffrer des messages** en utilisant la **cryptographie sur courbes elliptiques (ECC)**.

Pour des raisons pédagogiques et de performances, la taille des clés utilisées est volontairement faible et **non sécurisée pour un usage réel**.  
L’objectif principal est la compréhension et l’implémentation des mécanismes internes de l’ECC.

---

## Prérequis & installation

### Langage
- Python **≥ 3.8**

### Dépendances Python

Seules les parties **AES / Hash** utilisent des bibliothèques externes (autorisé par le sujet).  
La partie **ECC est intégralement codée à la main**.

Installation recommandée via un environnement virtuel :

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography
```
---

## Structure du projet

Le projet est volontairement contenu dans un seul fichier afin de faciliter la lecture lors de la correction.


---

## Découpage logique du code

Le fichier `wildECC.py` est structuré en sections clairement identifiées.

### 1. Interface CLI

Fonctions :
- main()
- show_help()

Responsabilités :
- parsing des arguments
- validation des commandes
- affichage de l’aide (help)

---

### 2. Paramètres ECC

Courbe elliptique définie sur un corps fini :

Y² = X³ + 35X + 3 (mod 101)

Point générateur :
- P = (2, 9)

Définition :
- du corps fini
- de la courbe elliptique
- du point générateur

---

### 3. Mathématiques ECC (from scratch)

Fonctions :
- point_add()
- scalar_mult()
- modinv()

Implémentations :
- addition de points
- doublement de points
- multiplication scalaire (méthode *double & add*)

Aucune bibliothèque ECC n’est utilisée, conformément aux consignes du TP.

---

### 4. Gestion des clés

Fonctions :
- generate_keypair()
- write_private_key()
- write_public_key()
- read_private_key()
- read_public_key()

Les clés sont stockées dans des fichiers texte respectant strictement le format imposé par le sujet :
- encodage Base64
- en-têtes fixes

---

### 5. Secret partagé & dérivation de clé

Fonction :
- derive_shared_secret()

Implémente :
- le calcul du secret partagé ECC : S = kQ
- le refus du point à l’infini
- le hachage SHA-256 servant de matière de clé AES

---

### 6. Chiffrement / Déchiffrement AES

Fonctions :
- aes_encrypt()
- aes_decrypt()

Algorithme utilisé :
- AES-128 en mode CBC
- padding PKCS7
- IV = 16 premiers octets du hash
- clé AES = 16 derniers octets du hash

---

### 7. Chiffrement ECC hybride

Fonctions :
- crypt
- decrypt
- decrypt_message()

Principe :
- génération d’un secret ECC éphémère
- dérivation d’une clé symétrique AES
- chiffrement du message avec AES

---
## Utilisation du programme

### Afficher l’aide

```bash 
python3 wildECC.py help
```

---
### Générer une paire de clés

Fichiers générés :
- wildECC.priv → clé privée
- wildECC.pub → clé publique

---

### Chiffrer un message
```bash
python3 wildECC.py crypt wildECC.pub "hello world"
```

Sortie :
Qe_x;Qe_y|ciphertext_base64


Exemple :
2;9|Y+yml/PjydomZDd+7aUxUA==


---

### Déchiffrer un message

```bash 
python3 wildECC.py decrypt wildECC.priv "2;9|Y+yml/PjydomZDd+7aUxUA=="

```

Sortie :
hello world


---

## Bonus – Sécurité & limites

ATTENTION : ce programme n’est PAS sécurisé pour un usage réel.

### Limitations connues :
- Taille du champ très faible (p = 101)
- Clés privées comprises entre 1 et 1000
- Courbe non standard
- Absence d’authentification du message
- Aucune protection contre :
  - attaques par force brute
  - attaques par rejeu
  - attaques par canaux auxiliaires (side-channel)

### Ce que le programme fait correctement :
- Calcul d’un secret partagé ECC valide
- Chiffrement hybride ECC + AES
- IV distinct à chaque chiffrement
- Hash cryptographiquement sûr (SHA-256)

---




