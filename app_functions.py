import re
import hashlib
import random
import math
import getpass
import os
import sys
from email_validator import validate_email, EmailNotValidError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def create_auth_file_if_not_exists():
    if not os.path.isfile('./Authentification.txt'):
        with open('./Authentification.txt', 'w') as file:
            file.write("Newly created Authentification File\n")

file_path = "./Authentification.txt"

def list():
    with open('Authentification.txt', 'r') as auth_file:
        lines = auth_file.readlines()  
        for line in lines:
            print(line)

def read_auth_file():
    create_auth_file_if_not_exists() 

    AuthDict = {}
    with open('./Authentification.txt', 'r') as auth_file:
        lines = auth_file.readlines()
        for i, line in enumerate(lines):
            if 'Login&password:' in line:
                login, password = line[11:-2].split('&')
                AuthDict[login] = password

    return AuthDict
        
def authentification():
    login = getpass.getpass("Login : ")
    password = getpass.getpass("password : ")
    AuthDict = read_auth_file()

    if login in AuthDict and AuthDict[login] == password:
        
        return True
    else:
        print("Authentification échouée. Veuillez vous enregistrer avant de continuer.")
        return False

def auth():
    if os.path.exists(file_path):
        
        while True:
            display_menuB()    
            choice = input("Enter your choice: ")
            choice = choice.upper()  
            if choice == "B1":
                if authentification():
                    hachage()
            elif choice == "B2":
                if authentification():
                    chiff()
            elif choice == "B3":
                    menu_redirector()
            else:
                print("Invalid choice. Please enter a valid option. or you are not authentificated")
    else:
        print("You should create Authentification.txt file to continue")


def display_menu():
    print("#### Application Multi Taches ####")
    print("A- Enregistrement")
    print("B- Authentification")
    print("C- Quitter")

def display_menuA():
    print("###### Menu A : Enregistrement ######")
    print("A1- Sauvegarder Données utilisateur")
    print("A2- Lire Données utilisteur")
    print("A3- Revenir au menu principal")

def display_menuB():
    print("###### Menu B : Authentification ######")
    print("B1- Hachage")
    print("B2- Chiffrement")
    print("B3- Revenir au menu principal")

def display_menub1():
    print("Menu B1 : Hachage")
    print("B1-A : Hacher un message par MDS")
    print("B1-B : Hacher un message par SHA256")
    print("B1-C : Hacher un message par Blake2b")
    print("B1-D : Cracker un message Haché")
    print("B1-E : Revenir au menu MenuB")

def display_menub2():
    print("Menu B2 chiffrement message")
    print("B2-A : cresar")
    print("    B2-A1 : Chiffrement messge")
    print("    B2-A2 : Dechiffrement messge")
    print("    B2-A3 : Revenir au menuB2 ")
    print("B2-B : affine")
    print("    B2-B1 : Chiffrement messge")
    print("    B2-B2 : Dechiffrement messge")
    print("    B2-B3 : Revenir au menuB2 ")
    print("B2-C : RSA")
    print("    B2-C1 : Chiffrement messge")
    print("    B2-C2 : Dechiffrement messge")
    print("    B2-C3 : Signature")
    print("    B2-C4 : Vérification signature")
    print("    B2-C5 : Revenir au menuB2")
    print("B2-D : Revenir au menuB")


def menu_redirector():
    while True:
        display_menu()
        choice = input("Enter your choice: ")
        choice = choice.upper()

        if choice == "A":
            enrollment_menu()
        elif choice == "B":
            auth()
        elif choice == "C":
            print("Goodbye!")
            sys.exit()
        else:
            print("Invalid choice. Please enter a valid option.")
            

def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                encrypted_char = chr(((ord(char) - ord('a') + shift_amount) % 26) + ord('a'))
            else:
                encrypted_char = chr(((ord(char) - ord('A') + shift_amount) % 26) + ord('A'))
            result += encrypted_char
        else:
            result += char
    return result

def enrollment_menu():
    while True:
        display_menuA()
        choice = input("Enter your choice: ")
        choice = choice.upper()  # Convert input to uppercase for case-insensitive comparison

        match choice:
            case "A1":
                data_input()
            case "A2":
                list()
            case "A3":
                menu_redirector()
            case _:
                print("Invalid selection. Please input a valid option.")


def data_input():
    with open('./Authentification.txt', 'a') as file:
        while True:
            Login = input("Donnez votre login: ")
            password = getpass.getpass("Saisissez votre password :")
            print("""
            "Choisissez votre classe (A/B/C/D) :\n"
            "A- SSIR\n"
            "B- GL\n"
            "C- IOT\n"
            "D- DS\n"
            """)
            class_mapping = {
                'A': 'SSIR',
                'B': 'GL',
                'C': 'IOT',
                'D': 'DS',
            }
            selected_class = input("Entrez la lettre correspondant à la classe choisie: ")
            Classe = class_mapping.get(selected_class.upper(), "Classe invalide")
            while Classe == "Classe invalide":
                selected_class = input("Choisir une classe valide : ")
                Classe = class_mapping.get(selected_class.upper(), "Classe invalide")
            
            Email = input("Donnez votre email: ")
            while True:
                try:
                    validate_email(Email)
                    break
                except EmailNotValidError:
                    print("Email invalide. Veuillez entrer une adresse email valide.")
                    Email = input("Donnez votre email: ")

            lp = f"{Login}&{password}"
            id_user = random.randint(1, 1000)
            file.write(f"Id_user: {id_user}\nLogin&password: {lp}\nclasse: {Classe}\nEmail: {Email}\n\n")

            print("User data saved.")
            break


ListeM = ["password", "azerty", "shadow", "hunter", "secure", "crypto", "key", "algorithm", "protect", "encode"]

ListeMD5 = {}
ListeSHA256 = {}
ListeBlake2b = {}

def hacher_message(message, algorithm):
    if algorithm == "MD5":
        return hashlib.md5(message.encode()).hexdigest()
    elif algorithm == "SHA256":
        return hashlib.sha256(message.encode()).hexdigest()
    elif algorithm == "Blake2b":
        return hashlib.blake2b(message.encode()).hexdigest()


ListeMH = [
    '5f4dcc3b5aa765d61d8327deb882cf99',
    'e3d0cac0:9a5fa1e3051bda8f5143d5e3',
    '53fbc6eb12439e52772e5e70e37bb418',
    '2c6ee28b36b001df50124e9b62656b16',
    'be12f38e6e0df3fbf72e5b4f54b6fca9',
    'd41d8cd98f00b204e9800998ecf8427e',
    '81922f23255ef898ae80b0db7a048230',
    'b6589fc6ab0dc82cf12099d1c2d40ab994e8410c',
    '80d1714d5160f1a7091221763768bcf7',
    '7df88de9e580e83b1ac8b9143ab572e4'
]

def cracker_hachage(hache):
    for hachage in ListeMH:
        for mot in ListeM:
            if hachage == hashlib.md5(mot.encode()).hexdigest() :
                return mot
            
def hachage():
    
    while True:
        display_menub1()
        choice = input("Entrez votre choix: ")
        choice = choice.upper()  
        if choice == "B1-A":
            for word in ListeM:
                hache = hacher_message(word, "MD5")
                ListeMD5[word] = hache
            print("Résultats du hachage MDS :", ListeMD5)
            print("\n")
            
        elif choice == "B1-B":
            for word in ListeM:
                hache = hacher_message(word, "SHA256")
                ListeSHA256[word] = hache
            print("Résultats du hachage SHA256 :", ListeSHA256)
            print("\n")
        
        elif choice == "B1-C":
            for word in ListeM:
                hache = hacher_message(word, "Blake2b")
                ListeBlake2b[word] = hache
            print("Résultats du hachage Blake2b :", ListeBlake2b)
            print("\n")
        
        elif choice == "B1-D":
           mot_cracké=cracker_hachage(ListeMH)  
           print("le mot haché est ",mot_cracké)
           print("\n")
        elif choice == "B1-E":
            auth()
            
        else:
            print("Invalid choice. Please enter a valid option.")

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


def generate_affine_keys():
    while True:
        a = random.randint(1, 25)
        if math.gcd(a, 26) == 1:
            break
    b = random.randint(1, 25)
    return a, b

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def affine_encrypt(text, a, b):
    result = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                encrypted_char = chr(((a * (ord(char) - ord('a')) + b) % 26) + ord('a'))
            else:
                encrypted_char = chr(((a * (ord(char) - ord('A')) + b) % 26) + ord('A'))
            result += encrypted_char
        else:
            result += char
    return result


def affine_decrypt(text, a, b):
    a_inverse = mod_inverse(a, 26)
    result = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                decrypted_char = chr(((a_inverse * (ord(char) - ord('a') - b)) % 26) + ord('a'))
            else:
                decrypted_char = chr(((a_inverse * (ord(char) - ord('A') - b)) % 26) + ord('A'))
            result += decrypted_char
        else:
            result += char
    return result



def generate_rsa_key_pair():
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open('private_key.pem', 'wb') as file:
        file.write(private_pem)

    
    public_key = private_key.public_key()

    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('public_key.pem', 'wb') as file:
        file.write(public_pem)

    return private_key, public_key

def rsa_encrypt(public_key, message):
    
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def rsa_sign(private_key, message):
    
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def rsa_verify(public_key, message, signature):
    
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return "Signature is valid."
    except:
        return "Signature is invalid."



def chiff():
    a, b = generate_affine_keys()
    private_key, public_key = generate_rsa_key_pair()

    while True:
        display_menub2()
        choice = input("Enter your choice: ")
        choice = choice.upper()

        match choice:
            case "B2-A1":
                text = input("Enter the text: ")
                shift = int(input("Enter the shift value: "))
                encrypted_text = caesar_encrypt(text, shift)
                print("Encrypted text:", encrypted_text)

            case "B2-A2":
                text = input("Enter the cipher text ")
                shift = int(input("Enter the shift value: "))
                decrypted_text = caesar_decrypt(text, shift)
                print("Decrypted text:", decrypted_text)

            case "B2-A3":
                chiff()

            case "B2-B1":
                text = input("Enter the text: ")
                encrypted_text = affine_encrypt(text, a, b)
                print("Encrypted text:", encrypted_text)

            case "B2-B2":
                text = input("Enter the cipher text: ")
                decrypted_text = affine_decrypt(text, a, b)
                print("Decrypted text:", decrypted_text)

            case "B2-B3":
                chiff()

            case "B2-C1":
                message = input("Enter the message to encrypt: ").encode()
                ciphertext = rsa_encrypt(public_key, message)
                print("Encrypted message:", ciphertext.hex())

            case "B2-C2":
                ciphertext_hex = input("Enter the ciphertext (in hexadecimal): ")
                ciphertext = bytes.fromhex(ciphertext_hex)
                decrypted_message = rsa_decrypt(private_key, ciphertext)
                print("Decrypted message:", decrypted_message.decode())

            case "B2-C3":
                message = input("Enter the message to sign: ").encode()
                signature = rsa_sign(private_key, message)
                print("Signature:", signature.hex())

            case "B2-C4":
                message = input("Enter the message: ").encode()
                signature_hex = input("Enter the signature: ")
                signature = bytes.fromhex(signature_hex)
                result = rsa_verify(public_key, message, signature)
                print(result)

            case "B2-C5":
                chiff()

            case "B2-D":
                menu_redirector()

            case _:
                print("Invalid choice. Please enter a valid option.")


    

