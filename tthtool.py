import sys
from itertools import chain, product, permutations, combinations
import string
import signal

charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def pause (debug):
    if debug:
        input()

# Encryption Method
def E (M, IV, debug=False, breaking=False):
    L = []
    encrypted = ""
    for k in range(len(M)):
        bloc = M[k]
        
        if debug:
            print("----- BLOC %d -----" % (k))
            for i in range(4):
                print(bloc[i*4:(4*i)+4])
            pause(breaking)

        # Initialisation avec IV / total_1 du bloc - 1
        if k == 0:
            total_1 = IV
        else:
            total_1 = L[-1]
        
        # Sommes des colonnes
        for col in range(4):
            somme = 0
            for line in range(4):
                somme += charset.index(bloc[col+line*4])
            total_1[col] = (total_1[col] + somme) % 26

        if debug:
            print("----- TOTAL 1 -----")
            print(total_1)
            pause(breaking)

        # Permutations circulaires
        # Ligne 1 [0:4]: bloc[1:4] + bloc[0]
        # Ligne 2 [4:8]: bloc[6:8] + bloc[4:6]
        # Ligne 3 [8:12]: bloc[11] + bloc[8:11]
        #
        # Inversement
        # Ligne 4 [12:16]: bloc[15] + bloc[14] + bloc[13] + bloc[12]
        lines  = bloc[1:4] + bloc[0]
        lines += bloc[6:8] + bloc[4:6]
        lines += bloc[11] + bloc[8:11]
        lines += bloc[15] + bloc[14] + bloc[13] + bloc[12]

        if debug:
            print("--- Permutations --")
            for i in range(4):
                print(lines[i*4:(4*i)+4])
            pause(breaking)

        # Sommes des colonnes
        total_2 = []
        for col in range(4):
            somme = 0
            for line in range(4):
                somme += charset.index(lines[col+line*4])
            total_2.append(somme % 26)

        if debug:
            print("----- TOTAL 2 -----")
            print(total_2)
            pause(breaking)

        # Ajout de total_2 à total_1
        for i in range(len(total_2)):
            total_1[i] = (total_1[i] + total_2[i]) % 26

        if debug:
            print("--- TOTAL FINAL ---")
            print(total_1)
            pause(breaking)

        # Ajout a la liste finale
        L.append(total_1)
        
    # Transformation en Hash
    for lists in L:
        for elt in lists:
            encrypted += charset[elt]
    if debug:
        print("---- ENCRYPTED ----")
        print(encrypted)
        print("-------------------")
    return encrypted

def wash (raw, askIV=True):
    # Ponçage
    raw = ''.join(raw.upper().split(' '))
    for c in raw:
        if c not in charset:
            raw.replace(c, "")

    # Padding
    while len(raw) % 16 != 0:
        raw += "A"
            
    # Creer M par blocs de 16
    M = [raw[i:(i+16)] for i in range(0, len(raw), 16)]

    # Initial Value
    IV = [0,0,0,0]
    if askIV:
        IV = [int(input("IV[%d]> " % i)) for i in range(4)]

    return M, IV

def collision_by_BF (hashed):
    # Fonction de bruteforce
    def bruteforce(charset, maxlength):
        return (''.join(candidate)
            for candidate in chain.from_iterable(product(charset, repeat=i)
            for i in range(1, maxlength + 1)))
    
    # Liste des possibilites, ici on travaille sur 6 caracteres
    L = bruteforce(charset, 6)

    # IV a (0,0,0,0)
    IV = [0, 0, 0, 0]
    for raw in L:
        M, IV = wash(raw, askIV=False)
        
        # Classic comparison
        elt = E(M, IV)
        if elt == hashed:
            print("[*] Collision finded with: %s" % (M))

def encrypt (debug=False, pauses=False):
    raw = input("Message> ")

    M, IV = wash(raw)
    print("[*] Plaintext: %s" % (M))
    print("[*] IV: %s" % (IV))
    print("[*] Encrypted: %s" % (E(M, IV, debug=debug, breaking=pauses)))

def print_menu (d, p):
    print("[0] Encrypt")
    print("[1] Decrypt by BruteForce Chosen-Ciphertext Attack")
    print("[2] Set debug mode to %r" % (not d))
    print("[3] Set pause mode to %r" % (not p))
    print("[4] Quit")

def main (debug=False, pauses=False):
    while True:
        print("------- MENU -------")
        print_menu(debug, pauses)
        ui = input("> ")
        while ui not in [str(i) for i in range(5)]:
            print("-- Enter a valid choice --")
            print_menu(debug, pauses)
            ui = input("> ")

        if ui == "0":
            encrypt(debug=debug, pauses=pauses)
        elif ui == "1":
            cc = input("Enter the ciphertext\n> ")
            print("/!\\ Press Ctrl + C to stop /!\\")
            collision_by_BF(cc)
        elif ui == "2":
            debug = not debug
        elif ui == "3":
            pauses = not pauses
        else:
            sys.exit(0)

def intHandler (signum, frame):
    print("/!\\ Algorithm stopped /!\\")
    main()

if __name__ == '__main__':
    # Sig Handler
    signal.signal(signal.SIGINT, intHandler)
    main()
