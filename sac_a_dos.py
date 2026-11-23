
def generer_cles():
    # Suite super-croissante
    privee = [2, 3, 7, 14, 30, 57, 120, 251]

    # Calcul de la somme
    somme = sum(privee)

    # Choix du modulo et du multiplicateur
    q = somme + 1
    r = 31

    # Vérification que r et q sont premiers entre eux
    if q % r == 0:
        raise ValueError("Choisir un autre multiplicateur.")

    publique = [(r * valeur) % q for valeur in privee]

    return publique, (privee, q, r)


def chiffrer(message, cle_publique):
    if not isinstance(message, str) or not message:
        raise ValueError("Le message doit être une chaîne non vide.")

    resultat = []

    for caractere in message:
        valeur = ord(caractere)

        if valeur > 255:
            raise ValueError("Utiliser uniquement des caractères ASCII.")

        chiffre = 0

        for i in range(8):
            bit = (valeur >> (7 - i)) & 1
            chiffre += bit * cle_publique[i]

        resultat.append(chiffre)

    return resultat


def dechiffrer(message_chiffre, cle_privee):
    privee, q, r = cle_privee

    inverse = pow(r, -1, q)
    resultat = ""

    for chiffre in message_chiffre:
        valeur = (chiffre * inverse) % q
        bits = [0] * 8

        for i in range(7, -1, -1):
            if privee[i] <= valeur:
                bits[i] = 1
                valeur -= privee[i]

        caractere = sum(
            bits[i] * (2 ** (7 - i)) for i in range(8)
        )

        resultat += chr(caractere)

    return resultat


if __name__ == "__main__":
    publique, privee = generer_cles()

    message = "MANU"
    chiffre = chiffrer(message, publique)
    resultat = dechiffrer(chiffre, privee)

    print("===== AUTHCRYPMANU : SAC A DOS =====")
    print("Cle publique :", publique)
    print("Cle privee :", privee)
    print("Message initial :", message)
    print("Message chiffre :", chiffre)
    print("Message dechiffre :", resultat)

    print("SUCCES" if resultat == message else "ECHEC")
