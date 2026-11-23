
# ==========================================
# AUTHCRYPMANU - ALGORITHME RSA
# ==========================================

def est_premier(n):
    """Verifie si un nombre est premier."""
    if n < 2:
        return False

    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False

    return True



def generer_cles(p, q, e):
    """Genere les cles publiques et privees RSA."""

    if not est_premier(p) or not est_premier(q):
        raise ValueError("p et q doivent etre premiers.")

    if p == q:
        raise ValueError("p et q doivent etre differents.")

    n = p * q
    phi = (p - 1) * (q - 1)

    if not (1 < e < phi):
        raise ValueError("e doit etre compris entre 1 et phi.")

    if phi % e == 0:
        raise ValueError("e et phi doivent etre premiers entre eux.")

    d = pow(e, -1, phi)

    cle_publique = (e, n)
    cle_privee = (d, n)

    return cle_publique, cle_privee


def chiffrer(message, cle_publique):
    """Chiffre un nombre avec la cle publique."""

    e, n = cle_publique

    if not isinstance(message, int) or not 0 <= message < n:
        raise ValueError("Le message doit etre un entier entre 0 et n-1.")

    return pow(message, e, n)


def dechiffrer(message_chiffre, cle_privee):
    """Dechiffre un nombre avec la cle privee."""

    d, n = cle_privee

    if not isinstance(message_chiffre, int) or not 0 <= message_chiffre < n:
        raise ValueError("Le message chiffre doit etre entre 0 et n-1.")

    return pow(message_chiffre, d, n)


# ==========================================
# TEST DE L'ALGORITHME RSA
# ==========================================

if __name__ == "__main__":

    p = 61
    q = 53
    e = 17

    publique, privee = generer_cles(p, q, e)

    message = 65

    chiffre = chiffrer(message, publique)
    resultat = dechiffrer(chiffre, privee)

    print("===== AUTHCRYPMANU : RSA =====")
    print("Cle publique :", publique)
    print("Cle privee :", privee)
    print("Message initial :", message)
    print("Message chiffre :", chiffre)
    print("Message dechiffre :", resultat)

    if resultat == message:
        print("SUCCES : le message est correctement retrouve.")
    else:
        print("ECHEC : erreur de dechiffrement.")

