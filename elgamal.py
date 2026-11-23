
import secrets


def generer_cles(p, g, x):
    if p < 3:
        raise ValueError("p doit etre superieur ou egal a 3.")

    if not (1 < g < p):
        raise ValueError("g doit etre compris entre 1 et p.")

    if not (1 <= x <= p - 2):
        raise ValueError("La cle privee x est invalide.")

    y = pow(g, x, p)

    return (p, g, y), x


def chiffrer(message, cle_publique, k=None):
    p, g, y = cle_publique

    if not isinstance(message, int) or not 0 <= message < p:
        raise ValueError("Le message doit etre entre 0 et p-1.")

    if k is None:
        k = secrets.randbelow(p - 2) + 1

    if not 1 <= k <= p - 2:
        raise ValueError("La valeur k est invalide.")

    c1 = pow(g, k, p)
    c2 = (message * pow(y, k, p)) % p

    return c1, c2


def dechiffrer(message_chiffre, cle_privee, p):
    c1, c2 = message_chiffre

    if not (1 <= c1 < p and 0 <= c2 < p):
        raise ValueError("Le message chiffre est invalide.")

    s = pow(c1, cle_privee, p)
    inverse = pow(s, -1, p)

    return (c2 * inverse) % p


if __name__ == "__main__":

    p = 467
    g = 2
    x = 127

    publique, privee = generer_cles(p, g, x)

    message = 100

    chiffre = chiffrer(message, publique, k=53)
    resultat = dechiffrer(chiffre, privee, p)

    print("===== AUTHCRYPMANU : ELGAMAL =====")
    print("Cle publique :", publique)
    print("Cle privee :", privee)
    print("Message initial :", message)
    print("Message chiffre :", chiffre)
    print("Message dechiffre :", resultat)

    print("SUCCES" if resultat == message else "ECHEC")
