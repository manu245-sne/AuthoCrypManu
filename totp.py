
import base64
import hashlib
import hmac
import secrets
import struct
import time


def generer_secret():
    """Génère un secret aléatoire encodé en Base32."""
    secret = secrets.token_bytes(20)
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def generer_code(secret, periode=30, chiffres=6):
    """Génère un code TOTP temporaire."""
    secret_bytes = base64.b32decode(
        secret + "=" * ((8 - len(secret) % 8) % 8)
    )

    compteur = int(time.time()) // periode
    message = struct.pack(">Q", compteur)

    empreinte = hmac.new(
        secret_bytes,
        message,
        hashlib.sha1
    ).digest()

    position = empreinte[-1] & 0x0F

    valeur = struct.unpack(
        ">I",
        empreinte[position:position + 4]
    )[0] & 0x7FFFFFFF

    code = valeur % (10 ** chiffres)

    return str(code).zfill(chiffres)


def verifier_code(secret, code, periode=30, fenetre=1):
    """Vérifie un code TOTP avec une petite tolérance temporelle."""
    if not code.isdigit() or len(code) != 6:
        return False

    for decalage in range(-fenetre, fenetre + 1):
        temps = int(time.time()) + decalage * periode

        secret_bytes = base64.b32decode(
            secret + "=" * ((8 - len(secret) % 8) % 8)
        )

        compteur = temps // periode
        message = struct.pack(">Q", compteur)

        empreinte = hmac.new(
            secret_bytes,
            message,
            hashlib.sha1
        ).digest()

        position = empreinte[-1] & 0x0F

        valeur = struct.unpack(
            ">I",
            empreinte[position:position + 4]
        )[0] & 0x7FFFFFFF

        attendu = str(valeur % 1000000).zfill(6)

        if hmac.compare_digest(attendu, code):
            return True

    return False


if __name__ == "__main__":
    secret = generer_secret()
    code = generer_code(secret)

    print("===== AUTHCRYPMANU : TOTP =====")
    print("Secret :", secret)
    print("Code temporaire :", code)
    print("Vérification :", verifier_code(secret, code))
