
import sqlite3
import hashlib
import secrets
import hmac
import os

from cryptography.fernet import Fernet, InvalidToken

# Emplacement du projet
DOSSIER = os.path.dirname(os.path.abspath(__file__))
CHEMIN_DB = os.path.join(DOSSIER, "authcrypmanu.db")
CHEMIN_CLE = os.path.join(DOSSIER, "cle_secrete.key")


def obtenir_chiffreur():
    """Charge ou crée la clé de chiffrement des secrets TOTP."""

    if not os.path.exists(CHEMIN_CLE):
        cle = Fernet.generate_key()

        with open(CHEMIN_CLE, "xb") as fichier:
            fichier.write(cle)

        os.chmod(CHEMIN_CLE, 0o600)

    with open(CHEMIN_CLE, "rb") as fichier:
        cle = fichier.read()

    return Fernet(cle)


def initialiser():
    """Crée la table et protège les anciens secrets TOTP."""

    connexion = sqlite3.connect(CHEMIN_DB)

    connexion.execute("""
        CREATE TABLE IF NOT EXISTS utilisateurs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom_utilisateur TEXT UNIQUE COLLATE NOCASE,
            mot_de_passe_hash TEXT NOT NULL,
            sel TEXT NOT NULL,
            secret_totp TEXT NOT NULL
        )
    """)

    chiffreur = obtenir_chiffreur()

    utilisateurs = connexion.execute(
        "SELECT id, secret_totp FROM utilisateurs"
    ).fetchall()

    for identifiant, secret in utilisateurs:
        try:
            chiffreur.decrypt(secret.encode("utf-8"))
        except (InvalidToken, ValueError):
            secret_chiffre = chiffreur.encrypt(
                secret.encode("utf-8")
            ).decode("utf-8")

            connexion.execute(
                "UPDATE utilisateurs SET secret_totp = ? WHERE id = ?",
                (secret_chiffre, identifiant)
            )

    connexion.commit()
    connexion.close()


def hacher_mot_de_passe(mot_de_passe, sel):
    """Protège le mot de passe avec PBKDF2."""

    resultat = hashlib.pbkdf2_hmac(
        "sha256",
        mot_de_passe.encode("utf-8"),
        bytes.fromhex(sel),
        200000
    )

    return resultat.hex()


def creer_compte(nom_utilisateur, mot_de_passe, secret_totp):
    """Enregistre un nouvel utilisateur."""

    if not nom_utilisateur.strip():
        return False, "Le nom d'utilisateur est obligatoire."

    if len(mot_de_passe) < 8:
        return False, "Le mot de passe doit avoir au moins 8 caractères."

    sel = secrets.token_hex(16)
    mot_de_passe_hash = hacher_mot_de_passe(mot_de_passe, sel)

    chiffreur = obtenir_chiffreur()

    secret_chiffre = chiffreur.encrypt(
        secret_totp.encode("utf-8")
    ).decode("utf-8")

    try:
        connexion = sqlite3.connect(CHEMIN_DB)

        connexion.execute("""
            INSERT INTO utilisateurs
            (nom_utilisateur, mot_de_passe_hash, sel, secret_totp)
            VALUES (?, ?, ?, ?)
        """, (
            nom_utilisateur.strip(),
            mot_de_passe_hash,
            sel,
            secret_chiffre
        ))

        connexion.commit()
        connexion.close()

        return True, "Compte créé avec succès."

    except sqlite3.IntegrityError:
        return False, "Ce nom d'utilisateur existe déjà."


def verifier_identifiants(nom_utilisateur, mot_de_passe):
    """Vérifie le nom d'utilisateur et le mot de passe."""

    connexion = sqlite3.connect(CHEMIN_DB)

    utilisateur = connexion.execute("""
        SELECT mot_de_passe_hash, sel
        FROM utilisateurs
        WHERE nom_utilisateur = ?
    """, (nom_utilisateur.strip(),)).fetchone()

    connexion.close()

    if utilisateur is None:
        return False

    hash_enregistre, sel = utilisateur
    hash_saisi = hacher_mot_de_passe(mot_de_passe, sel)

    return hmac.compare_digest(hash_enregistre, hash_saisi)


def obtenir_secret(nom_utilisateur):
    """Déchiffre et récupère le secret TOTP."""

    connexion = sqlite3.connect(CHEMIN_DB)

    resultat = connexion.execute("""
        SELECT secret_totp
        FROM utilisateurs
        WHERE nom_utilisateur = ?
    """, (nom_utilisateur.strip(),)).fetchone()

    connexion.close()

    if resultat is None:
        return None

    chiffreur = obtenir_chiffreur()

    try:
        secret = chiffreur.decrypt(
            resultat[0].encode("utf-8")
        )

        return secret.decode("utf-8")

    except (InvalidToken, ValueError):
        return None


if __name__ == "__main__":
    initialiser()
    print("Base de données AuthCrypManu initialisée.")

