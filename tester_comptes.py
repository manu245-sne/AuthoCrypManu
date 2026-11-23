
from base_donnees import (
    initialiser,
    creer_compte,
    verifier_identifiants,
    obtenir_secret
)
from totp import generer_secret, generer_code, verifier_code

# Initialisation
initialiser()

# Création d'un compte de test
nom = "test_manu"
mot_de_passe = "ManuTest2026!"

secret = generer_secret()

succes, message = creer_compte(nom, mot_de_passe, secret)

print("===== TEST AUTHCRYPMANU =====")
print("Inscription :", message)

# Récupération du secret
secret_enregistre = obtenir_secret(nom)

# Vérification du mot de passe
connexion = verifier_identifiants(nom, mot_de_passe)
print("Vérification du mot de passe :", connexion)

# Génération et vérification du code OTP
code = generer_code(secret_enregistre)
print("Code OTP généré :", code)
print("Vérification OTP :", verifier_code(secret_enregistre, code))
