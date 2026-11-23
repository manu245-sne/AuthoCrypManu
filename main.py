
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from totp import generer_secret, generer_code, verifier_code
from rsa import generer_cles, chiffrer, dechiffrer
from elgamal import (
    generer_cles as generer_cles_elgamal,
    chiffrer as chiffrer_elgamal,
    dechiffrer as dechiffrer_elgamal
)
from sac_a_dos import (
    generer_cles as generer_cles_sac,
    chiffrer as chiffrer_sac,
    dechiffrer as dechiffrer_sac
)
from base_donnees import (
    initialiser,
    creer_compte,
    verifier_identifiants,
    obtenir_secret
)

from totp import generer_secret, generer_code, verifier_code

class AuthCrypManuApp(App):

    def build(self):
        initialiser()

        self.root = BoxLayout(
            orientation="vertical",
            padding=20,
            spacing=10
        )
        self.accueil()
        return self.root

    
    def accueil(self):
        self.root.clear_widgets()

        self.root.add_widget(Label(
            text="AUTHCRYPMANU",
            font_size=30
        ))

        self.root.add_widget(Label(
            text="Application d'authentification cryptographique"
        ))

        for nom, methode in [
            ("RSA", self.interface_rsa),
            ("ElGamal", self.interface_elgamal),
            ("Sac à dos", self.interface_sac_a_dos),
            ("Authentification OTP", self.interface_otp)
        ]:
            bouton = Button(
                text=nom,
                size_hint_y=None,
                height=55
            )
            bouton.bind(on_release=methode)
            self.root.add_widget(bouton)

        # Bouton inscription
        bouton_inscription = Button(
            text="Créer un compte",
            size_hint_y=None,
            height=55
        )
        bouton_inscription.bind(
            on_release=self.interface_inscription
        )
        self.root.add_widget(bouton_inscription)

        # Bouton connexion
        bouton_connexion = Button(
            text="Se connecter",
            size_hint_y=None,
            height=55
        )
        bouton_connexion.bind(
            on_release=self.interface_connexion
        )
        self.root.add_widget(bouton_connexion)

    def bouton_retour(self):
        bouton = Button(
            text="Retour au menu",
            size_hint_y=None,
            height=45
        )
        bouton.bind(on_release=self.accueil)
        return bouton

    # RSA
    def interface_rsa(self, instance):
        self.root.clear_widgets()

        self.champ_p = TextInput(hint_text="Nombre premier p (61)", multiline=False)
        self.champ_q = TextInput(hint_text="Nombre premier q (53)", multiline=False)
        self.champ_e = TextInput(hint_text="Exposant e (17)", multiline=False)
        self.champ_message = TextInput(hint_text="Message numérique (65)", multiline=False)

        bouton = Button(text="Exécuter RSA", size_hint_y=None, height=50)
        bouton.bind(on_release=self.executer_rsa)

        self.resultat = Label(text="Résultats RSA")

        for widget in [
            Label(text="AUTHCRYPMANU - RSA", font_size=24),
            self.champ_p, self.champ_q, self.champ_e,
            self.champ_message, bouton, self.resultat,
            self.bouton_retour()
        ]:
            self.root.add_widget(widget)

    def executer_rsa(self, instance):
        try:
            p = int(self.champ_p.text)
            q = int(self.champ_q.text)
            e = int(self.champ_e.text)
            message = int(self.champ_message.text)

            publique, privee = generer_cles(p, q, e)
            chiffre = chiffrer(message, publique)
            resultat = dechiffrer(chiffre, privee)

            self.resultat.text = (
                f"Clé publique : {publique}\n"
                f"Clé privée : {privee}\n"
                f"Message chiffré : {chiffre}\n"
                f"Message déchiffré : {resultat}\n"
                f"Vérification : {'SUCCÈS' if resultat == message else 'ÉCHEC'}"
            )
        except Exception as erreur:
            self.resultat.text = f"Erreur : {erreur}"

    # ELGAMAL
    def interface_elgamal(self, instance):
        self.root.clear_widgets()

        self.champ_p_elgamal = TextInput(hint_text="Nombre premier p (467)", multiline=False)
        self.champ_g = TextInput(hint_text="Générateur g (2)", multiline=False)
        self.champ_x = TextInput(hint_text="Clé privée x (127)", multiline=False)
        self.champ_message_elgamal = TextInput(hint_text="Message numérique (100)", multiline=False)

        bouton = Button(text="Exécuter ElGamal", size_hint_y=None, height=50)
        bouton.bind(on_release=self.executer_elgamal)

        self.resultat = Label(text="Résultats ElGamal")

        for widget in [
            Label(text="AUTHCRYPMANU - ELGAMAL", font_size=24),
            self.champ_p_elgamal, self.champ_g,
            self.champ_x, self.champ_message_elgamal,
            bouton, self.resultat, self.bouton_retour()
        ]:
            self.root.add_widget(widget)

    def executer_elgamal(self, instance):
        try:
            p = int(self.champ_p_elgamal.text)
            g = int(self.champ_g.text)
            x = int(self.champ_x.text)
            message = int(self.champ_message_elgamal.text)

            publique, privee = generer_cles_elgamal(p, g, x)
            chiffre = chiffrer_elgamal(message, publique)
            resultat = dechiffrer_elgamal(chiffre, privee, p)

            self.resultat.text = (
                f"Clé publique : {publique}\n"
                f"Clé privée : {privee}\n"
                f"Message chiffré : {chiffre}\n"
                f"Message déchiffré : {resultat}\n"
                f"Vérification : {'SUCCÈS' if resultat == message else 'ÉCHEC'}"
            )
        except Exception as erreur:
            self.resultat.text = f"Erreur : {erreur}"

    # SAC A DOS
    def interface_sac_a_dos(self, instance):
        self.root.clear_widgets()

        self.champ_message_sac = TextInput(
            hint_text="Message à chiffrer (ex : MANU)",
            multiline=False
        )

        bouton = Button(
            text="Exécuter le sac à dos",
            size_hint_y=None,
            height=50
        )
        bouton.bind(on_release=self.executer_sac_a_dos)

        self.resultat = Label(text="Résultats sac à dos")

        for widget in [
            Label(text="AUTHCRYPMANU - SAC À DOS", font_size=24),
            self.champ_message_sac, bouton,
            self.resultat, self.bouton_retour()
        ]:
            self.root.add_widget(widget)

    def executer_sac_a_dos(self, instance):
        try:
            message = self.champ_message_sac.text

            publique, privee = generer_cles_sac()
            chiffre = chiffrer_sac(message, publique)
            resultat = dechiffrer_sac(chiffre, privee)

            self.resultat.text = (
                f"Clé publique : {publique}\n"
                f"Message chiffré : {chiffre}\n"
                f"Message déchiffré : {resultat}\n"
                f"Vérification : {'SUCCÈS' if resultat == message else 'ÉCHEC'}"
            )
        except Exception as erreur:
            self.resultat.text = f"Erreur : {erreur}"
    # INTERFACE AUTHENTIFICATION OTP
    def interface_otp(self, instance):
        self.root.clear_widgets()

        self.secret_otp = generer_secret()

        titre = Label(
            text="AUTHCRYPMANU - AUTHENTIFICATION OTP",
            font_size=20,
            size_hint_y=None,
            height=60
        )

        self.affichage_secret = Label(
            text=f"Secret partagé : {self.secret_otp}"
        )

        bouton_code = Button(
            text="Générer un code OTP",
            size_hint_y=None,
            height=50
        )
        bouton_code.bind(on_release=self.afficher_code_otp)

        self.champ_code_otp = TextInput(
            hint_text="Saisir le code OTP à 6 chiffres",
            multiline=False,
            input_filter="int"
        )

        bouton_verifier = Button(
            text="Vérifier le code",
            size_hint_y=None,
            height=50
        )
        bouton_verifier.bind(on_release=self.verifier_otp_interface)

        self.resultat_otp = Label(
            text="En attente d'authentification..."
        )

        retour = Button(
            text="Retour au menu",
            size_hint_y=None,
            height=45
        )
        retour.bind(on_release=self.accueil)

        for widget in [
            titre,
            self.affichage_secret,
            bouton_code,
            self.champ_code_otp,
            bouton_verifier,
            self.resultat_otp,
            retour
        ]:
            self.root.add_widget(widget)

    def afficher_code_otp(self, instance):
        code = generer_code(self.secret_otp)

        self.resultat_otp.text = (
            f"Votre code OTP est : {code}\n"
            "Ce code est valable environ 30 secondes."
        )

    def verifier_otp_interface(self, instance):
        code = self.champ_code_otp.text

        if verifier_code(self.secret_otp, code):
            self.resultat_otp.text = (
                "AUTHENTIFICATION REUSSIE !"
            )
        else:
            self.resultat_otp.text = (
                "CODE INCORRECT OU EXPIRE."
            )

	
    # INTERFACE INSCRIPTION
    def interface_inscription(self, instance):
        self.root.clear_widgets()

        titre = Label(text="CREATION D'UN COMPTE", font_size=24)

        self.nom_inscription = TextInput(
            hint_text="Nom d'utilisateur",
            multiline=False
        )

        self.mdp_inscription = TextInput(
            hint_text="Mot de passe (8 caractères minimum)",
            password=True,
            multiline=False
        )

        bouton = Button(
            text="Créer mon compte",
            size_hint_y=None,
            height=50
        )
        bouton.bind(on_release=self.executer_inscription)

        self.resultat_compte = Label(
            text="Remplissez les champs pour vous inscrire."
        )

        retour = Button(
            text="Retour au menu",
            size_hint_y=None,
            height=45
        )
        retour.bind(on_release=self.accueil)

        for widget in [
            titre,
            self.nom_inscription,
            self.mdp_inscription,
            bouton,
            self.resultat_compte,
            retour
        ]:
            self.root.add_widget(widget)

    def executer_inscription(self, instance):
        nom = self.nom_inscription.text.strip()
        mot_de_passe = self.mdp_inscription.text

        secret = generer_secret()

        succes, message = creer_compte(
            nom,
            mot_de_passe,
            secret
        )

        if succes:
            self.resultat_compte.text = (
                f"{message}\n\n"
                f"Votre secret TOTP :\n{secret}\n\n"
                "Conservez ce secret en lieu sûr."
            )
        else:
            self.resultat_compte.text = message

    # INTERFACE CONNEXION
    def interface_connexion(self, instance):
        self.root.clear_widgets()

        titre = Label(
            text="CONNEXION AUTHCRYPMANU",
            font_size=24
        )

        self.nom_connexion = TextInput(
            hint_text="Nom d'utilisateur",
            multiline=False
        )

        self.mdp_connexion = TextInput(
            hint_text="Mot de passe",
            password=True,
            multiline=False
        )

        self.code_connexion = TextInput(
            hint_text="Code OTP à 6 chiffres",
            multiline=False,
            input_filter="int"
        )

        bouton_code = Button(
            text="Générer un code de démonstration",
            size_hint_y=None,
            height=50
        )
        bouton_code.bind(on_release=self.generer_otp_connexion)

        bouton_connexion = Button(
            text="Vérifier et se connecter",
            size_hint_y=None,
            height=50
        )
        bouton_connexion.bind(on_release=self.executer_connexion)

        self.resultat_connexion = Label(
            text="Saisissez vos identifiants."
        )

        retour = Button(
            text="Retour au menu",
            size_hint_y=None,
            height=45
        )
        retour.bind(on_release=self.accueil)

        for widget in [
            titre,
            self.nom_connexion,
            self.mdp_connexion,
            self.code_connexion,
            bouton_code,
            bouton_connexion,
            self.resultat_connexion,
            retour
        ]:
            self.root.add_widget(widget)

    def generer_otp_connexion(self, instance):
        nom = self.nom_connexion.text.strip()

        secret = obtenir_secret(nom)

        if secret is None:
            self.resultat_connexion.text = "Utilisateur introuvable."
            return

        code = generer_code(secret)
        self.code_connexion.text = code

        self.resultat_connexion.text = (
            f"Code de démonstration : {code}\n"
            "Valable environ 30 secondes."
        )

    def executer_connexion(self, instance):
        nom = self.nom_connexion.text.strip()
        mot_de_passe = self.mdp_connexion.text
        code = self.code_connexion.text.strip()

        if not verifier_identifiants(nom, mot_de_passe):
            self.resultat_connexion.text = (
                "Nom d'utilisateur ou mot de passe incorrect."
            )
            return

        secret = obtenir_secret(nom)

        if secret is None or not verifier_code(secret, code):
            self.resultat_connexion.text = (
                "Code OTP incorrect ou expiré."
            )
            return

        self.resultat_connexion.text = (
            "AUTHENTIFICATION REUSSIE !\n"
            "Bienvenue dans AuthCrypManu."
        )


if __name__ == "__main__":
    AuthCrypManuApp().run()

