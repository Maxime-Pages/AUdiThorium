import os

def header():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                              AUdiThorium                                     ║
║                    Système Linux et Serveur Apache                           ║
║                                                                              ║
║                         Développé pour le module                             ║
║                            Scripting 2024-2025                               ║
╚══════════════════════════════════════════════════════════════════════════════╝



          """)

def about():
    os.system("clear")
    header()
    print("Développé par Louis de Lavenne, Maxime Pages, Quentin Lemaire.\n")
    print("\nApache Ubuntu Thorium (parce que le nucléaire c'est l'avenir et qu'il fait déjà tourner vos PC et serveurs).\n")
    print("1. Audit Système : \n\tfait tourner un script qui détecte les mauvaises utilisations \
les points faibles potentiels d'un serveur Linux")
    print("2. Audit Apache: \n\tfait tourner un script qui collecte les paramètres essentiels \
configuration d'un serveur Apache.")
    print("3. Audit Apache & Sysème : \n\tfait tourner les scripts 1 et 2 pour une analyse compète d'Apache et de Linux")
    input()
