from doc import about, header
import os
import sys
import logging
from datetime import datetime
from audit_analyse import AnalyseurAudit
from audit_systeme import AuditSysteme
from audit_apache import AuditApache
import json

class Menu:
    def __init__(self):
        self.begin = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        self.logger = self.configurer_logging()
        self.resultats_globaux = {}
        
    def configurer_logging(self):
        """Configure le système de logging"""
        # Configuration du logger principal
        logger = logging.getLogger('audit_principal')
        logger.setLevel(logging.INFO)
        
        # Création du handler pour le fichier de log
        os.system(f"mkdir outputs/logs_{self.begin}")
        log_handler = logging.FileHandler(f'outputs/logs_{self.begin}/{self.begin}_audit.log', mode='a', encoding='utf-8')
        log_handler.setLevel(logging.INFO)
        
        # Création du handler pour la console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Format des messages
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        log_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Ajout des handlers
        logger.addHandler(log_handler)
        logger.addHandler(console_handler)
        
        return logger

    def audit(self, choice):
        if choice == 1: # systeme
            self.audit_system()
            
    def audit_system(self):
        print("\n" + "="*60)
        print("DÉMARRAGE DE L'AUDIT SYSTÈME LINUX")
        print("="*60)
        
        self.logger.info("Démarrage de l'audit système Linux")
        
        try:
            audit_sys = AuditSysteme(self.begin, self.logger)
            
            print("Collecte des informations système en cours...")
            succes = audit_sys.executer_audit_complet()
            
            if succes:
                print("Audit système terminé avec succès")
                
                # Sauvegarde des résultats
                fichier_json = audit_sys.sauvegarder_resultats("json")
                fichier_txt = audit_sys.sauvegarder_resultats("txt")
                
                print(f"Résultats sauvegardés dans:")
                print(f"   - {fichier_json}")
                print(f"   - {fichier_txt}")
                
                # Stockage des résultats pour le résumé
                self.resultats_globaux["systeme"] = {
                    "succes": True,
                    "fichier_json": fichier_json,
                    "fichier_txt": fichier_txt,
                    "timestamp": datetime.now().isoformat()
                }
                
                self.logger.info("Audit système terminé avec succès")
                input("(appuyez sur entrée)")
                return True
            else:
                print("Erreur lors de l'audit système")
                self.logger.error("Erreur lors de l'audit système")
                input("(appuyez sur entrée)")
                return False
                
        except Exception as e:
            print(f"Erreur critique lors de l'audit système: {e}")
            self.logger.error(f"Erreur critique lors de l'audit système: {e}")
            return False
    
    def executer(self):
        while True:
            os.system("clear")
            header()
            choice = input("""AUdiThorium:
1. Audit Système seul
2. Audit Apache seul
3. Audit Sytèe & Apache
4. A propos
5. Quitter
> """)
            try:
                choice = int(choice)
            except Exception:
                continue
            if choice >= 1 and choice <= 3:
                self.audit(choice)
            elif choice == 4:
                about()
            elif choice == 5:
                break

def main():
    """Fonction principale"""
    # Vérification des permissions
    if os.geteuid() != 0:
        print("   ATTENTION: Ce script nécessite des privilèges administrateur")
        print("   Certaines informations peuvent être incomplètes sans sudo/root")
        print("   Recommandation: sudo python3 audit_principal.py")
        print()
        
        continuer = input("Voulez-vous continuer malgré tout? (o/N): ").strip().lower()
        if continuer not in ['o', 'oui', 'y', 'yes']:
            print("Arrêt du programme.")
            sys.exit(1)
    
    # Lancement du programme principal
    try:
        audit_principal = Menu()
        audit_principal.executer()
    except Exception as e:
        print(f"Erreur fatale: {e}")
        logging.error(f"Erreur fatale dans le programme principal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
