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
        os.system(f"mkdir -p outputs/logs_{self.begin}")
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
            input("(appuyez sur entrée)")
        elif choice == 2: # apache
            self.executer_audit_apache()
            input("(appuyez sur entrée)")
        elif choice == 3: # complet
            self.executer_audits_complets()
            input("(appuyez sur entrée)")
        elif choice == 4: # analyser
            self.executer_audit_analyse()
            input("(appuyez sur entrée)")
        elif choice == 5: # afficher
            self.afficher_resultats()
            input("(appuyez sur entrée)")

            
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
                return True
            else:
                print("Erreur lors de l'audit système")
                self.logger.error("Erreur lors de l'audit système")
                return False
                
        except Exception as e:
            print(f"Erreur critique lors de l'audit système: {e}")
            self.logger.error(f"Erreur critique lors de l'audit système: {e}")
            return False
    
    def executer_audit_apache(self):
        """Exécute l'audit Apache"""
        print("\n" + "="*60)
        print("DÉMARRAGE DE L'AUDIT APACHE")
        print("="*60)
        
        self.logger.info("Démarrage de l'audit Apache")
        
        try:
            audit_apache = AuditApache(self.begin, self.logger)
            
            print("Collecte des informations Apache en cours...")
            succes = audit_apache.executer_audit_complet()
            
            if succes:
                print("Audit Apache terminé avec succès")
                
                # Sauvegarde des résultats
                fichier_json = audit_apache.sauvegarder_resultats("json")
                fichier_txt = audit_apache.sauvegarder_resultats("txt")
                
                print(f"Résultats sauvegardés dans:")
                print(f"   - {fichier_json}")
                print(f"   - {fichier_txt}")
                
                # Stockage des résultats pour le résumé
                self.resultats_globaux["apache"] = {
                    "succes": True,
                    "fichier_json": fichier_json,
                    "fichier_txt": fichier_txt,
                    "timestamp": datetime.now().isoformat()
                }
                
                print("Audit Apache terminé avec succès")
                self.logger.info("Audit Apache terminé avec succès")
                return True
            else:
                print("Erreur lors de l'audit Apache")
                self.logger.error("Erreur lors de l'audit Apache")
                return False
                
        except Exception as e:
            print(f"Erreur critique lors de l'audit Apache: {e}")
            self.logger.error(f"Erreur critique lors de l'audit Apache: {e}")
            return False
    
    def executer_audits_complets(self):
        """Exécute les deux audits"""
        print("\n" + "="*60)
        print("DÉMARRAGE DES AUDITS COMPLETS")
        print("="*60)
        
        self.logger.info("Démarrage des audits complets (système + Apache)")
        
        succes_systeme = self.audit_system()
        succes_apache = self.executer_audit_apache()
        
        print("\n" + "="*60)
        print("RÉSUMÉ DES AUDITS")
        print("="*60)
        
        if succes_systeme and succes_apache:
            print("Tous les audits ont été exécutés avec succès")
            self.logger.info("Tous les audits terminés avec succès")
        elif succes_systeme:
            print("Audit système: Succès")
            print("Audit Apache: Échec")
            self.logger.warning("Audit système réussi, audit Apache échoué")
        elif succes_apache:
            print("Audit système: Échec")
            print("Audit Apache: Succès")
            self.logger.warning("Audit Apache réussi, audit système échoué")
        else:
            print("Tous les audits ont échoué")
            self.logger.error("Tous les audits ont échoué")
        
        return succes_systeme or succes_apache
    
    def executer_audit_analyse(self):
        """Exécute l'analyse des résultats d'audit"""
        print("\n" + "="*60)
        print("DÉMARRAGE DE L'ANALYSE DES RÉSULTATS D'AUDIT")
        print("="*60)
        
        self.logger.info("Démarrage de l'analyse des résultats d'audit")
        
        try:
            analyseur = AnalyseurAudit(self.begin, self.logger)
            analyseur.analyser_complet(f'outputs/logs_{self.begin}/{self.begin}_audit_systeme.json',f'outputs/logs_{self.begin}/{self.begin}_audit_apache.json')
            print("✅ Analyse des résultats terminée avec succès")
            self.logger.info("Analyse des résultats terminée avec succès")
        except Exception as e:
            print(f"Erreur lors de l'analyse des résultats: {e}")
            self.logger.error(f"Erreur lors de l'analyse des résultats: {e}")
    
    
    def afficher_resultats(self):
        """Affiche les résultats des derniers audits"""
        print("\n" + "="*60)
        print("RÉSULTATS DES DERNIERS AUDITS")
        print("="*60)
        
        if not self.resultats_globaux:
            print("Aucun audit n'a été exécuté dans cette session.")

            fichier = f"outputs/logs_{self.begin}/{self.begin}_audit.log"
            if os.path.exists(fichier):
                print("\nFICHIERS D'AUDIT PRÉSENTS:")
                taille = os.path.getsize(fichier)
                print(f"     {fichier} ({taille} octets)")
            return
        
        for type_audit, resultats in self.resultats_globaux.items():
            print(f"\nAUDIT {type_audit.upper()}:")
            print(f"   Status: {'Succès' if resultats['succes'] else 'Échec'}")
            print(f"   Timestamp: {resultats['timestamp']}")
            if resultats['succes']:
                print(f"   Fichiers générés:")
                print(f"     - {resultats['fichier_json']}")
                print(f"     - {resultats['fichier_txt']}")
        
        # Vérification des fichiers existants
        print("\nFICHIERS D'AUDIT PRÉSENTS:")
        fichiers_audit = [
            f"outputs/logs_{self.begin}/{self.begin}_audit_systeme.json",
            f"outputs/logs_{self.begin}/{self.begin}_audit_systeme.txt",
            f"outputs/logs_{self.begin}/{self.begin}_audit_apache.json", 
            f"outputs/logs_{self.begin}/{self.begin}_audit_apache.txt",
            f"outputs/logs_{self.begin}/{self.begin}_audit.log"
        ]
        
        for fichier in fichiers_audit:
            if os.path.exists(fichier):
                taille = os.path.getsize(fichier)
                print(f"     {fichier} ({taille} octets)")
            else:
                print(f"     {fichier} (non trouvé)")
    
    
    def executer(self):
        while True:
            os.system("clear")
            header()
            choice = input("""AUdiThorium:
1. Audit Système seul
2. Audit Apache seul
3. Audit Sytsème & Apache
4. Analyse Auto des résultats
5. Afficher les résultats
6. A propos
7. Quitter
> """)
            try:
                choice = int(choice)
            except Exception:
                continue
            if choice >= 1 and choice <= 5:
                self.audit(choice)
            elif choice == 6:
                about()
            elif choice == 7:
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
