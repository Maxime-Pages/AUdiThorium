#!/usr/bin/env python3
"""
Module principal d'audit de sécurité
Menu interactif pour orchestrer les audits système et Apache
"""

import os
import sys
import logging
from datetime import datetime
from audit_analyse import AnalyseurAudit
import json

# Import des modules d'audit
try:
    from audit_systeme import AuditSysteme
    from audit_apache import AuditApache
except ImportError as e:
    print(f"Erreur d'importation des modules: {e}")
    print("Assurez-vous que les fichiers audit_systeme.py et audit_apache.py sont présents")
    sys.exit(1)

class AuditPrincipal:
    def __init__(self):
        self.logger = self.configurer_logging()
        self.resultats_globaux = {}
        
    def configurer_logging(self):
        """Configure le système de logging"""
        # Configuration du logger principal
        logger = logging.getLogger('audit_principal')
        logger.setLevel(logging.INFO)
        
        # Création du handler pour le fichier de log
        log_handler = logging.FileHandler('audit.log', mode='a', encoding='utf-8')
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
    
    def afficher_banniere(self):
        """Affiche la bannière du programme"""
        banniere = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                           AUDIT DE SÉCURITÉ                                  ║
║                    Système Linux et Serveur Apache                           ║
║                                                                               ║
║                         Développé pour le module                             ║
║                            Scripting 2024-2025                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banniere)
        print(f"Heure de début: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 79)
    
    def afficher_menu(self):
        """Affiche le menu principal"""
        menu = """
┌─────────────────────────────────────────────────────────────────────────────┐
│                              MENU PRINCIPAL                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Lancer un audit système Linux uniquement                                │
│  2. Lancer un audit Apache uniquement                                       │
│  3. Lancer les deux audits (système + Apache)                               │       
│  4. Analyser les résultats des derniers audits                              │
│  5. Afficher les résultats des derniers audits                              │
│  6. Aide et informations                                                    │
│  7. Quitter                                                                 │
└─────────────────────────────────────────────────────────────────────────────┘
        """
        print(menu)
    
    def valider_choix(self, choix):
        """Valide le choix de l'utilisateur"""
        try:
            choix_int = int(choix)
            return 1 <= choix_int <= 6
        except ValueError:
            return False
    
    def executer_audit_systeme(self):
        """Exécute l'audit système"""
        print("\n" + "="*60)
        print("DÉMARRAGE DE L'AUDIT SYSTÈME LINUX")
        print("="*60)
        
        self.logger.info("Démarrage de l'audit système Linux")
        
        try:
            audit_sys = AuditSysteme()
            
            print("⏳ Collecte des informations système en cours...")
            succes = audit_sys.executer_audit_complet()
            
            if succes:
                print("✅ Audit système terminé avec succès")
                
                # Sauvegarde des résultats
                fichier_json = audit_sys.sauvegarder_resultats("json")
                fichier_txt = audit_sys.sauvegarder_resultats("txt")
                
                print(f"📁 Résultats sauvegardés dans:")
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
                print("❌ Erreur lors de l'audit système")
                self.logger.error("Erreur lors de l'audit système")
                return False
                
        except Exception as e:
            print(f"❌ Erreur critique lors de l'audit système: {e}")
            self.logger.error(f"Erreur critique lors de l'audit système: {e}")
            return False
    
    def executer_audit_apache(self):
        """Exécute l'audit Apache"""
        print("\n" + "="*60)
        print("DÉMARRAGE DE L'AUDIT APACHE")
        print("="*60)
        
        self.logger.info("Démarrage de l'audit Apache")
        
        try:
            audit_apache = AuditApache()
            
            print("⏳ Collecte des informations Apache en cours...")
            succes = audit_apache.executer_audit_complet()
            
            if succes:
                print("✅ Audit Apache terminé avec succès")
                
                # Sauvegarde des résultats
                fichier_json = audit_apache.sauvegarder_resultats("json")
                fichier_txt = audit_apache.sauvegarder_resultats("txt")
                
                print(f"📁 Résultats sauvegardés dans:")
                print(f"   - {fichier_json}")
                print(f"   - {fichier_txt}")
                
                # Stockage des résultats pour le résumé
                self.resultats_globaux["apache"] = {
                    "succes": True,
                    "fichier_json": fichier_json,
                    "fichier_txt": fichier_txt,
                    "timestamp": datetime.now().isoformat()
                }
                
                self.logger.info("Audit Apache terminé avec succès")
                return True
            else:
                print("❌ Erreur lors de l'audit Apache")
                self.logger.error("Erreur lors de l'audit Apache")
                return False
                
        except Exception as e:
            print(f"❌ Erreur critique lors de l'audit Apache: {e}")
            self.logger.error(f"Erreur critique lors de l'audit Apache: {e}")
            return False
    
    def executer_audits_complets(self):
        """Exécute les deux audits"""
        print("\n" + "="*60)
        print("DÉMARRAGE DES AUDITS COMPLETS")
        print("="*60)
        
        self.logger.info("Démarrage des audits complets (système + Apache)")
        
        succes_systeme = self.executer_audit_systeme()
        succes_apache = self.executer_audit_apache()
        
        print("\n" + "="*60)
        print("RÉSUMÉ DES AUDITS")
        print("="*60)
        
        if succes_systeme and succes_apache:
            print("✅ Tous les audits ont été exécutés avec succès")
            self.logger.info("Tous les audits terminés avec succès")
        elif succes_systeme:
            print("⚠️  Audit système: ✅ Succès")
            print("⚠️  Audit Apache: ❌ Échec")
            self.logger.warning("Audit système réussi, audit Apache échoué")
        elif succes_apache:
            print("⚠️  Audit système: ❌ Échec")
            print("⚠️  Audit Apache: ✅ Succès")
            self.logger.warning("Audit Apache réussi, audit système échoué")
        else:
            print("❌ Tous les audits ont échoué")
            self.logger.error("Tous les audits ont échoué")
        
        return succes_systeme or succes_apache
    
    def afficher_resultats(self):
        """Affiche les résultats des derniers audits"""
        print("\n" + "="*60)
        print("RÉSULTATS DES DERNIERS AUDITS")
        print("="*60)
        
        if not self.resultats_globaux:
            print("Aucun audit n'a été exécuté dans cette session.")
            return
        
        for type_audit, resultats in self.resultats_globaux.items():
            print(f"\n📊 AUDIT {type_audit.upper()}:")
            print(f"   Status: {'✅ Succès' if resultats['succes'] else '❌ Échec'}")
            print(f"   Timestamp: {resultats['timestamp']}")
            if resultats['succes']:
                print(f"   Fichiers générés:")
                print(f"     - {resultats['fichier_json']}")
                print(f"     - {resultats['fichier_txt']}")
        
        # Vérification des fichiers existants
        print("\n📁 FICHIERS D'AUDIT PRÉSENTS:")
        fichiers_audit = [
            "audit_systeme.json", "audit_systeme.txt",
            "audit_apache.json", "audit_apache.txt",
            "audit.log"
        ]
        
        for fichier in fichiers_audit:
            if os.path.exists(fichier):
                taille = os.path.getsize(fichier)
                print(f"   ✅ {fichier} ({taille} octets)")
            else:
                print(f"   ❌ {fichier} (non trouvé)")
    
    def executer_audit_analyse(self):
        """Exécute l'analyse des résultats d'audit"""
        print("\n" + "="*60)
        print("DÉMARRAGE DE L'ANALYSE DES RÉSULTATS D'AUDIT")
        print("="*60)
        
        self.logger.info("Démarrage de l'analyse des résultats d'audit")
        
        try:
            analyseur = AnalyseurAudit(self.resultats_globaux["systeme"]["fichier_json"],
                                      self.resultats_globaux["apache"]["fichier_json"])
            analyseur.analyser()
            print("✅ Analyse des résultats terminée avec succès")
            self.logger.info("Analyse des résultats terminée avec succès")
        except Exception as e:
            print(f"❌ Erreur lors de l'analyse des résultats: {e}")
            self.logger.error(f"Erreur lors de l'analyse des résultats: {e}")
    
    def afficher_aide(self):
        """Affiche l'aide et les informations"""
        aide = """
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AIDE ET INFORMATIONS                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ 🎯 OBJECTIF:                                                                │
│    Cet outil effectue un audit de sécurité automatisé pour détecter        │
│    les vulnérabilités et mauvaises pratiques sur un système Linux         │
│    et un serveur web Apache.                                               │
│                                                                             │
│ 📋 AUDIT SYSTÈME LINUX:                                                     │
│    • Informations système (OS, kernel, hardware)                           │
│    • Gestion des utilisateurs et permissions                               │
│    • Services et processus actifs                                          │
│    • Configuration réseau et firewall                                      │
│    • Fichiers sensibles et leurs permissions                               │
│    • Paramètres de sécurité (SSH, PAM, etc.)                              │
│    • État des mises à jour                                                 │
│                                                                             │
│ 🌐 AUDIT APACHE:                                                            │
│    • Détection et version d'Apache                                         │
│    • Configuration principale                                              │
│    • Virtual Hosts                                                         │
│    • Modules de sécurité                                                   │
│    • Configuration des logs                                                │
│    • Permissions des fichiers                                              │
│    • Paramètres de sécurité avancés                                        │
│                                                                             │
│ 📁 FICHIERS GÉNÉRÉS:                                                        │
│    • audit_systeme.json/txt : Résultats de l'audit système                 │
│    • audit_apache.json/txt : Résultats de l'audit Apache                   │
│    • audit.log : Journal d'exécution                                       │
│                                                                             │
│ 🔧 UTILISATION:                                                             │
│    1. Exécutez ce script avec les privilèges administrateur                │
│    2. Choisissez le type d'audit à effectuer                               │
│    3. Analysez les fichiers générés                                        │
│    4. Implémentez les corrections nécessaires                              │
│                                                                             │
│ ⚠️  PRÉREQUIS:                                                              │
│    • Privilèges sudo/root pour certaines commandes                         │
│    • Système Linux (Ubuntu/Debian recommandé)                             │
│    • Apache installé (pour l'audit Apache)                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
        """
        print(aide)
    
    def nettoyer_session(self):
        """Nettoie les données de la session"""
        self.resultats_globaux.clear()
        print("🧹 Session nettoyée")
    
    def quitter(self):
        """Quitte l'application"""
        print("\n" + "="*60)
        print("ARRÊT DU PROGRAMME")
        print("="*60)
        
        self.logger.info("Arrêt du programme d'audit")
        
        if self.resultats_globaux:
            print("📊 Résumé de cette session:")
            for type_audit, resultats in self.resultats_globaux.items():
                status = "✅ Succès" if resultats['succes'] else "❌ Échec"
                print(f"   {type_audit.capitalize()}: {status}")
        
        print(f"\n🕐 Fin de session: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("📋 Consultez le fichier audit.log pour les détails d'exécution")
        print("\nMerci d'avoir utilisé l'outil d'audit de sécurité!")
        print("="*60)
    
    def executer(self):
        """Boucle principale du programme"""
        self.afficher_banniere()
        self.logger.info("Démarrage du programme d'audit principal")
        
        while True:
            try:
                self.afficher_menu()
                
                choix = input("\n🎯 Entrez votre choix (1-7): ").strip()
                
                if not self.valider_choix(choix):
                    print("❌ Choix invalide. Veuillez entrer un nombre entre 1 et 6.")
                    continue
                
                choix_int = int(choix)
                
                if choix_int == 1:
                    self.executer_audit_systeme()
                
                elif choix_int == 2:
                    self.executer_audit_apache()
                
                elif choix_int == 3:
                    self.executer_audits_complets()
                
                elif choix_int == 4:
                    self.executer_audit_analyse()
                
                elif choix_int == 5:
                    self.afficher_resultats()
                
                elif choix_int == 6:
                    self.afficher_aide()
                
                elif choix_int == 7:
                    self.quitter()
                    break
                
                # Pause avant de réafficher le menu
                if choix_int in [1, 2, 3]:
                    input("\n⏸️  Appuyez sur Entrée pour continuer...")
                
            except KeyboardInterrupt:
                print("\n\n⚠️  Interruption détectée (Ctrl+C)")
                confirmation = input("Voulez-vous vraiment quitter? (o/N): ").strip().lower()
                if confirmation in ['o', 'oui', 'y', 'yes']:
                    self.quitter()
                    break
                else:
                    print("↩️  Retour au menu principal")
                    continue
            
            except Exception as e:
                print(f"❌ Erreur inattendue: {e}")
                self.logger.error(f"Erreur inattendue dans le menu principal: {e}")
                continue

def main():
    """Fonction principale"""
    # Vérification des permissions
    if os.geteuid() != 0:
        print("⚠️  ATTENTION: Ce script nécessite des privilèges administrateur")
        print("   Certaines informations peuvent être incomplètes sans sudo/root")
        print("   Recommandation: sudo python3 audit_principal.py")
        print()
        
        continuer = input("Voulez-vous continuer malgré tout? (o/N): ").strip().lower()
        if continuer not in ['o', 'oui', 'y', 'yes']:
            print("Arrêt du programme.")
            sys.exit(1)
    
    # Lancement du programme principal
    try:
        audit_principal = AuditPrincipal()
        audit_principal.executer()
    except Exception as e:
        print(f"❌ Erreur fatale: {e}")
        logging.error(f"Erreur fatale dans le programme principal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()