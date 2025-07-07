#!/usr/bin/env python3
"""
Module d'analyse des résultats d'audit de sécurité
Évalue les risques et fournit des recommandations de sécurité
"""

import json
import os
import re
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Any

class AnalyseurAudit:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.resultats_analyse = {}
        self.score_securite = 0
        self.score_max = 100
        self.vulnerabilites = []
        
        # Définition des critères de sécurité et leurs poids
        self.criteres_securite = {
            'systeme': {
                'utilisateurs_risque': 15,
                'services_dangereux': 10,
                'permissions_faibles': 15,
                'configuration_ssh': 10,
                'firewall': 10,
                'mises_a_jour': 15,
                'fichiers_sensibles': 10,
                'authentification': 15
            },
            'apache': {
                'version_obsolete': 15,
                'modules_dangereux': 15,
                'configuration_securite': 20,
                'permissions_fichiers': 15,
                'headers_securite': 10,
                'ssl_tls': 15,
                'logs_securite': 10
            }
        }
    
    def charger_resultats_audit(self, fichier_systeme=None, fichier_apache=None):
        """Charge les résultats d'audit depuis les fichiers JSON"""
        resultats = {}
        
        if fichier_systeme:
            try:
                with open(fichier_systeme, 'r', encoding='utf-8') as f:
                    resultats['systeme'] = json.load(f)
                self.logger.info(f"Résultats système chargés depuis {fichier_systeme}")
            except Exception as e:
                self.logger.error(f"Erreur lors du chargement de {fichier_systeme}: {e}")
                resultats['systeme'] = {}
        
        if fichier_apache:
            try:
                with open(fichier_apache, 'r', encoding='utf-8') as f:
                    resultats['apache'] = json.load(f)
                self.logger.info(f"Résultats Apache chargés depuis {fichier_apache}")
            except Exception as e:
                self.logger.error(f"Erreur lors du chargement de {fichier_apache}: {e}")
                resultats['apache'] = {}
        
        return resultats
    
    def analyser_utilisateurs_systeme(self, donnees_systeme):
        """Analyse les risques liés aux utilisateurs"""
        vulnerabilites = []
        score = 0
        
        if 'utilisateurs' not in donnees_systeme:
            return vulnerabilites, 0
        
        utilisateurs = donnees_systeme['utilisateurs']
        
        # Vérification des utilisateurs avec UID 0
        if 'uid_0_users' in utilisateurs:
            uid_0_users = [user for user in utilisateurs['uid_0_users'] if user.strip()]
            if len(uid_0_users) > 1:
                vulnerabilites.append({
                    'type': 'CRITIQUE',
                    'categorie': 'Utilisateurs',
                    'titre': 'Plusieurs comptes avec UID 0',
                    'description': f'Comptes détectés avec UID 0: {", ".join(uid_0_users)}',
                    'risque': 'Élévation de privilèges non autorisée',
                    'recommandation': 'Seul le compte root devrait avoir UID 0'
                })
                score -= 5
        
        # Vérification des comptes sans mot de passe
        if 'no_password_users' in utilisateurs:
            no_pass_users = [user for user in utilisateurs['no_password_users'] if user.strip()]
            if no_pass_users:
                vulnerabilites.append({
                    'type': 'CRITIQUE',
                    'categorie': 'Utilisateurs',
                    'titre': 'Comptes sans mot de passe',
                    'description': f'Comptes sans mot de passe: {", ".join(no_pass_users)}',
                    'risque': 'Accès non autorisé au système',
                    'recommandation': 'Définir des mots de passe forts ou désactiver ces comptes'
                })
                score -= 10
        
        # Analyse des utilisateurs sudoers
        if 'sudo_users' in utilisateurs:
            sudo_info = utilisateurs['sudo_users']
            if sudo_info:
                # Extraire les utilisateurs du groupe sudo
                sudo_users = re.findall(r':([^:]+)$', sudo_info)
                if sudo_users:
                    users_list = sudo_users[0].split(',')
                    if len(users_list) > 3:
                        vulnerabilites.append({
                            'type': 'MOYEN',
                            'categorie': 'Utilisateurs',
                            'titre': 'Trop d\'utilisateurs avec privilèges sudo',
                            'description': f'Utilisateurs avec sudo: {", ".join(users_list)}',
                            'risque': 'Surface d\'attaque élargie',
                            'recommandation': 'Limiter les privilèges sudo aux utilisateurs nécessaires'
                        })
                        score -= 3
        
        return vulnerabilites, max(0, score)
    
    def analyser_services_systeme(self, donnees_systeme):
        """Analyse les risques liés aux services"""
        vulnerabilites = []
        score = 0
        
        if 'services' not in donnees_systeme:
            return vulnerabilites, 0
        
        services = donnees_systeme['services']
        
        # Services potentiellement dangereux
        services_dangereux = [
            'telnet', 'ftp', 'rsh', 'rlogin', 'rexec', 'finger',
            'tftp', 'snmp', 'nis', 'rpc', 'portmap'
        ]
        
        if 'services_actifs' in services:
            services_actifs = services['services_actifs'].lower()
            for service in services_dangereux:
                if service in services_actifs:
                    vulnerabilites.append({
                        'type': 'ÉLEVÉ',
                        'categorie': 'Services',
                        'titre': f'Service dangereux actif: {service}',
                        'description': f'Le service {service} est actif',
                        'risque': 'Communication non chiffrée ou vulnérabilités connues',
                        'recommandation': f'Désactiver {service} et utiliser des alternatives sécurisées'
                    })
                    score -= 3
        
        # Analyse des ports ouverts
        if 'ports_ouverts' in services:
            ports_ouverts = services['ports_ouverts']
            # Ports potentiellement dangereux
            ports_dangereux = {
                '21': 'FTP',
                '23': 'Telnet',
                '25': 'SMTP',
                '53': 'DNS',
                '69': 'TFTP',
                '135': 'RPC',
                '139': 'NetBIOS',
                '445': 'SMB',
                '512': 'rexec',
                '513': 'rlogin',
                '514': 'rsh'
            }
            
            for port, service in ports_dangereux.items():
                if f':{port} ' in ports_ouverts:
                    vulnerabilites.append({
                        'type': 'MOYEN',
                        'categorie': 'Services',
                        'titre': f'Port dangereux ouvert: {port} ({service})',
                        'description': f'Le port {port} ({service}) est ouvert',
                        'risque': 'Point d\'entrée potentiel pour les attaquants',
                        'recommandation': f'Fermer le port {port} si non nécessaire'
                    })
                    score -= 2
        
        return vulnerabilites, max(0, score)
    
    def analyser_configuration_ssh(self, donnees_systeme):
        """Analyse la configuration SSH"""
        vulnerabilites = []
        score = 0
        
        if 'securite' not in donnees_systeme or 'ssh_config' not in donnees_systeme['securite']:
            return vulnerabilites, 0
        
        ssh_config = donnees_systeme['securite']['ssh_config']
        
        # Vérification PermitRootLogin
        if 'PermitRootLogin yes' in ssh_config:
            vulnerabilites.append({
                'type': 'CRITIQUE',
                'categorie': 'SSH',
                'titre': 'Connexion root SSH autorisée',
                'description': 'PermitRootLogin est configuré sur "yes"',
                'risque': 'Attaque par force brute sur le compte root',
                'recommandation': 'Configurer PermitRootLogin sur "no" ou "prohibit-password"'
            })
            score -= 8
        
        # Vérification PasswordAuthentication
        if 'PasswordAuthentication yes' in ssh_config:
            vulnerabilites.append({
                'type': 'ÉLEVÉ',
                'categorie': 'SSH',
                'titre': 'Authentification par mot de passe activée',
                'description': 'PasswordAuthentication est configuré sur "yes"',
                'risque': 'Attaque par force brute sur les mots de passe',
                'recommandation': 'Utiliser uniquement l\'authentification par clés (PubkeyAuthentication)'
            })
            score -= 5
        
        # Vérification du port par défaut
        if 'Port 22' in ssh_config or 'Port' not in ssh_config:
            vulnerabilites.append({
                'type': 'FAIBLE',
                'categorie': 'SSH',
                'titre': 'Port SSH par défaut',
                'description': 'SSH utilise le port 22 par défaut',
                'risque': 'Cible facile pour les scans automatisés',
                'recommandation': 'Changer le port SSH par défaut'
            })
            score -= 2
        
        return vulnerabilites, max(0, score)
    
    def analyser_firewall(self, donnees_systeme):
        """Analyse la configuration du firewall"""
        vulnerabilites = []
        score = 0
        
        if 'reseau' not in donnees_systeme:
            return vulnerabilites, 0
        
        reseau = donnees_systeme['reseau']
        
        # Vérification UFW
        if 'firewall_ufw' in reseau:
            ufw_status = reseau['firewall_ufw']
            if 'Status: inactive' in ufw_status:
                vulnerabilites.append({
                    'type': 'ÉLEVÉ',
                    'categorie': 'Firewall',
                    'titre': 'UFW désactivé',
                    'description': 'Le firewall UFW est inactif',
                    'risque': 'Aucune protection réseau au niveau système',
                    'recommandation': 'Activer et configurer UFW'
                })
                score -= 8
        
        # Vérification iptables
        if 'firewall_iptables' in reseau:
            iptables = reseau['firewall_iptables']
            if 'ACCEPT' in iptables and 'DROP' not in iptables:
                vulnerabilites.append({
                    'type': 'MOYEN',
                    'categorie': 'Firewall',
                    'titre': 'Configuration iptables permissive',
                    'description': 'Iptables semble avoir une politique permissive',
                    'risque': 'Filtrage réseau insuffisant',
                    'recommandation': 'Configurer des règles iptables restrictives'
                })
                score -= 3
        
        return vulnerabilites, max(0, score)
    
    def analyser_fichiers_sensibles(self, donnees_systeme):
        """Analyse les permissions des fichiers sensibles"""
        vulnerabilites = []
        score = 0
        
        if 'fichiers_sensibles' not in donnees_systeme:
            return vulnerabilites, 0
        
        fichiers = donnees_systeme['fichiers_sensibles']
        
        # Vérification des permissions critiques
        if 'permissions_critiques' in fichiers:
            permissions = fichiers['permissions_critiques']
            
            # Règles de sécurité pour les fichiers
            regles_fichiers = {
                '/etc/passwd': {'max_perm': '644', 'owner': 'root'},
                '/etc/shadow': {'max_perm': '640', 'owner': 'root'},
                '/etc/group': {'max_perm': '644', 'owner': 'root'},
                '/etc/gshadow': {'max_perm': '640', 'owner': 'root'},
                '/etc/ssh/sshd_config': {'max_perm': '600', 'owner': 'root'},
                '/etc/sudoers': {'max_perm': '440', 'owner': 'root'}
            }
            
            for fichier, regle in regles_fichiers.items():
                if fichier in permissions and 'permissions' in permissions[fichier]:
                    perm_actuelle = permissions[fichier]['permissions']
                    perm_max = regle['max_perm']
                    
                    if int(perm_actuelle) > int(perm_max):
                        vulnerabilites.append({
                            'type': 'ÉLEVÉ',
                            'categorie': 'Permissions',
                            'titre': f'Permissions trop permissives: {fichier}',
                            'description': f'Permissions actuelles: {perm_actuelle}, recommandées: {perm_max}',
                            'risque': 'Accès non autorisé aux fichiers critiques',
                            'recommandation': f'chmod {perm_max} {fichier}'
                        })
                        score -= 4
        
        # Vérification des fichiers SUID/SGID
        if 'suid_sgid' in fichiers:
            suid_files = fichiers['suid_sgid']
            if suid_files:
                # Fichiers SUID potentiellement dangereux
                fichiers_suid_dangereux = [
                    'nmap', 'vim', 'less', 'more', 'nano', 'cp', 'mv',
                    'find', 'awk', 'sed', 'python', 'perl', 'ruby'
                ]
                
                for fichier_dangereux in fichiers_suid_dangereux:
                    if fichier_dangereux in suid_files:
                        vulnerabilites.append({
                            'type': 'CRITIQUE',
                            'categorie': 'Permissions',
                            'titre': f'Fichier SUID dangereux: {fichier_dangereux}',
                            'description': f'Le fichier {fichier_dangereux} a des permissions SUID',
                            'risque': 'Élévation de privilèges possible',
                            'recommandation': f'Retirer les permissions SUID de {fichier_dangereux}'
                        })
                        score -= 6
        
        return vulnerabilites, max(0, score)
    
    def analyser_apache_version(self, donnees_apache):
        """Analyse la version d'Apache"""
        vulnerabilites = []
        score = 0
        
        if 'detection' not in donnees_apache or 'version' not in donnees_apache['detection']:
            return vulnerabilites, 0
        
        version_info = donnees_apache['detection']['version']
        
        # Extraction de la version
        version_match = re.search(r'Apache/(\d+\.\d+\.\d+)', version_info)
        if version_match:
            version = version_match.group(1)
            version_parts = [int(x) for x in version.split('.')]
            
            # Versions obsolètes (exemple: Apache < 2.4.41)
            if version_parts < [2, 4, 41]:
                vulnerabilites.append({
                    'type': 'CRITIQUE',
                    'categorie': 'Apache Version',
                    'titre': 'Version Apache obsolète',
                    'description': f'Version détectée: {version}',
                    'risque': 'Vulnérabilités de sécurité connues',
                    'recommandation': 'Mettre à jour Apache vers la dernière version stable'
                })
                score -= 10
        
        return vulnerabilites, max(0, score)
    
    def analyser_configuration_apache(self, donnees_apache):
        """Analyse la configuration de sécurité d'Apache"""
        vulnerabilites = []
        score = 0
        
        if 'configuration_principale' not in donnees_apache:
            return vulnerabilites, 0
        
        config = donnees_apache['configuration_principale']
        
        # Vérification ServerTokens
        if 'server_tokens' in config:
            server_tokens = config['server_tokens']
            if 'ServerTokens Full' in server_tokens or 'ServerTokens' not in server_tokens:
                vulnerabilites.append({
                    'type': 'MOYEN',
                    'categorie': 'Apache Configuration',
                    'titre': 'ServerTokens non configuré',
                    'description': 'ServerTokens révèle des informations sur le serveur',
                    'risque': 'Fuite d\'informations sensibles',
                    'recommandation': 'Configurer ServerTokens Prod'
                })
                score -= 3
        
        # Vérification ServerSignature
        if 'server_signature' in config:
            server_signature = config['server_signature']
            if 'ServerSignature On' in server_signature:
                vulnerabilites.append({
                    'type': 'FAIBLE',
                    'categorie': 'Apache Configuration',
                    'titre': 'ServerSignature activée',
                    'description': 'ServerSignature révèle des informations sur le serveur',
                    'risque': 'Fuite d\'informations',
                    'recommandation': 'Configurer ServerSignature Off'
                })
                score -= 2
        
        return vulnerabilites, max(0, score)
    
    def analyser_modules_apache(self, donnees_apache):
        """Analyse les modules Apache"""
        vulnerabilites = []
        score = 0
        
        if 'modules_securite' not in donnees_apache:
            return vulnerabilites, 0
        
        modules = donnees_apache['modules_securite']
        
        # Modules dangereux
        if 'modules_dangereux' in modules:
            modules_dangereux = modules['modules_dangereux']
            for module, status in modules_dangereux.items():
                if status == 'Activé':
                    vulnerabilites.append({
                        'type': 'ÉLEVÉ',
                        'categorie': 'Apache Modules',
                        'titre': f'Module dangereux activé: {module}',
                        'description': f'Le module {module} est activé',
                        'risque': 'Fuite d\'informations ou vulnérabilités',
                        'recommandation': f'Désactiver le module {module} si non nécessaire'
                    })
                    score -= 4
        
        # Modules de sécurité manquants
        if 'security_modules_status' in modules:
            security_modules = modules['security_modules_status']
            modules_importants = ['ssl', 'headers', 'security2']
            
            for module in modules_importants:
                if module in security_modules and security_modules[module] == 'Désactivé':
                    vulnerabilites.append({
                        'type': 'MOYEN',
                        'categorie': 'Apache Modules',
                        'titre': f'Module de sécurité désactivé: {module}',
                        'description': f'Le module {module} n\'est pas activé',
                        'risque': 'Fonctionnalités de sécurité manquantes',
                        'recommandation': f'Activer et configurer le module {module}'
                    })
                    score -= 3
        
        return vulnerabilites, max(0, score)
    
    def analyser_complet(self, fichier_systeme=None, fichier_apache=None):
        """Effectue une analyse complète des résultats d'audit"""
        self.logger.info("Début de l'analyse de sécurité")
        
        # Chargement des résultats
        resultats = self.charger_resultats_audit(fichier_systeme, fichier_apache)
        
        # Initialisation du score
        score_total = 0
        
        # Analyse du système
        if 'systeme' in resultats:
            donnees_systeme = resultats['systeme']
            
            # Analyse des différents aspects
            analyses = [
                self.analyser_utilisateurs_systeme(donnees_systeme),
                self.analyser_services_systeme(donnees_systeme),
                self.analyser_configuration_ssh(donnees_systeme),
                self.analyser_firewall(donnees_systeme),
                self.analyser_fichiers_sensibles(donnees_systeme)
            ]
            
            for vulnerabilites, score in analyses:
                self.vulnerabilites.extend(vulnerabilites)
                score_total += score
        
        # Analyse d'Apache
        if 'apache' in resultats:
            donnees_apache = resultats['apache']
            
            # Analyse des différents aspects Apache
            analyses_apache = [
                self.analyser_apache_version(donnees_apache),
                self.analyser_configuration_apache(donnees_apache),
                self.analyser_modules_apache(donnees_apache)
            ]
            
            for vulnerabilites, score in analyses_apache:
                self.vulnerabilites.extend(vulnerabilites)
                score_total += score
        
        # Calcul du score final
        self.score_securite = max(0, min(100, 100 + score_total))
        
        # Génération du rapport
        self.generer_rapport()
        
        self.logger.info("Analyse de sécurité terminée")
        return self.resultats_analyse
    
    def generer_rapport(self):
        """Génère le rapport d'analyse"""
        # Classification des vulnérabilités
        critiques = [v for v in self.vulnerabilites if v['type'] == 'CRITIQUE']
        elevees = [v for v in self.vulnerabilites if v['type'] == 'ÉLEVÉ']
        moyennes = [v for v in self.vulnerabilites if v['type'] == 'MOYEN']
        faibles = [v for v in self.vulnerabilites if v['type'] == 'FAIBLE']
        
        # Évaluation du niveau de sécurité
        if self.score_securite >= 90:
            niveau = "EXCELLENT"
            couleur = "🟢"
        elif self.score_securite >= 75:
            niveau = "BON"
            couleur = "🟡"
        elif self.score_securite >= 50:
            niveau = "MOYEN"
            couleur = "🟠"
        else:
            niveau = "FAIBLE"
            couleur = "🔴"
        
        self.resultats_analyse = {
            'timestamp': datetime.now().isoformat(),
            'score_securite': self.score_securite,
            'niveau_securite': niveau,
            'couleur': couleur,
            'total_vulnerabilites': len(self.vulnerabilites),
            'repartition': {
                'critiques': len(critiques),
                'elevees': len(elevees),
                'moyennes': len(moyennes),
                'faibles': len(faibles)
            },
            'vulnerabilites': {
                'critiques': critiques,
                'elevees': elevees,
                'moyennes': moyennes,
                'faibles': faibles
            },
            'recommandations_prioritaires': self.generer_recommandations_prioritaires()
        }
    
    def generer_recommandations_prioritaires(self):
        """Génère les recommandations prioritaires"""
        recommandations = []
        
        # Recommandations basées sur les vulnérabilités critiques
        critiques = [v for v in self.vulnerabilites if v['type'] == 'CRITIQUE']
        
        if critiques:
            recommandations.append({
                'priorite': 'IMMÉDIATE',
                'titre': 'Corriger les vulnérabilités critiques',
                'description': f'{len(critiques)} vulnérabilités critiques détectées',
                'actions': [v['recommandation'] for v in critiques[:5]]
            })
        
        # Recommandations générales
        if self.score_securite < 50:
            recommandations.append({
                'priorite': 'ÉLEVÉE',
                'titre': 'Améliorer la sécurité globale',
                'description': 'Score de sécurité faible détecté',
                'actions': [
                    'Effectuer un audit de sécurité complet',
                    'Mettre à jour tous les composants',
                    'Revoir la configuration de sécurité',
                    'Implémenter un monitoring de sécurité'
                ]
            })
        
        return recommandations
    
    def sauvegarder_analyse(self, format_sortie="json"):
        """Sauvegarde l'analyse dans un fichier"""
        if format_sortie == "json":
            nom_fichier = f"analyse_securite_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(nom_fichier, 'w', encoding='utf-8') as f:
                json.dump(self.resultats_analyse, f, indent=2, ensure_ascii=False)
        else:
            nom_fichier = f"analyse_securite_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(nom_fichier, 'w', encoding='utf-8') as f:
                self.ecrire_rapport_texte(f)
        
        self.logger.info(f"Analyse sauvegardée dans {nom_fichier}")
        return nom_fichier
    
    def ecrire_rapport_texte(self, fichier):
        """Écrit le rapport d'analyse en format texte"""
        rapport = self.resultats_analyse
        
        fichier.write("╔════════════════════════════════════════════════════════════════════════════════╗\n")
        fichier.write("║                           RAPPORT D'ANALYSE DE SÉCURITÉ                       ║\n")
        fichier.write("╚════════════════════════════════════════════════════════════════════════════════╝\n\n")
        
        fichier.write(f"📅 Date d'analyse: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        fichier.write(f"🔒 Score de sécurité: {rapport['score_securite']}/100\n")
        fichier.write(f"📊 Niveau de sécurité: {rapport['couleur']} {rapport['niveau_securite']}\n")
        fichier.write(f"⚠️  Total des vulnérabilités: {rapport['total_vulnerabilites']}\n\n")
        
        fichier.write("═══════════════════════════════════════════════════════════════════════════════\n")
        fichier.write("                            RÉPARTITION DES VULNÉRABILITÉS\n")
        fichier.write("═══════════════════════════════════════════════════════════════════════════════\n\n")
        
        fichier.write(f"🔴 CRITIQUES: {rapport['repartition']['critiques']}\n")
        fichier.write(f"🟠 ÉLEVÉES: {rapport['repartition']['elevees']}\n")
        fichier.write(f"🟡 MOYENNES: {rapport['repartition']['moyennes']}\n")
        fichier.write(f"🟢 FAIBLES: {rapport['repartition']['faibles']}\n\n")
        
        # Détail des vulnérabilités
        for type_vuln, vulnerabilites in rapport['vulnerabilites'].items():
            if vulnerabilites:
                fichier.write(f"\n{'='*80}\n")
                fichier.write(f"                        VULNÉRABILITÉS {type_vuln.upper()}\n")
                fichier.write(f"{'='*80}\n\n")
                
                for i, vuln in enumerate(vulnerabilites, 1):
                    fichier.write(f"[{i}] {vuln['titre']}\n")
                    fichier.write(f"    Catégorie: {vuln['categorie']}\n")
                    fichier.write(f"    Description: {vuln['description']}\n")
                    fichier.write(f"    Risque: {vuln['risque']}\n")
                    fichier.write(f"    Recommandation: {vuln['recommandation']}\n\n")
        
        # Recommandations prioritaires
        if rapport['recommandations_prioritaires']:
            fichier.write("\n" + "="*80 + "\n")
            fichier.write("                        RECOMMANDATIONS PRIORITAIRES\n")
            fichier.write("="*80 + "\n\n")
            
            for recommandation in rapport['recommandations_prioritaires']:
                fichier.write(f"🎯 {recommandation['titre']} (Priorité: {recommandation['priorite']})\n")
                fichier.write(f"   {recommandation['description']}\n\n")
                fichier.write("   Actions à effectuer:\n")
                for action in recommandation['actions']:
                    fichier.write(f"   • {action}\n")
                fichier.write("\n")
    
    def afficher_resume(self):
        """Affiche un résumé de l'analyse"""
        if not self.resultats_analyse:
            print("Aucune analyse n'a été effectuée.")
            return
        
        print("Résumé de l'analyse de sécurité :")
        print(f"📅 Date : {self.resultats_analyse['timestamp']}")
        print(f"🔒 Score de sécurité : {self.resultats_analyse['score_securite']}/100")
        print(f"📊 Niveau : {self.resultats_analyse['couleur']} {self.resultats_analyse['niveau_securite']}")
        print(f"⚠️  Vulnérabilités détectées : {self.resultats_analyse['total_vulnerabilites']}")
        print("Répartition :")
        for niveau, total in self.resultats_analyse['repartition'].items():
            icone = {
                'critiques': '🔴',
                'elevees': '🟠',
                'moyennes': '🟡',
                'faibles': '🟢'
            }.get(niveau, '•')
            print(f"  {icone} {niveau.capitalize()} : {total}")