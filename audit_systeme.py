#!/usr/bin/env python3
"""
Module d'audit système Linux
Collecte les informations critiques de configuration pour l'audit de sécurité
"""

import subprocess
import os
import json
import pwd
import grp
import stat
from datetime import datetime
import logging

class AuditSysteme:
    def __init__(self, b, logger=None):
        self.resultats = {}
        self.begin = b
        self.logger = logger if logger else logging.getLogger(name)
        
    def executer_commande(self, commande):
        """Exécute une commande système et retourne le résultat"""
        try:
            resultat = subprocess.run(commande, shell=True, capture_output=True, text=True, timeout=30)
            return resultat.stdout.strip(), resultat.stderr.strip(), resultat.returncode
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout lors de l'exécution de: {commande}")
            return "", "Timeout", 1
        except Exception as e:
            self.logger.error(f"Erreur lors de l'exécution de {commande}: {e}")
            return "", str(e), 1
    
    def audit_informations_systeme(self):
        """Collecte les informations générales du système"""
        info_systeme = {}
        
        # Version du système
        stdout, stderr, code = self.executer_commande("cat /etc/os-release")
        info_systeme["os_release"] = stdout
        
        # Version du noyau
        stdout, stderr, code = self.executer_commande("uname -a")
        info_systeme["kernel"] = stdout
        
        # Uptime
        stdout, stderr, code = self.executer_commande("uptime")
        info_systeme["uptime"] = stdout
        
        # Informations CPU
        stdout, stderr, code = self.executer_commande("cat /proc/cpuinfo | grep 'model name' | head -1")
        info_systeme["cpu"] = stdout
        
        # Mémoire
        stdout, stderr, code = self.executer_commande("free -h")
        info_systeme["memory"] = stdout
        
        # Espace disque
        stdout, stderr, code = self.executer_commande("df -h")
        info_systeme["disk_space"] = stdout
        
        self.resultats["informations_systeme"] = info_systeme
        self.logger.info("Audit des informations système terminé")
    
    def audit_utilisateurs(self):
        """Audit des comptes utilisateurs"""
        utilisateurs = {}
        
        # Utilisateurs avec shell
        stdout, stderr, code = self.executer_commande("cat /etc/passwd | grep -E '/bin/(bash|sh|zsh|fish)'")
        utilisateurs["users_with_shell"] = stdout.split('\n') if stdout else []
        
        # Utilisateurs avec UID 0 (root)
        stdout, stderr, code = self.executer_commande("awk -F: '$3 == 0 {print $1}' /etc/passwd")
        utilisateurs["uid_0_users"] = stdout.split('\n') if stdout else []
        
        # Comptes sans mot de passe
        stdout, stderr, code = self.executer_commande("awk -F: '$2 == \"\" {print $1}' /etc/shadow")
        utilisateurs["no_password_users"] = stdout.split('\n') if stdout else []
        
        # Dernières connexions
        stdout, stderr, code = self.executer_commande("last -10")
        utilisateurs["recent_logins"] = stdout
        
        # Utilisateurs sudoers
        stdout, stderr, code = self.executer_commande("getent group sudo")
        utilisateurs["sudo_users"] = stdout
        
        self.resultats["utilisateurs"] = utilisateurs
        self.logger.info("Audit des utilisateurs terminé")
    
    def audit_services(self):
        """Audit des services système"""
        services = {}
        
        # Services actifs
        stdout, stderr, code = self.executer_commande("systemctl list-units --type=service --state=running")
        services["services_actifs"] = stdout
        
        # Services activés au démarrage
        stdout, stderr, code = self.executer_commande("systemctl list-unit-files --type=service --state=enabled")
        services["services_enabled"] = stdout
        
        # Ports ouverts
        stdout, stderr, code = self.executer_commande("ss -tuln")
        services["ports_ouverts"] = stdout
        
        # Processus en cours
        stdout, stderr, code = self.executer_commande("ps aux --sort=-%cpu | head -20")
        services["processus_top"] = stdout
        
        self.resultats["services"] = services
        self.logger.info("Audit des services terminé")
    
    def audit_reseau(self):
        """Audit de la configuration réseau"""
        reseau = {}
        
        # Interfaces réseau
        stdout, stderr, code = self.executer_commande("ip addr show")
        reseau["interfaces"] = stdout
        
        # Table de routage
        stdout, stderr, code = self.executer_commande("ip route show")
        reseau["routes"] = stdout
        
        # Connexions réseau
        stdout, stderr, code = self.executer_commande("ss -tuln")
        reseau["connexions"] = stdout
        
        # Firewall (ufw)
        stdout, stderr, code = self.executer_commande("ufw status verbose")
        reseau["firewall_ufw"] = stdout
        
        # Firewall (iptables)
        stdout, stderr, code = self.executer_commande("iptables -L -n")
        reseau["firewall_iptables"] = stdout
        
        self.resultats["reseau"] = reseau
        self.logger.info("Audit réseau terminé")
    
    def audit_fichiers_sensibles(self):
        """Audit des fichiers et permissions sensibles"""
        fichiers = {}
        
        # Permissions des fichiers critiques
        fichiers_critiques = [
            "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
            "/etc/ssh/sshd_config", "/etc/sudoers", "/etc/fstab",
            "/etc/hosts", "/etc/resolv.conf"
        ]
        
        permissions = {}
        for fichier in fichiers_critiques:
            try:
                stat_info = os.stat(fichier)
                permissions[fichier] = {
                    "permissions": oct(stat_info.st_mode)[-3:],
                    "owner": pwd.getpwuid(stat_info.st_uid).pw_name,
                    "group": grp.getgrgid(stat_info.st_gid).gr_name
                }
            except Exception as e:
                permissions[fichier] = {"error": str(e)}
        
        fichiers["permissions_critiques"] = permissions
        
        # Fichiers SUID/SGID
        stdout, stderr, code = self.executer_commande("find /usr -type f \\( -perm -4000 -o -perm -2000 \\) -exec ls -la {} \\; 2>/dev/null")
        fichiers["suid_sgid"] = stdout
        
        # Fichiers world-writable
        stdout, stderr, code = self.executer_commande("find /tmp /var/tmp -type f -perm -002 -exec ls -la {} \\; 2>/dev/null")
        fichiers["world_writable"] = stdout
        
        self.resultats["fichiers_sensibles"] = fichiers
        self.logger.info("Audit des fichiers sensibles terminé")
    
    def audit_securite(self):
        """Audit des paramètres de sécurité"""
        securite = {}
        
        # Configuration SSH
        stdout, stderr, code = self.executer_commande("grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Port)' /etc/ssh/sshd_config")
        securite["ssh_config"] = stdout
        
        # Politique de mots de passe
        stdout, stderr, code = self.executer_commande("grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)' /etc/login.defs")
        securite["password_policy"] = stdout
        
        # Modules PAM
        stdout, stderr, code = self.executer_commande("ls -la /etc/pam.d/")
        securite["pam_modules"] = stdout
        
        # Logs d'authentification
        stdout, stderr, code = self.executer_commande("grep -i 'failed\\|invalid\\|authentication failure' /var/log/auth.log | tail -20")
        securite["auth_failures"] = stdout
        
        # AppArmor/SELinux
        stdout, stderr, code = self.executer_commande("aa-status")
        securite["apparmor"] = stdout
        
        stdout, stderr, code = self.executer_commande("sestatus")
        securite["selinux"] = stdout
        
        self.resultats["securite"] = securite
        self.logger.info("Audit de sécurité terminé")
    
    def audit_mises_a_jour(self):
        """Audit des mises à jour système"""
        maj = {}
        
        # Packages installés
        stdout, stderr, code = self.executer_commande("dpkg -l | wc -l")
        maj["packages_installed"] = stdout
        
        # Mises à jour disponibles
        stdout, stderr, code = self.executer_commande("apt list --upgradable 2>/dev/null")
        maj["updates_available"] = stdout
        
        # Dernière mise à jour
        stdout, stderr, code = self.executer_commande("stat /var/lib/apt/lists/ -c %Y")
        maj["last_update_check"] = stdout
        
        # Sources APT
        stdout, stderr, code = self.executer_commande("cat /etc/apt/sources.list")
        maj["apt_sources"] = stdout
        
        self.resultats["mises_a_jour"] = maj
        self.logger.info("Audit des mises à jour terminé")
    
    def executer_audit_complet(self):
        """Exécute l'audit complet du système"""
        self.logger.info("Début de l'audit système Linux")
        
        try:
            self.audit_informations_systeme()
            self.audit_utilisateurs()
            self.audit_services()
            self.audit_reseau()
            self.audit_fichiers_sensibles()
            self.audit_securite()
            self.audit_mises_a_jour()
            
            self.resultats["timestamp"] = datetime.now().isoformat()
            self.resultats["audit_type"] = "systeme_linux"
            
            self.logger.info("Audit système Linux terminé avec succès")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'audit système: {e}")
            return False
    
    def sauvegarder_resultats(self, format_sortie="json"):
        """Sauvegarde les résultats dans un fichier"""
        if format_sortie == "json":
            nom_fichier = f"outputs/logs_{self.begin}/{self.begin}_audit_systeme.json"
            with open(nom_fichier, 'w', encoding='utf-8') as f:
                json.dump(self.resultats, f, indent=2, ensure_ascii=False)
        else:
            nom_fichier = f"outputs/logs_{self.begin}/{self.begin}_audit_systeme.txt"
            with open(nom_fichier, 'w', encoding='utf-8') as f:
                f.write(f"AUDIT SYSTÈME LINUX - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*60 + "\n\n")
                
                for section, contenu in self.resultats.items():
                    f.write(f"\n[{section.upper()}]\n")
                    f.write("-" * 40 + "\n")
                    if isinstance(contenu, dict):
                        for key, value in contenu.items():
                            f.write(f"{key}: {value}\n")
                    else:
                        f.write(f"{contenu}\n")
                    f.write("\n")
        
        self.logger.info(f"Résultats sauvegardés dans {nom_fichier}")
        return nom_fichier

if __name__ == "__main__":
    # Configuration du logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Exécution de l'audit
    audit = AuditSysteme()
    if audit.executer_audit_complet():
        audit.sauvegarder_resultats("json")
        print("Audit système terminé avec succès")
    else:
        print("Erreur lors de l'audit système")