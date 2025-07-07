#!/usr/bin/env python3
"""
Module d'audit serveur web Apache
Collecte les informations critiques de configuration Apache pour l'audit de sécurité
"""

import subprocess
import os
import json
import re
from datetime import datetime
import logging

class AuditApache:
    def __init__(self, logger=None):
        self.resultats = {}
        self.begin = b
        self.logger = logger if logger else logging.getLogger(name)
        self.apache_paths = [
            "/etc/apache2",
            "/etc/httpd",
            "/usr/local/apache2",
            "/opt/apache2"
        ]
        self.apache_binaries = [
            "apache2",
            "httpd",
            "apache2ctl",
            "apachectl"
        ]
        self.apache_root = None
        self.apache_binary = None
        
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
    
    def detecter_apache(self):
        """Détecte l'installation et la configuration Apache"""
        detection = {}
        
        # Recherche du binaire Apache
        for binary in self.apache_binaries:
            stdout, stderr, code = self.executer_commande(f"which {binary}")
            if code == 0 and stdout:
                self.apache_binary = binary
                detection["binary_path"] = stdout
                break
        
        if not self.apache_binary:
            self.logger.warning("Aucun binaire Apache trouvé")
            return False
        
        # Recherche du répertoire de configuration
        for path in self.apache_paths:
            if os.path.exists(path):
                self.apache_root = path
                detection["config_root"] = path
                break
        
        # Version Apache
        stdout, stderr, code = self.executer_commande(f"{self.apache_binary} -v")
        detection["version"] = stdout
        
        # Modules compilés
        stdout, stderr, code = self.executer_commande(f"{self.apache_binary} -l")
        detection["compiled_modules"] = stdout
        
        # Modules chargés
        stdout, stderr, code = self.executer_commande(f"{self.apache_binary} -M")
        detection["loaded_modules"] = stdout
        
        # Configuration active
        stdout, stderr, code = self.executer_commande(f"{self.apache_binary} -S")
        detection["config_syntax"] = stdout
        
        # Processus Apache
        stdout, stderr, code = self.executer_commande("ps aux | grep -E '(apache|httpd)' | grep -v grep")
        detection["processes"] = stdout
        
        self.resultats["detection"] = detection
        self.logger.info("Détection Apache terminée")
        return True
    
    def audit_configuration_principale(self):
        """Audit de la configuration principale Apache"""
        config = {}
        
        if not self.apache_root:
            self.logger.warning("Répertoire de configuration Apache non trouvé")
            return
        
        # Fichiers de configuration principaux
        config_files = [
            "apache2.conf", "httpd.conf", "000-default.conf",
            "default-ssl.conf", "security.conf", "ports.conf"
        ]
        
        configurations = {}
        for conf_file in config_files:
            file_path = os.path.join(self.apache_root, conf_file)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        configurations[conf_file] = f.read()
                except Exception as e:
                    configurations[conf_file] = f"Erreur de lecture: {e}"
            else:
                # Recherche récursive
                stdout, stderr, code = self.executer_commande(f"find {self.apache_root} -name '{conf_file}' -type f")
                if stdout:
                    try:
                        with open(stdout.split('\n')[0], 'r', encoding='utf-8') as f:
                            configurations[conf_file] = f.read()
                    except Exception as e:
                        configurations[conf_file] = f"Erreur de lecture: {e}"
        
        config["fichiers_configuration"] = configurations
        
        # Directive ServerTokens
        stdout, stderr, code = self.executer_commande(f"grep -r 'ServerTokens' {self.apache_root}")
        config["server_tokens"] = stdout
        
        # Directive ServerSignature
        stdout, stderr, code = self.executer_commande(f"grep -r 'ServerSignature' {self.apache_root}")
        config["server_signature"] = stdout
        
        # Directive ServerRoot
        stdout, stderr, code = self.executer_commande(f"grep -r 'ServerRoot' {self.apache_root}")
        config["server_root"] = stdout
        
        # Directive DocumentRoot
        stdout, stderr, code = self.executer_commande(f"grep -r 'DocumentRoot' {self.apache_root}")
        config["document_root"] = stdout
        
        # Directive User/Group
        stdout, stderr, code = self.executer_commande(f"grep -r -E '^(User|Group)' {self.apache_root}")
        config["user_group"] = stdout
        
        self.resultats["configuration_principale"] = config
        self.logger.info("Audit de la configuration principale terminé")
    
    def audit_virtualhost(self):
        """Audit des Virtual Hosts"""
        vhosts = {}
        
        if not self.apache_root:
            return
        
        # Sites disponibles
        sites_available = os.path.join(self.apache_root, "sites-available")
        if os.path.exists(sites_available):
            stdout, stderr, code = self.executer_commande(f"ls -la {sites_available}")
            vhosts["sites_available"] = stdout
            
            # Contenu des sites disponibles
            configs_sites = {}
            for fichier in os.listdir(sites_available):
                if fichier.endswith('.conf'):
                    try:
                        with open(os.path.join(sites_available, fichier), 'r', encoding='utf-8') as f:
                            configs_sites[fichier] = f.read()
                    except Exception as e:
                        configs_sites[fichier] = f"Erreur de lecture: {e}"
            vhosts["configurations_sites"] = configs_sites
        
        # Sites activés
        sites_enabled = os.path.join(self.apache_root, "sites-enabled")
        if os.path.exists(sites_enabled):
            stdout, stderr, code = self.executer_commande(f"ls -la {sites_enabled}")
            vhosts["sites_enabled"] = stdout
        
        # Virtual hosts actifs
        stdout, stderr, code = self.executer_commande(f"{self.apache_binary} -S")
        vhosts["vhosts_actifs"] = stdout
        
        self.resultats["virtualhost"] = vhosts
        self.logger.info("Audit des Virtual Hosts terminé")
    
    def audit_modules_securite(self):
        """Audit des modules de sécurité"""
        modules_sec = {}
        
        # Modules activés
        mods_enabled = os.path.join(self.apache_root, "mods-enabled")
        if os.path.exists(mods_enabled):
            stdout, stderr, code = self.executer_commande(f"ls -la {mods_enabled}")
            modules_sec["mods_enabled"] = stdout
        
        # Modules de sécurité importants
        security_modules = [
            "ssl", "rewrite", "headers", "security2", "evasive",
            "auth_digest", "auth_basic", "access_compat"
        ]
        
        modules_status = {}
        for module in security_modules:
            stdout, stderr, code = self.executer_commande(f"{self.apache_binary} -M | grep {module}")
            modules_status[module] = "Activé" if stdout else "Désactivé"
        
        modules_sec["security_modules_status"] = modules_status
        
        # Configuration SSL
        stdout, stderr, code = self.executer_commande(f"grep -r 'SSLEngine' {self.apache_root}")
        modules_sec["ssl_config"] = stdout
        
        # Configuration des headers de sécurité
        stdout, stderr, code = self.executer_commande(f"grep -r -E '(Header.*Security|Header.*Frame|Header.*Content)' {self.apache_root}")
        modules_sec["security_headers"] = stdout
        
        self.resultats["modules_securite"] = modules_sec
        self.logger.info("Audit des modules de sécurité terminé")
    
    def audit_logs(self):
        """Audit de la configuration des logs"""
        logs = {}
        
        # Configuration des logs
        stdout, stderr, code = self.executer_commande(f"grep -r -E '(ErrorLog|CustomLog|LogFormat)' {self.apache_root}")
        logs["log_config"] = stdout
        
        # Répertoires de logs
        log_dirs = ["/var/log/apache2", "/var/log/httpd", "/var/log/apache"]
        for log_dir in log_dirs:
            if os.path.exists(log_dir):
                stdout, stderr, code = self.executer_commande(f"ls -la {log_dir}")
                logs[f"log_dir_{log_dir}"] = stdout
                
                # Taille des logs
                stdout, stderr, code = self.executer_commande(f"du -sh {log_dir}/*")
                logs[f"log_sizes_{log_dir}"] = stdout
        
        # Logs d'erreur récents
        for log_dir in log_dirs:
            error_log = os.path.join(log_dir, "error.log")
            if os.path.exists(error_log):
                stdout, stderr, code = self.executer_commande(f"tail -50 {error_log}")
                logs["recent_errors"] = stdout
                break
        
        self.resultats["logs"] = logs
        self.logger.info("Audit des logs terminé")
    
    def audit_permissions(self):
        """Audit des permissions des fichiers Apache"""
        permissions = {}
        
        if not self.apache_root:
            return
        
        # Permissions du répertoire de configuration
        stdout, stderr, code = self.executer_commande(f"ls -la {self.apache_root}")
        permissions["config_dir_permissions"] = stdout
        
        # Permissions des fichiers de configuration
        stdout, stderr, code = self.executer_commande(f"find {self.apache_root} -type f -name '*.conf' -exec ls -la {{}} \\;")
        permissions["config_files_permissions"] = stdout
        
        # Propriétaire des processus Apache
        stdout, stderr, code = self.executer_commande("ps aux | grep -E '(apache|httpd)' | grep -v grep")
        permissions["process_owner"] = stdout
        
        # Permissions des répertoires web
        stdout, stderr, code = self.executer_commande(f"grep -r 'DocumentRoot' {self.apache_root}")
        if stdout:
            # Extraire le chemin du DocumentRoot
            doc_roots = re.findall(r'DocumentRoot\s+([^\s]+)', stdout)
            for doc_root in doc_roots:
                if os.path.exists(doc_root):
                    stdout2, stderr2, code2 = self.executer_commande(f"ls -la {doc_root}")
                    permissions[f"web_dir_{doc_root}"] = stdout2
        
        self.resultats["permissions"] = permissions
        self.logger.info("Audit des permissions terminé")
    
    def audit_securite_avancee(self):
        """Audit des paramètres de sécurité avancés"""
        securite = {}
        
        # Directives de sécurité dans la configuration
        directives_securite = [
            "ServerTokens", "ServerSignature", "AllowOverride",
            "Options", "DirectoryIndex", "LimitRequestBody",
            "Timeout", "KeepAlive", "MaxKeepAliveRequests"
        ]
        
        for directive in directives_securite:
            stdout, stderr, code = self.executer_commande(f"grep -r '{directive}' {self.apache_root}")
            securite[directive.lower()] = stdout
        
        # Configuration des .htaccess
        stdout, stderr, code = self.executer_commande(f"find {self.apache_root} -name '.htaccess' -exec ls -la {{}} \\;")
        securite["htaccess_files"] = stdout
        
        # Modules potentiellement dangereux
        modules_dangereux = ["userdir", "autoindex", "status", "info"]
        modules_danger_status = {}
        for module in modules_dangereux:
            stdout, stderr, code = self.executer_commande(f"{self.apache_binary} -M | grep {module}")
            modules_danger_status[module] = "Activé" if stdout else "Désactivé"
        
        securite["modules_dangereux"] = modules_danger_status
        
        self.resultats["securite_avancee"] = securite
        self.logger.info("Audit de sécurité avancée terminé")
    
    def executer_audit_complet(self):
        """Exécute l'audit complet d'Apache"""
        self.logger.info("Début de l'audit Apache")
        
        try:
            if not self.detecter_apache():
                self.logger.error("Apache non détecté sur le système")
                return False
            
            self.audit_configuration_principale()
            self.audit_virtualhost()
            self.audit_modules_securite()
            self.audit_logs()
            self.audit_permissions()
            self.audit_securite_avancee()
            
            self.resultats["timestamp"] = datetime.now().isoformat()
            self.resultats["audit_type"] = "apache_web_server"
            
            self.logger.info("Audit Apache terminé avec succès")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'audit Apache: {e}")
            return False
    
    def sauvegarder_resultats(self, format_sortie="json"):
        """Sauvegarde les résultats dans un fichier"""
        if format_sortie == "json":
            nom_fichier = "audit_apache.json"
            with open(nom_fichier, 'w', encoding='utf-8') as f:
                json.dump(self.resultats, f, indent=2, ensure_ascii=False)
        else:
            nom_fichier = "audit_apache.txt"
            with open(nom_fichier, 'w', encoding='utf-8') as f:
                f.write(f"AUDIT SERVEUR APACHE - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
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
    audit = AuditApache()
    if audit.executer_audit_complet():
        audit.sauvegarder_resultats("json")
        print("Audit Apache terminé avec succès")
    else:
        print("Erreur lors de l'audit Apache")