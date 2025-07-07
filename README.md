# AUdiThorium

Projet – Module Scripting 2024-2025  
**Audit de configuration d'un serveur Linux et d'un serveur web Apache**

## Présentation

**AUdiThorium** est un script Python d'audit de sécurité pour serveurs Linux (ex : Ubuntu Server) et serveurs web Apache. L'objectif est de collecter automatiquement les informations critiques de configuration, de détecter de mauvaises pratiques, et d'identifier des points faibles potentiels selon les standards de sécurité (CIS Benchmarks, ANSSI, etc.).

### Développeurs

- Louis de Lavenne
- Maxime Pages
- Quentin Lemaire 

## Fonctionnalités principales

- **Audit système Linux**  
  Collecte et analyse les paramètres essentiels du système d'exploitation pour repérer les mauvaises pratiques et faiblesses potentielles.

- **Audit du serveur web Apache**  
  Analyse la configuration du serveur Apache pour identifier les paramètres critiques et détecter d'éventuels points de faiblesse.

- **Génération automatique de fichiers de résultats**  
  - `outputs/logs_{date}/{date}_audit_systeme.txt` ou `.json` : Résultats de l'audit système
  - `outputs/logs_{date}/{date}_audit_apache.txt` ou `.json` : Résultats de l'audit Apache
  - `outputs/logs_{date}/{date}_audit.log` : Journal détaillé de l'exécution du script (début, fin, erreurs, modules appelés...)

## Structure du projet

- `audit_systeme.py` : Module d'audit système Linux
- `audit_apache.py` : Module d'audit Apache
- `audit_analyse.py` : Module d'analyse des résultats
- `doc.py` : Module de documentation
- `menu.py` : Point d'entrée, menu interactif, orchestration des modules

## Exécution

```bash
sudo python3 menu.py
```

Suivez le menu pour choisir le type d'audit à lancer.

Il est recommandé de commencer par l'option 3 (audit complet) avant d'appeler l'option 4 (analyse des audits).
Veuillez renvoyer le dossier `outputs/logs_{date}/` pour une analyse approfondie par nos équipes.

## Prérequis

- Python 3.x
- Système Linux (Ubuntu recommandé)
- Serveur Apache pour le module Apache

## Références

- [CIS Ubuntu Linux Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [CIS Apache HTTP Server Benchmark](https://www.cisecurity.org/benchmark/apache_http_server)
- [Recommandations ANSSI](https://www.ssi.gouv.fr/)

## Ce que nous collectons et pourquoi

### Audit système Linux

#### Informations système de base
- **Version OS et kernel** : Identifie les versions obsolètes ou non supportées présentant des vulnérabilités connues
- **Uptime et ressources** : Évalue la stabilité du système et détecte les redémarrages suspects
- **CPU et mémoire** : Analyse les performances et identifie les anomalies de consommation

#### Gestion des utilisateurs
- **Comptes avec shell** : Recense tous les utilisateurs pouvant exécuter des commandes interactives
- **Utilisateurs avec UID 0** : Détecte les comptes root multiples (violation des bonnes pratiques)
- **Comptes sans mot de passe** : Identifie les failles de sécurité critiques permettant l'accès non autorisé
- **Historique des connexions** : Analyse les patterns de connexion pour détecter les accès suspects
- **Privilèges sudo** : Évalue la distribution des privilèges administrateur

#### Services et processus
- **Services actifs** : Identifie les services non nécessaires augmentant la surface d'attaque
- **Services au démarrage** : Détecte les services automatiques potentiellement dangereux
- **Ports ouverts** : Analyse les points d'entrée réseau exposés aux attaques
- **Processus consommateurs** : Identifie les processus suspects ou malveillants

#### Configuration réseau
- **Interfaces réseau** : Évalue la configuration IP et détecte les interfaces non sécurisées
- **Tables de routage** : Analyse les chemins réseau et identifie les routes suspectes
- **Pare-feu (UFW/iptables)** : Vérifie la configuration des règles de filtrage réseau
- **Connexions établies** : Détecte les connexions non autorisées ou suspectes

#### Fichiers et permissions
- **Permissions des fichiers critiques** : Vérifie l'accès aux fichiers sensibles (/etc/passwd, /etc/shadow, etc.)
- **Fichiers SUID/SGID** : Identifie les programmes avec privilèges élevés pouvant être exploités
- **Fichiers world-writable** : Détecte les fichiers modifiables par tous les utilisateurs (risque d'escalade)

#### Sécurité avancée
- **Configuration SSH** : Analyse les paramètres de connexion distante (authentification, ports, etc.)
- **Politique de mots de passe** : Évalue les règles de complexité et d'expiration
- **Modules PAM** : Vérifie la configuration de l'authentification
- **Logs d'authentification** : Détecte les tentatives d'intrusion et échecs de connexion
- **AppArmor/SELinux** : Vérifie l'activation des systèmes de contrôle d'accès obligatoire

#### Mises à jour
- **Packages installés** : Inventaire des logiciels présents sur le système
- **Mises à jour disponibles** : Identifie les correctifs de sécurité non appliqués
- **Sources APT** : Vérifie l'intégrité des dépôts de packages

### Audit serveur Apache

#### Détection et configuration
- **Binaires Apache** : Localise l'installation et vérifie la version pour identifier les vulnérabilités
- **Modules compilés et chargés** : Analyse les fonctionnalités actives et identifie les modules inutiles
- **Configuration globale** : Examine les directives principales de sécurité

#### Configuration principale
- **ServerTokens/ServerSignature** : Vérifie la divulgation d'informations sensibles dans les en-têtes HTTP
- **User/Group** : Analyse les privilèges d'exécution du serveur web
- **DocumentRoot** : Vérifie l'emplacement et la sécurité des fichiers web
- **Directives de sécurité** : Évalue les paramètres de limitation et de protection

#### Virtual Hosts
- **Sites disponibles et activés** : Inventorie les sites web hébergés
- **Configuration des VirtualHosts** : Analyse les paramètres de sécurité par site
- **Certificats SSL** : Vérifie la configuration du chiffrement

#### Modules de sécurité
- **SSL/TLS** : Évalue la configuration du chiffrement des communications
- **Headers de sécurité** : Vérifie la présence des en-têtes de protection (HSTS, CSP, etc.)
- **Modules d'authentification** : Analyse les mécanismes de contrôle d'accès
- **Modules de réécriture** : Vérifie la configuration des règles de réécriture d'URL

#### Journalisation
- **Configuration des logs** : Évalue la qualité et la complétude de la journalisation
- **Répertoires et fichiers de logs** : Vérifie l'accessibilité et la rotation des journaux
- **Erreurs récentes** : Analyse les incidents et tentatives d'exploitation

#### Permissions et sécurité avancée
- **Permissions des fichiers de configuration** : Vérifie l'accès aux fichiers sensibles d'Apache
- **Propriétaires des processus** : Analyse les privilèges d'exécution
- **Fichiers .htaccess** : Identifie les configurations de répertoire potentiellement dangereuses
- **Modules dangereux** : Détecte les modules exposant des informations sensibles (mod_status, mod_info, etc.)

### Importance de ces données

Ces informations sont cruciales pour :

1. **Évaluation des risques** : Identifier les vulnérabilités exploitables par des attaquants
2. **Conformité réglementaire** : Vérifier le respect des standards de sécurité (CIS, ANSSI, NIST)
3. **Détection d'intrusions** : Repérer les signes de compromission ou d'activité malveillante
4. **Hardening** : Proposer des recommandations de durcissement de la sécurité
5. **Audit de conformité** : Documenter l'état de sécurité pour les audits internes et externes
6. **Gestion des incidents** : Fournir une base de données pour l'investigation forensique
7. **Amélioration continue** : Établir un référentiel pour le suivi des améliorations de sécurité