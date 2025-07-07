# AUdiThorium

Projet – Module Scripting 2024-2025  
**Audit de configuration d’un serveur Linux et d’un serveur web Apache**

## Présentation

**AUdiThorium** est un script Python d’audit de sécurité pour serveurs Linux (ex : Ubuntu Server) et serveurs web Apache. L’objectif est de collecter automatiquement les informations critiques de configuration, de détecter de mauvaises pratiques, et d’identifier des points faibles potentiels selon les standards de sécurité (CIS Benchmarks, ANSSI, etc.).

## Fonctionnalités principales

- **Audit système Linux**  
  Collecte et analyse les paramètres essentiels du système d’exploitation pour repérer les mauvaises pratiques et faiblesses potentielles.

- **Audit du serveur web Apache**  
  Analyse la configuration du serveur Apache pour identifier les paramètres critiques et détecter d’éventuels points de faiblesse.

- **Génération automatique de fichiers de résultats**  
  - `audit_systeme.txt` ou `.json` : Résultats de l’audit système
  - `audit_apache.txt` ou `.json` : Résultats de l’audit Apache
  - `audit.log` : Journal détaillé de l’exécution du script (début, fin, erreurs, modules appelés...)

## Structure du projet

- `linux_audit.py` : Module d’audit système Linux
- `apache_audit.py` : Module d’audit Apache
- `main.py` : Point d’entrée, menu interactif, orchestration des modules
- `audit_systeme.txt` / `.json` : Résultats audit système (générés)
- `audit_apache.txt` / `.json` : Résultats audit Apache (générés)
- `audit.log` : Log d’audit (généré)

## Exécution

```bash
python3 main.py
```

Suivez le menu pour choisir le type d’audit à lancer.

## Prérequis

- Python 3.x
- Système Linux (Ubuntu recommandé)
- Serveur Apache pour le module Apache

## Références

- [CIS Ubuntu Linux Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [CIS Apache HTTP Server Benchmark](https://www.cisecurity.org/benchmark/apache_http_server)
- [Recommandations ANSSI](https://www.ssi.gouv.fr/)
