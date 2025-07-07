# AUdiThorium

Projet – Module Scripting 2024-2025  
**Audit de configuration d’un serveur Linux et d’un serveur web Apache**

## Présentation

**AUdiThorium** est un script Python d’audit de sécurité pour serveurs Linux (ex : Ubuntu Server) et serveurs web Apache. L’objectif est de collecter automatiquement les informations critiques de configuration, de détecter de mauvaises pratiques, et d’identifier des points faibles potentiels selon les standards de sécurité (CIS Benchmarks, ANSSI, etc.).

### Développeurs

- Louis de Lavenne
- Maxime Pages
- Quentin Lemaire 

## Fonctionnalités principales

- **Audit système Linux**  
  Collecte et analyse les paramètres essentiels du système d’exploitation pour repérer les mauvaises pratiques et faiblesses potentielles.

- **Audit du serveur web Apache**  
  Analyse la configuration du serveur Apache pour identifier les paramètres critiques et détecter d’éventuels points de faiblesse.

- **Génération automatique de fichiers de résultats**  
  - `outputs/logs_{date}/{date}_audit_systeme.txt` ou `.json` : Résultats de l’audit système
  - `outputs/logs_{date}/{date}_audit_apache.txt` ou `.json` : Résultats de l’audit Apache
  - `outputs/logs_{date}/{date}_audit.log` : Journal détaillé de l’exécution du script (début, fin, erreurs, modules appelés...)

## Structure du projet

- `audit_systeme.py` : Module d’audit système Linux
- `audit_apache.py` : Module d’audit Apache
- `audit_analyse.py` : Module d'analyse des résultats
- `doc.py` : Module de documentation
- `menu.py` : Point d’entrée, menu interactif, orchestration des modules

## Exécution

```bash
sudo python3 menu.py
```

Suivez le menu pour choisir le type d’audit à lancer.

Il est recommandé de commencer par l'option 3 (audit complet) avant d'appeler l'option 4 (analyse des audits).

## Prérequis

- Python 3.x
- Système Linux (Ubuntu recommandé)
- Serveur Apache pour le module Apache

## Références

- [CIS Ubuntu Linux Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [CIS Apache HTTP Server Benchmark](https://www.cisecurity.org/benchmark/apache_http_server)
- [Recommandations ANSSI](https://www.ssi.gouv.fr/)
