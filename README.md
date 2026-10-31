<h1 align="center">DashAudit</h1>

DashAudit est un projet réalisé en équipe de quatre lors d’un **hackathon** organisé par **EPITECH**, que nous avons remporté.

L’application répond à une problématique simple : comment repérer rapidement les erreurs de configuration d’un site ou d’un serveur et identifier les corrections prioritaires ?

Elle centralise les résultats d’audits de sécurité dans un tableau de bord avec un historique et des alertes. Les contrôles portent sur les en-têtes HTTP, le certificat TLS et une sélection de ports TCP. Une recherche complémentaire permet de consulter des références de vulnérabilités connues.

Le projet utilise Angular pour l’interface, Python pour le back-end et les audits ainsi que des scripts Bash pour leur lancement. Les résultats sont conservés dans une base SQLite locale.

## Installation

### Prérequis

- Git
- Node.js 24 avec npm
- Python 3.12
- Bash

### Récupérer le projet

    git clone https://github.com/Shunthail/DashAudit.git
    cd DashAudit

### Compiler et lancer l’application

    bash scripts/build.sh
    bash scripts/start.sh

L’application est accessible sur http://127.0.0.1:8000.

Le back-end utilise uniquement la bibliothèque standard de Python. Aucun paquet Python supplémentaire n’est nécessaire.

Au premier lancement, aucun audit n’est préenregistré. Les compteurs et l’historique sont alimentés par les audits réalisés.

### Lancer un audit en ligne de commande

    bash scripts/audit.sh --authorized https://votre-site.fr

Pour inclure la recherche de références CVE :

    bash scripts/audit.sh --authorized https://votre-site.fr --cves

Les résultats sont affichés dans le terminal et enregistrés pour être consultés depuis le tableau de bord.

### Développement

Pour lancer le back-end et le serveur de développement Angular :

    bash scripts/dev.sh

L’interface de développement est accessible sur http://127.0.0.1:4200.

### Vérifications

Pour exécuter les tests du back-end, vérifier les scripts Bash et compiler l’interface :

    bash scripts/check.sh

## Portée des audits

DashAudit contrôle la configuration HTTP et TLS ainsi que l’exposition de certains ports TCP.

La recherche de vulnérabilités utilise les versions Apache ou nginx identifiables dans les réponses du serveur. Les références retournées par la NVD sont des correspondances à examiner et ne constituent pas une confirmation de vulnérabilité.

## Le hackathon

Nous avons développé DashAudit à quatre pour réunir des contrôles techniques dispersés dans une interface permettant de distinguer les problèmes prioritaires et de suivre leur évolution entre plusieurs audits.

[EPITECH](https://www.epitech.eu/programme-grande-ecole-informatique/) est une école privée d’informatique proposant un Programme Grande École en cinq ans.

## À propos du projet

Au sein du groupe, j’ai pris en charge le back-end Python, la logique des audits et les scripts Bash. J’ai développé les contrôles des en-têtes HTTP, la vérification des certificats TLS et les tests de connexion TCP exécutés en parallèle sur une sélection de ports.

La logique serveur comprend la validation des cibles, la gestion des délais de connexion et le traitement des erreurs réseau. Les constats sont structurés par catégorie et par niveau de gravité avant d’être transmis à l’interface. J’ai également intégré la recherche de références CVE à partir des versions de serveur exposées en distinguant ces correspondances des vulnérabilités confirmées.

Pour la persistance, j’ai travaillé sur l’enregistrement des rapports dans SQLite et leur restitution par l’API afin d’alimenter l’historique des audits. Les scripts Bash permettent de lancer les contrôles depuis le terminal, de compiler l’interface et de démarrer les différents composants du projet.

Pour préserver mon anonymat et celui des autres participants, j’ai adapté cette version publique en retirant les informations personnelles présentes dans le projet, notamment les noms, les prénoms et les coordonnées.

Ce dépôt accompagne la présentation de mes compétences sur [shunthail.fr](https://shunthail.fr). Il s’adresse notamment aux recruteurs qui souhaitent consulter mon travail et explorer le code sans avoir à me contacter au préalable.

## Réutilisation et contact

Vous pouvez utiliser le code ou vous inspirer du projet sans me demander d’autorisation. Un message reste toujours apprécié si ce travail vous aide à lancer un projet ou à développer une idée.

Si vous avez une question ou besoin d’aide, vous pouvez me contacter sur Discord : **shunthail**.
