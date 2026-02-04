# SecuLab CTF - Infrastructure & Ops

> 🎓 **Dépôt enseignant** : Scripts de provisioning et déploiement pour le TP cybersécurité BUT3.

## 📋 Prérequis

- Python 3.10+
- Google Cloud SDK (`gcloud`) configuré
- Accès à un projet GCP avec les APIs Compute Engine activées
- Clé API Google Gemini

## 🚀 Workflow complet

### 1. Configuration initiale

```bash
# Cloner ce dépôt
git clone https://github.com/votre-org/seculab-infra.git
cd seculab-infra

# Installer les dépendances
pip install -r requirements.txt

# Configurer la clé Gemini
cp .env.master.example .env.master
nano .env.master  # Ajouter votre clé GEMINI_API_KEY
```

### 2. Provisionner la VM GCP

```bash
python provision_vm.py \
    --project=votre-projet-gcp \
    --zone=europe-west1-b \
    --name=seculab-ctf
```

Cette commande :

- Crée une VM Ubuntu 24.04 LTS
- Installe Apache, PHP 8.3-FPM, SQLite
- Configure UFW (pare-feu)
- Configure les règles de pare-feu GCP

### 3. Copier les fichiers sur la VM

```bash
# Se connecter à la VM
gcloud compute ssh seculab-ctf --zone=europe-west1-b

# Cloner le dépôt infra
git clone https://github.com/votre-org/seculab-infra.git
cd seculab-infra

# Installer les dépendances
pip install -r requirements.txt
```

### 4. Déployer les instances étudiantes

```bash
# Déployer N instances (exemple: 25 étudiants)
sudo python3 deploy_lab.py --count=25 --domain=marill.fr

# Avec la clé Gemini en argument
sudo python3 deploy_lab.py --count=25 --gemini-key=AIza...
```

Le script génère :

- Un utilisateur Linux par étudiant (`user-[UUID]`)
- Un pool PHP-FPM isolé par instance
- Un VirtualHost Apache par instance
- Des flags uniques basés sur l'UUID
- Un fichier `instances_report.csv` récapitulatif

### 5. Configuration DNS

Configurez un enregistrement DNS wildcard :

```
*.marill.fr  A  [IP_DE_LA_VM]
```

### 6. Valider les corrections étudiantes

```bash
# Valider une instance spécifique
sudo python3 validate_lab.py --instance=abc12345 --verbose

# Valider toutes les instances depuis le CSV
sudo python3 validate_lab.py --csv=instances_report.csv
```

Le script analyse le code de chaque instance et vérifie si les 7 failles ont été corrigées.

**Pondération des failles :**

| Faille           | Poids | Module      |
| ---------------- | ----- | ----------- |
| SQL Injection    | 20%   | auth.php    |
| RCE (eval)       | 20%   | calc.php    |
| IDOR             | 15%   | profile.php |
| XSS Stocké       | 15%   | wall.php    |
| Logic Error      | 10%   | admin.php   |
| Info Disclosure  | 10%   | debug.php   |
| Prompt Injection | 10%   | secubot.php |

Chaque instance reçoit un `validation_report.json` avec le détail des vérifications.

## 📁 Structure du projet

```
seculab-infra/
├── provision_vm.py       # Création de la VM GCP
├── deploy_lab.py         # Déploiement des instances
├── validate_lab.py       # Validation des corrections
├── requirements.txt      # Dépendances Python
├── .env.master          # Clé Gemini (à configurer)
└── README.md            # Ce fichier
```

## 📊 Fichier CSV de sortie

Le fichier `instances_report.csv` contient :

| Colonne                 | Description                             |
| ----------------------- | --------------------------------------- |
| uuid                    | Identifiant unique de l'instance        |
| url-instance            | URL complète (https://[UUID].marill.fr) |
| ssh-user                | Nom d'utilisateur Linux                 |
| ssh-password            | Mot de passe SSH                        |
| secret-sqli             | Flag SQL Injection                      |
| secret-idor             | Flag IDOR                               |
| secret-xss              | Flag XSS                                |
| secret-rce              | Flag RCE                                |
| secret-logic            | Flag Logic Error                        |
| secret-debug            | Flag Info Disclosure                    |
| secret-prompt-injection | Flag Prompt Injection                   |
| score                   | Score de correction (0-100%)            |
| grade                   | Note (A/B/C/D/E/F)                      |

## 🔐 Sécurité

- Les mots de passe SSH sont générés aléatoirement
- Les flags sont uniques par instance (basés sur SHA256)
- Chaque instance est isolée (utilisateur Linux + pool PHP-FPM)
- L'egress est limité (UFW bloque tout sauf Gemini API)

## 🛠️ Dépannage

### La VM ne répond pas après création

Attendez 2-3 minutes que le startup script s'exécute, puis :

```bash
gcloud compute ssh seculab-ctf --zone=europe-west1-b
sudo tail -f /var/log/syslog
```

### Le module SecuBot ne fonctionne pas

Vérifiez que la clé Gemini est valide et que l'egress vers Google est autorisé.

### Une instance ne charge pas

Vérifiez les logs Apache :

```bash
sudo tail -f /var/www/instances/[UUID]/logs/apache_error.log
```

---

_SecuLab CTF - IUT BUT3 Cybersécurité_
