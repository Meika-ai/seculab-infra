#!/usr/bin/env python3
"""
SecuLab CTF - Script de Deploiement des Instances Etudiantes
Cree les utilisateurs, pools PHP-FPM, VirtualHosts et initialise les sites

Usage:
    sudo python3 deploy_lab.py --count=N [--domain=DOMAIN] [--repo=REPO_URL]
    
Exemple:
    sudo python3 deploy_lab.py --count=25 --domain=marill.fr
"""

import argparse
import csv
import hashlib
import os
import pwd
import grp
import secrets
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Dict, List
from jinja2 import Template


# Configuration
DEFAULT_DOMAIN = "seculab.marill.fr"
DEFAULT_REPO = "https://github.com/Meika-ai/seculab-app.git"
INSTANCES_DIR = Path("/var/www/instances")
PHP_FPM_POOL_DIR = Path("/etc/php/8.3/fpm/pool.d")
APACHE_SITES_DIR = Path("/etc/apache2/sites-available")
TEMPLATES_DIR = Path(__file__).parent / "templates"
ENV_EXAMPLE_PATH = Path(__file__).parent / ".env.master"


def check_root():
    """Verifie que le script est execute en tant que root."""
    if os.geteuid() != 0:
        print("[ERROR] Ce script doit etre execute en tant que root (sudo)")
        sys.exit(1)


def generate_uuid() -> str:
    """Genere un UUID court (8 caracteres)."""
    return str(uuid.uuid4())[:8]


def generate_password(length: int = 16) -> str:
    """Genere un mot de passe aleatoire."""
    return secrets.token_urlsafe(length)[:length]


def generate_flag(instance_uuid: str, flag_type: str, salt: str = "seculab2024") -> str:
    """Genere un flag deterministe base sur l'UUID."""
    data = f"{instance_uuid}:{flag_type}:{salt}"
    hash_value = hashlib.sha256(data.encode()).hexdigest()[:16].upper()
    return f"FLAG{{{flag_type}_{hash_value}}}"


def create_linux_user(username: str, password: str, home_dir: Path) -> bool:
    """Cree un utilisateur Linux avec rbash."""
    try:
        # Creer l'utilisateur avec rbash
        subprocess.run([
            "useradd", "-m",
            "-d", str(home_dir),
            "-s", "/bin/rbash",
            "-G", "www-data",
            username
        ], check=True, capture_output=True)
        
        # Definir le mot de passe
        proc = subprocess.Popen(
            ["chpasswd"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        proc.communicate(f"{username}:{password}".encode())
        
        # Configurer le profil rbash restrictif
        setup_rbash_profile(username, home_dir)
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"  [ERROR] Erreur creation utilisateur {username}: {e.stderr.decode()}")
        return False


def setup_rbash_profile(username: str, home_dir: Path):
    """Configure un environnement rbash restrictif."""
    # Creer le repertoire .bin pour les commandes autorisees
    bin_dir = home_dir / ".bin"
    bin_dir.mkdir(exist_ok=True)
    
    # Liens symboliques vers les commandes autorisees
    allowed_commands = ["ls", "cat", "vi", "vim", "git", "php", "nano", "grep", "less"]
    for cmd in allowed_commands:
        cmd_path = shutil.which(cmd)
        if cmd_path:
            link_path = bin_dir / cmd
            if not link_path.exists():
                os.symlink(cmd_path, link_path)
    
    # Creer le .bash_profile restrictif
    bash_profile = home_dir / ".bash_profile"
    bash_profile.write_text(f'''# SecuLab Restricted Environment
export PATH="{bin_dir}"
export SHELL=/bin/rbash
readonly PATH
readonly SHELL
readonly HISTFILE
cd "{home_dir}"
echo "Bienvenue sur SecuLab CTF - Environnement restreint"
echo "Repertoire: {home_dir}"
echo "Commandes disponibles: {', '.join(allowed_commands)}"
''')
    
    # Proteger les fichiers
    subprocess.run(["chown", "root:root", str(bash_profile)], check=True)
    subprocess.run(["chmod", "644", str(bash_profile)], check=True)
    subprocess.run(["chown", "-R", f"{username}:www-data", str(bin_dir)], check=True)


def create_php_fpm_pool(instance_uuid: str, username: str):
    """Cree un pool PHP-FPM dedie pour l'instance."""
    template = Template('''[{{ uuid }}]
user = {{ username }}
group = www-data
listen = /run/php/php8.3-fpm-{{ uuid }}.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3

; Isolation de securite
php_admin_value[open_basedir] = {{ instance_dir }}:/tmp
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen,curl_multi_exec,parse_ini_file,show_source
php_admin_value[session.save_path] = {{ instance_dir }}/sessions
php_admin_value[upload_tmp_dir] = {{ instance_dir }}/tmp

; Logging
php_admin_flag[log_errors] = on
php_admin_value[error_log] = {{ instance_dir }}/logs/php_errors.log
''')
    
    instance_dir = INSTANCES_DIR / instance_uuid
    config = template.render(
        uuid=instance_uuid,
        username=username,
        instance_dir=str(instance_dir)
    )
    
    pool_file = PHP_FPM_POOL_DIR / f"{instance_uuid}.conf"
    pool_file.write_text(config)
    
    # Creer les repertoires necessaires
    (instance_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (instance_dir / "tmp").mkdir(parents=True, exist_ok=True)
    (instance_dir / "logs").mkdir(parents=True, exist_ok=True)


def create_apache_vhost(instance_uuid: str, domain: str):
    """Cree un VirtualHost Apache pour l'instance."""
    template = Template('''<VirtualHost *:80>
    ServerName {{ uuid }}.{{ domain }}
    DocumentRoot {{ instance_dir }}
    
    <Directory {{ instance_dir }}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    # Proxy vers le pool PHP-FPM dedie
    <FilesMatch \\.php$>
        SetHandler "proxy:unix:/run/php/php8.3-fpm-{{ uuid }}.sock|fcgi://localhost"
    </FilesMatch>
    
    # Logs
    ErrorLog {{ instance_dir }}/logs/apache_error.log
    CustomLog {{ instance_dir }}/logs/apache_access.log combined
    
    # Securite basique
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
</VirtualHost>
''')
    
    instance_dir = INSTANCES_DIR / instance_uuid
    config = template.render(
        uuid=instance_uuid,
        domain=domain,
        instance_dir=str(instance_dir)
    )
    
    vhost_file = APACHE_SITES_DIR / f"{instance_uuid}.conf"
    vhost_file.write_text(config)
    
    # Activer le site
    subprocess.run(["a2ensite", f"{instance_uuid}.conf"], 
                   check=True, capture_output=True)


def clone_and_setup_app(instance_uuid: str, username: str, repo_url: str, 
                        flags: Dict[str, str], gemini_key: str):
    """Clone le repo et configure l'instance."""
    instance_dir = INSTANCES_DIR / instance_uuid
    
    # Cloner le depot
    subprocess.run([
        "git", "clone", "--depth=1", repo_url, str(instance_dir)
    ], check=True, capture_output=True)
    
    # Creer le fichier .env avec les flags
    env_content = f'''# SecuLab CTF - Instance {instance_uuid}
# Genere automatiquement - NE PAS MODIFIER

# Secrets (flags uniques)
SECRET_SQLI={flags['sqli']}
SECRET_IDOR={flags['idor']}
SECRET_XSS={flags['xss']}
SECRET_RCE={flags['rce']}
SECRET_LOGIC={flags['logic']}
SECRET_DEBUG={flags['debug']}
SECRET_PROMPT_INJECTION={flags['prompt']}

# API Gemini
GEMINI_API_KEY={gemini_key}
'''
    
    env_file = instance_dir / ".env"
    env_file.write_text(env_content)
    
    # Initialiser la base de donnees
    subprocess.run([
        "php", str(instance_dir / "init_database.php")
    ], cwd=str(instance_dir), capture_output=True)
    
    # Corriger les permissions
    subprocess.run([
        "chown", "-R", f"{username}:www-data", str(instance_dir)
    ], check=True)
    subprocess.run([
        "chmod", "-R", "g+w", str(instance_dir)
    ], check=True)
    subprocess.run([
        "chmod", "600", str(env_file)
    ], check=True)


def deploy_instance(instance_uuid: str, domain: str, repo_url: str, 
                    gemini_key: str) -> Dict:
    """Deploie une instance complete."""
    username = f"user-{instance_uuid}"
    password = generate_password()
    home_dir = INSTANCES_DIR / instance_uuid
    
    print(f"  [DEPLOY] Deploiement {instance_uuid}...")
    
    # Generer les flags
    flags = {
        'sqli': generate_flag(instance_uuid, 'SQLI'),
        'idor': generate_flag(instance_uuid, 'IDOR'),
        'xss': generate_flag(instance_uuid, 'XSS'),
        'rce': generate_flag(instance_uuid, 'RCE'),
        'logic': generate_flag(instance_uuid, 'LOGIC'),
        'debug': generate_flag(instance_uuid, 'DEBUG'),
        'prompt': generate_flag(instance_uuid, 'PROMPT'),
    }
    
    # Creer l'utilisateur Linux
    if not create_linux_user(username, password, home_dir):
        return None
    print(f"    [OK] Utilisateur {username} cree")
    
    # Creer le pool PHP-FPM
    create_php_fpm_pool(instance_uuid, username)
    print(f"    [OK] Pool PHP-FPM configure")
    
    # Creer le VirtualHost Apache
    create_apache_vhost(instance_uuid, domain)
    print(f"    [OK] VirtualHost Apache cree")
    
    # Cloner et configurer l'application
    clone_and_setup_app(instance_uuid, username, repo_url, flags, gemini_key)
    print(f"    [OK] Application deployee")
    
    return {
        'uuid': instance_uuid,
        'url': f"https://{instance_uuid}.{domain}",
        'ssh_user': username,
        'ssh_password': password,
        'flags': flags
    }


def export_csv(instances: List[Dict], output_path: Path):
    """Exporte le rapport CSV."""
    fieldnames = [
        'uuid', 'url-instance', 'ssh-user', 'ssh-password',
        'secret-sqli', 'secret-idor', 'secret-xss', 
        'secret-rce', 'secret-logic', 'secret-prompt-injection'
    ]
    
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for inst in instances:
            if inst:
                writer.writerow({
                    'uuid': inst['uuid'],
                    'url-instance': inst['url'],
                    'ssh-user': inst['ssh_user'],
                    'ssh-password': inst['ssh_password'],
                    'secret-sqli': inst['flags']['sqli'],
                    'secret-idor': inst['flags']['idor'],
                    'secret-xss': inst['flags']['xss'],
                    'secret-rce': inst['flags']['rce'],
                    'secret-logic': inst['flags']['logic'],
                    'secret-prompt-injection': inst['flags']['prompt'],
                })
    
    print(f"[CSV] Rapport exporte: {output_path}")


def reload_services():
    """Recharge Apache et PHP-FPM."""
    print("[RELOAD] Rechargement des services...")
    subprocess.run(["systemctl", "reload", "php8.3-fpm"], check=True)
    subprocess.run(["systemctl", "reload", "apache2"], check=True)
    print("[OK] Services recharges")


def main():
    parser = argparse.ArgumentParser(
        description="Deploie les instances SecuLab CTF"
    )
    parser.add_argument("--count", type=int, required=True, 
                        help="Nombre d'instances a creer")
    parser.add_argument("--domain", default=DEFAULT_DOMAIN,
                        help=f"Domaine de base (defaut: {DEFAULT_DOMAIN})")
    parser.add_argument("--repo", default=DEFAULT_REPO,
                        help="URL du depot seculab-app")
    parser.add_argument("--gemini-key", default="",
                        help="Cle API Gemini (ou via .env.master)")
    parser.add_argument("--output", default="instances_report.csv",
                        help="Fichier CSV de sortie")
    
    args = parser.parse_args()
    
    check_root()
    
    print("=" * 50)
    print("SecuLab CTF - Deploiement des Instances")
    print("=" * 50)
    print(f"[INFO] Nombre d'instances: {args.count}")
    print(f"[INFO] Domaine: *.{args.domain}")
    print()
    
    # Recuperer la cle Gemini
    gemini_key = args.gemini_key
    if not gemini_key and ENV_EXAMPLE_PATH.exists():
        with open(ENV_EXAMPLE_PATH) as f:
            for line in f:
                if line.startswith("GEMINI_API_KEY="):
                    gemini_key = line.split("=", 1)[1].strip()
                    break
    
    if not gemini_key:
        print("[WARN] Cle API Gemini non fournie. Le module SecuBot ne fonctionnera pas.")
    
    # Creer le repertoire principal
    INSTANCES_DIR.mkdir(parents=True, exist_ok=True)
    
    # Deployer les instances
    instances = []
    for i in range(args.count):
        instance_uuid = generate_uuid()
        print(f"\n[{i+1}/{args.count}] Instance {instance_uuid}")
        
        result = deploy_instance(
            instance_uuid, args.domain, args.repo, gemini_key
        )
        instances.append(result)
    
    # Recharger les services
    print()
    reload_services()
    
    # Exporter le CSV
    export_csv(instances, Path(args.output))
    
    print("\n" + "=" * 50)
    print("[DONE] Deploiement termine!")
    print("=" * 50)
    print(f"\n[OK] {len([i for i in instances if i])} instances creees")
    print(f"[CSV] Rapport: {args.output}")
    print(f"\n[INFO] N'oubliez pas de configurer le DNS wildcard *.{args.domain}")


if __name__ == "__main__":
    main()
