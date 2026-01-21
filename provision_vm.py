#!/usr/bin/env python3
"""
SecuLab CTF - Script de Provisioning GCP
Cree une VM Ubuntu 24.04 sur Google Cloud Platform

Usage:
    python provision_vm.py --project=PROJECT_ID --zone=ZONE [--name=VM_NAME]
    
Exemple:
    python provision_vm.py --project=my-gcp-project --zone=europe-west1-b
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path

# Configuration par defaut
DEFAULT_VM_NAME = "seculab-ctf"
DEFAULT_MACHINE_TYPE = "e2-medium"
DEFAULT_DISK_SIZE = "50GB"
DEFAULT_IMAGE_FAMILY = "ubuntu-2404-lts-amd64"
DEFAULT_IMAGE_PROJECT = "ubuntu-os-cloud"


def get_gcloud_cmd():
    """Retourne la commande gcloud adaptee au systeme."""
    if sys.platform == "win32":
        return "gcloud.cmd"
    return "gcloud"


def run_command(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    """Execute une commande shell et retourne le resultat."""
    # Sur Windows, remplacer gcloud par gcloud.cmd
    if sys.platform == "win32" and cmd and cmd[0] == "gcloud":
        cmd = [get_gcloud_cmd()] + cmd[1:]
    
    print(f"[RUN] {' '.join(cmd)}")
    # Sur Windows, utiliser shell=True pour les commandes .cmd
    use_shell = sys.platform == "win32"
    result = subprocess.run(cmd, capture_output=True, text=True, shell=use_shell)
    if check and result.returncode != 0:
        print(f"[ERROR] {result.stderr}")
        sys.exit(1)
    return result


def check_gcloud_installed():
    """Verifie que gcloud CLI est installe."""
    gcloud = get_gcloud_cmd()
    use_shell = sys.platform == "win32"
    try:
        result = subprocess.run([gcloud, "--version"], capture_output=True, shell=use_shell)
        if result.returncode != 0:
            raise FileNotFoundError()
    except FileNotFoundError:
        print("[ERROR] gcloud CLI n'est pas installe.")
        print("[INFO] Installez-le depuis: https://cloud.google.com/sdk/docs/install")
        sys.exit(1)
    print("[OK] gcloud CLI detecte")


def check_authentication():
    """Verifie que l'utilisateur est authentifie."""
    gcloud = get_gcloud_cmd()
    use_shell = sys.platform == "win32"
    result = subprocess.run(
        [gcloud, "auth", "list", "--filter=status:ACTIVE", "--format=value(account)"],
        capture_output=True, text=True, shell=use_shell
    )
    if not result.stdout.strip():
        print("[ERROR] Vous n'etes pas authentifie.")
        print("[INFO] Executez: gcloud auth login")
        sys.exit(1)
    print(f"[OK] Authentifie en tant que: {result.stdout.strip()}")


def create_startup_script() -> str:
    """Genere le script de demarrage pour la VM."""
    return '''#!/bin/bash
set -e

# Mise a jour du systeme
apt-get update && apt-get upgrade -y

# Installation des paquets necessaires
apt-get install -y \\
    apache2 \\
    php8.3 \\
    php8.3-fpm \\
    php8.3-sqlite3 \\
    php8.3-curl \\
    php8.3-mbstring \\
    libapache2-mod-fcgid \\
    sqlite3 \\
    git \\
    ufw \\
    certbot \\
    python3-certbot-apache

# Activation des modules Apache
a2enmod proxy_fcgi setenvif rewrite headers ssl
a2enconf php8.3-fpm

# Configuration UFW (pare-feu)
ufw default deny incoming
ufw default deny outgoing
ufw allow 22/tcp        # SSH
ufw allow 80/tcp        # HTTP
ufw allow 443/tcp       # HTTPS
# Autoriser l'API Gemini (Google)
ufw allow out to 142.250.0.0/15 port 443
ufw allow out to 172.217.0.0/16 port 443
ufw allow out to 216.58.0.0/16 port 443
# Autoriser DNS pour resolution
ufw allow out 53/udp
ufw allow out 53/tcp
ufw --force enable

# Creation du repertoire pour les instances
mkdir -p /var/www/instances
chown www-data:www-data /var/www/instances

# Desactivation du site par defaut
a2dissite 000-default

# Creer un lien symbolique pour rbash si necessaire
if [ ! -f /bin/rbash ]; then
    ln -s /bin/bash /bin/rbash
fi

# Redemarrage des services
systemctl restart apache2
systemctl restart php8.3-fpm

echo "[OK] SecuLab VM provisionnee avec succes!"
'''


def create_firewall_rules(project: str):
    """Cree les regles de pare-feu GCP."""
    print("[FIREWALL] Configuration des regles de pare-feu...")
    
    rules = [
        {
            "name": "seculab-allow-http",
            "allow": "tcp:80",
            "description": "Allow HTTP traffic"
        },
        {
            "name": "seculab-allow-https", 
            "allow": "tcp:443",
            "description": "Allow HTTPS traffic"
        },
        {
            "name": "seculab-allow-ssh",
            "allow": "tcp:22",
            "description": "Allow SSH traffic"
        }
    ]
    
    for rule in rules:
        # Verifier si la regle existe deja
        check = run_command([
            "gcloud", "compute", "firewall-rules", "describe",
            rule["name"], f"--project={project}"
        ], check=False)
        
        if check.returncode == 0:
            print(f"  [SKIP] Regle {rule['name']} existe deja")
            continue
            
        # Creer la regle
        run_command([
            "gcloud", "compute", "firewall-rules", "create",
            rule["name"],
            f"--project={project}",
            f"--allow={rule['allow']}",
            "--network=default",
            "--target-tags=seculab",
            f"--description={rule['description']}"
        ])
        print(f"  [OK] Regle {rule['name']} creee")


def create_vm(project: str, zone: str, name: str):
    """Cree la VM sur GCP."""
    print(f"[VM] Creation de la VM {name}...")
    
    # Sauvegarder le script de demarrage
    startup_script = create_startup_script()
    script_path = Path("/tmp/seculab-startup.sh")
    script_path.write_text(startup_script)
    
    # Creer la VM
    run_command([
        "gcloud", "compute", "instances", "create", name,
        f"--project={project}",
        f"--zone={zone}",
        f"--machine-type={DEFAULT_MACHINE_TYPE}",
        f"--boot-disk-size={DEFAULT_DISK_SIZE}",
        f"--image-family={DEFAULT_IMAGE_FAMILY}",
        f"--image-project={DEFAULT_IMAGE_PROJECT}",
        f"--metadata-from-file=startup-script={script_path}",
        "--tags=seculab,http-server,https-server",
        "--scopes=default"
    ])
    
    print(f"[OK] VM {name} creee avec succes!")
    
    # Recuperer l'IP externe
    result = run_command([
        "gcloud", "compute", "instances", "describe", name,
        f"--project={project}",
        f"--zone={zone}",
        "--format=get(networkInterfaces[0].accessConfigs[0].natIP)"
    ])
    
    external_ip = result.stdout.strip()
    print(f"[IP] IP externe: {external_ip}")
    
    return external_ip


def main():
    parser = argparse.ArgumentParser(
        description="Provision une VM GCP pour SecuLab CTF"
    )
    parser.add_argument("--project", required=True, help="ID du projet GCP")
    parser.add_argument("--zone", required=True, help="Zone GCP (ex: europe-west1-b)")
    parser.add_argument("--name", default=DEFAULT_VM_NAME, help=f"Nom de la VM (defaut: {DEFAULT_VM_NAME})")
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("SecuLab CTF - Provisioning GCP")
    print("=" * 50)
    
    # Verifications
    check_gcloud_installed()
    check_authentication()
    
    # Creer les regles de pare-feu
    create_firewall_rules(args.project)
    
    # Creer la VM
    external_ip = create_vm(args.project, args.zone, args.name)
    
    print("\n" + "=" * 50)
    print("[DONE] Provisioning termine!")
    print("=" * 50)
    print(f"\n[NEXT] Prochaines etapes:")
    print(f"1. Attendez 2-3 minutes que le startup script s'execute")
    print(f"2. Connectez-vous: gcloud compute ssh {args.name} --zone={args.zone}")
    print(f"3. Verifiez l'installation: sudo systemctl status apache2 php8.3-fpm")
    print(f"4. Copiez le depot seculab-infra sur la VM")
    print(f"5. Lancez: sudo python3 deploy_lab.py --count=N")
    print(f"\n[DNS] Configurez votre DNS *.marill.fr vers: {external_ip}")


if __name__ == "__main__":
    main()
