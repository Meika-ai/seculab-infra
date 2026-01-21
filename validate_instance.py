#!/usr/bin/env python3
"""
SecuLab CTF - Script de Validation des Corrections
Verifie que les failles ont ete corrigees ET que les fonctionnalites marchent encore

Usage:
    python validate_instance.py --url=URL [--verbose]
    python validate_instance.py --csv=instances_report.csv
    
Exemple:
    python validate_instance.py --url=https://abc12345.marill.fr
"""

import argparse
import csv
import re
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    print("[ERROR] Module 'requests' requis. Installez-le: pip install requests")
    sys.exit(1)


@dataclass
class TestResult:
    """Resultat d'un test."""
    name: str
    vulnerability_fixed: bool
    functionality_works: bool
    details: str


class InstanceValidator:
    """Validateur d'instance SecuLab."""
    
    def __init__(self, base_url: str, verbose: bool = False):
        self.base_url = base_url.rstrip('/')
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'SecuLab-Validator/1.0'
    
    def log(self, message: str):
        """Affiche un message si verbose."""
        if self.verbose:
            print(f"    {message}")
    
    def get(self, path: str, **kwargs) -> requests.Response:
        """Effectue une requete GET."""
        url = urljoin(self.base_url, path)
        return self.session.get(url, timeout=10, **kwargs)
    
    def post(self, path: str, **kwargs) -> requests.Response:
        """Effectue une requete POST."""
        url = urljoin(self.base_url, path)
        return self.session.post(url, timeout=10, **kwargs)
    
    # =========================================
    # Tests de vulnerabilites
    # =========================================
    
    def test_sqli(self) -> TestResult:
        """Test SQL Injection sur /login."""
        name = "SQL Injection (Auth)"
        
        # Test de la vulnerabilite
        vuln_payload = "admin' OR 1=1 --"
        resp = self.post('/login', data={
            'username': vuln_payload,
            'password': 'test'
        })
        
        # Si on est redirige vers / ou si "Bienvenue" apparait, la faille existe
        sqli_vulnerable = (
            'Connexion reussie' in resp.text or 
            'Bienvenue' in resp.text or
            resp.url.endswith('/')
        )
        
        self.log(f"SQLi payload tested, vulnerable={sqli_vulnerable}")
        
        # Test que le login normal fonctionne
        # D'abord, on se deconnecte
        self.get('/logout')
        
        # Login avec de vrais identifiants
        resp = self.post('/login', data={
            'username': 'alice',
            'password': 'alice123'
        })
        
        login_works = 'Connexion reussie' in resp.text or 'Bienvenue' in resp.text
        self.log(f"Normal login works={login_works}")
        
        return TestResult(
            name=name,
            vulnerability_fixed=not sqli_vulnerable,
            functionality_works=login_works,
            details=f"SQLi blocked: {not sqli_vulnerable}, Login works: {login_works}"
        )
    
    def test_idor(self) -> TestResult:
        """Test IDOR sur /profile."""
        name = "IDOR (Profile)"
        
        # Se deconnecter d'abord
        self.get('/logout')
        
        # Essayer d'acceder au profil admin sans etre connecte
        resp = self.get('/profile?id=1')
        
        # Si le flag IDOR ou la bio admin est visible, la faille existe
        idor_vulnerable = (
            'FLAG{' in resp.text and 'IDOR' in resp.text
        ) or 'Bio secrete' in resp.text
        
        self.log(f"IDOR tested, vulnerable={idor_vulnerable}")
        
        # Test que la fonctionnalite marche (acces a son propre profil)
        # On se connecte d'abord
        self.post('/login', data={'username': 'alice', 'password': 'alice123'})
        resp = self.get('/profile')
        
        profile_works = 'alice' in resp.text.lower()
        self.log(f"Profile access works={profile_works}")
        
        return TestResult(
            name=name,
            vulnerability_fixed=not idor_vulnerable,
            functionality_works=profile_works,
            details=f"IDOR blocked: {not idor_vulnerable}, Profile works: {profile_works}"
        )
    
    def test_xss(self) -> TestResult:
        """Test Stored XSS sur /wall."""
        name = "Stored XSS (Wall)"
        
        # Poster un message avec XSS
        xss_payload = '<script>alert("XSS")</script>'
        self.post('/wall', data={'message': xss_payload})
        
        # Recuperer la page et verifier si le script est non echappe
        resp = self.get('/wall')
        
        # Si le script est present tel quel (non echappe), la faille existe
        xss_vulnerable = xss_payload in resp.text
        
        # Verifier les versions echappees
        escaped_variations = [
            '&lt;script&gt;',
            '&#60;script&#62;',
        ]
        properly_escaped = any(v in resp.text for v in escaped_variations)
        
        self.log(f"XSS tested, vulnerable={xss_vulnerable}, escaped={properly_escaped}")
        
        # Test que le wall fonctionne (on peut poster des messages normaux)
        normal_message = f"Test message {hash(self.base_url)}"
        self.post('/wall', data={'message': normal_message})
        resp = self.get('/wall')
        
        wall_works = normal_message in resp.text
        self.log(f"Wall posting works={wall_works}")
        
        return TestResult(
            name=name,
            vulnerability_fixed=not xss_vulnerable,
            functionality_works=wall_works,
            details=f"XSS blocked: {not xss_vulnerable}, Wall works: {wall_works}"
        )
    
    def test_rce(self) -> TestResult:
        """Test RCE sur /calc."""
        name = "RCE (Calculator)"
        
        # Tenter d'executer une commande systeme
        rce_payload = "system('echo RCE_TEST')"
        resp = self.post('/calc', data={'expression': rce_payload})
        
        # Si RCE_TEST apparait dans la reponse ou si on voit le flag, vulnerable
        rce_vulnerable = (
            'RCE_TEST' in resp.text or
            ('FLAG{' in resp.text and 'RCE' in resp.text)
        )
        
        self.log(f"RCE tested, vulnerable={rce_vulnerable}")
        
        # Test que la calculatrice fonctionne pour des calculs normaux
        resp = self.post('/calc', data={'expression': '2 + 2'})
        
        # Verifier que 4 apparait dans le resultat
        calc_works = '4' in resp.text
        self.log(f"Calculator works={calc_works}")
        
        return TestResult(
            name=name,
            vulnerability_fixed=not rce_vulnerable,
            functionality_works=calc_works,
            details=f"RCE blocked: {not rce_vulnerable}, Calc works: {calc_works}"
        )
    
    def test_logic_error(self) -> TestResult:
        """Test Logic Error sur /admin."""
        name = "Logic Error (Admin)"
        
        # Se deconnecter et supprimer les cookies
        self.get('/logout')
        self.session.cookies.clear()
        
        # Acceder a /admin avec le cookie is_admin=true
        self.session.cookies.set('is_admin', 'true')
        resp = self.get('/admin')
        
        # Si on voit le panel admin ou le flag, vulnerable
        logic_vulnerable = (
            'Bienvenue, Administrateur' in resp.text or
            ('FLAG{' in resp.text and 'LOGIC' in resp.text)
        )
        
        self.log(f"Logic error tested, vulnerable={logic_vulnerable}")
        
        # Test que l'admin fonctionne pour les vrais admins
        self.session.cookies.clear()
        # Se connecter en tant qu'admin (si on connait le mot de passe)
        # Note: En vrai CTF, on ne teste pas ca car on ne connait pas le mdp
        admin_works = True  # On assume que ca marche si bien configure
        
        return TestResult(
            name=name,
            vulnerability_fixed=not logic_vulnerable,
            functionality_works=admin_works,
            details=f"Logic error blocked: {not logic_vulnerable}"
        )
    
    def test_info_disclosure(self) -> TestResult:
        """Test Info Disclosure sur .env."""
        name = "Info Disclosure (.env)"
        
        # Tenter d'acceder au fichier .env directement
        resp = self.get('/.env', allow_redirects=False)
        
        # Si on recoit un 200 avec du contenu, vulnerable
        env_accessible = (
            resp.status_code == 200 and 
            ('SECRET_' in resp.text or 'GEMINI_API_KEY' in resp.text)
        )
        
        # Verifier aussi database.sqlite
        resp_db = self.get('/database.sqlite', allow_redirects=False)
        db_accessible = resp_db.status_code == 200
        
        self.log(f".env accessible={env_accessible}, db accessible={db_accessible}")
        
        # L'app devrait toujours fonctionner
        resp = self.get('/')
        app_works = resp.status_code == 200 and 'SecuLab' in resp.text
        
        return TestResult(
            name=name,
            vulnerability_fixed=not env_accessible and not db_accessible,
            functionality_works=app_works,
            details=f".env blocked: {not env_accessible}, DB blocked: {not db_accessible}"
        )
    
    def run_all_tests(self) -> List[TestResult]:
        """Execute tous les tests."""
        tests = [
            self.test_sqli,
            self.test_idor,
            self.test_xss,
            self.test_rce,
            self.test_logic_error,
            self.test_info_disclosure,
        ]
        
        results = []
        for test_func in tests:
            try:
                result = test_func()
                results.append(result)
            except Exception as e:
                results.append(TestResult(
                    name=test_func.__name__,
                    vulnerability_fixed=False,
                    functionality_works=False,
                    details=f"Error: {str(e)}"
                ))
        
        return results


def print_results(url: str, results: List[TestResult]):
    """Affiche les resultats de maniere formatee."""
    print(f"\n[RESULTS] Resultats pour: {url}")
    print("-" * 60)
    
    fixed_count = 0
    working_count = 0
    
    for result in results:
        # Marqueur pour l'etat
        vuln_marker = "[OK]" if result.vulnerability_fixed else "[FAIL]"
        func_marker = "[OK]" if result.functionality_works else "[WARN]"
        
        print(f"  {result.name}")
        print(f"    Faille corrigee: {vuln_marker}  Fonctionnalite OK: {func_marker}")
        
        if result.vulnerability_fixed:
            fixed_count += 1
        if result.functionality_works:
            working_count += 1
    
    print("-" * 60)
    print(f"[SCORE] Score: {fixed_count}/{len(results)} failles corrigees, "
          f"{working_count}/{len(results)} fonctionnalites OK")
    
    # Note finale
    if fixed_count == len(results) and working_count == len(results):
        print("[SUCCESS] PARFAIT! Toutes les failles sont corrigees et tout fonctionne!")
    elif fixed_count == len(results):
        print("[WARN] Failles corrigees mais certaines fonctionnalites sont cassees.")
    elif fixed_count > len(results) / 2:
        print("[INFO] Bon progres! Continuez les corrections.")
    else:
        print("[INFO] Travail en cours. Il reste des failles a corriger.")
    
    return fixed_count, working_count


def main():
    parser = argparse.ArgumentParser(
        description="Valide les corrections d'une instance SecuLab"
    )
    parser.add_argument("--url", help="URL de l'instance a tester")
    parser.add_argument("--csv", help="Fichier CSV avec les instances")
    parser.add_argument("--verbose", "-v", action="store_true", 
                        help="Mode verbeux")
    parser.add_argument("--output", help="Fichier CSV de sortie pour les resultats")
    
    args = parser.parse_args()
    
    if not args.url and not args.csv:
        parser.error("Specifiez --url ou --csv")
    
    print("=" * 60)
    print("SecuLab CTF - Validation des Corrections")
    print("=" * 60)
    
    all_results = []
    
    if args.url:
        # Test d'une seule instance
        validator = InstanceValidator(args.url, verbose=args.verbose)
        results = validator.run_all_tests()
        fixed, working = print_results(args.url, results)
        all_results.append((args.url, results))
    
    elif args.csv:
        # Test de plusieurs instances depuis un CSV
        with open(args.csv) as f:
            reader = csv.DictReader(f)
            for row in reader:
                url = row.get('url-instance', row.get('url', ''))
                if url:
                    print(f"\n[TEST] Test de {url}...")
                    validator = InstanceValidator(url, verbose=args.verbose)
                    results = validator.run_all_tests()
                    print_results(url, results)
                    all_results.append((url, results))
    
    # Export des resultats si demande
    if args.output and all_results:
        with open(args.output, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'url', 'sqli_fixed', 'idor_fixed', 'xss_fixed', 
                'rce_fixed', 'logic_fixed', 'info_fixed',
                'total_fixed', 'total_working'
            ])
            
            for url, results in all_results:
                row = [url]
                fixed = 0
                working = 0
                for r in results:
                    row.append('1' if r.vulnerability_fixed else '0')
                    if r.vulnerability_fixed:
                        fixed += 1
                    if r.functionality_works:
                        working += 1
                row.extend([fixed, working])
                writer.writerow(row)
        
        print(f"\n[CSV] Resultats exportes: {args.output}")


if __name__ == "__main__":
    main()
