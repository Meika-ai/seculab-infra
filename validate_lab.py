#!/usr/bin/env python3
"""
SecuLab CTF - Script de Validation des Corrections
Analyse le code des instances pour vérifier si les failles ont été corrigées.

Usage:
    python validate_lab.py --instance=UUID          # Valider une instance
    python validate_lab.py --csv=instances.csv      # Valider toutes les instances
"""

import argparse
import csv
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Configuration
INSTANCES_DIR = Path("/var/www/instances")

# Pondération des failles (total = 100)
WEIGHTS = {
    'sqli': 20,      # SQL Injection - Critique
    'rce': 20,       # Remote Code Execution - Critique
    'idor': 15,      # Insecure Direct Object Reference
    'xss': 15,       # Cross-Site Scripting
    'logic': 10,     # Logic Error
    'debug': 10,     # Information Disclosure
    'prompt': 10,    # Prompt Injection
}


class VulnerabilityChecker:
    """Vérifie si les failles de sécurité ont été corrigées."""
    
    def __init__(self, instance_path: Path, verbose: bool = False):
        self.instance_path = instance_path
        self.verbose = verbose
        self.modules_path = instance_path / "modules"
    
    def _read_file(self, filename: str) -> Optional[str]:
        """Lit le contenu d'un fichier module."""
        filepath = self.modules_path / filename
        if filepath.exists():
            return filepath.read_text(encoding='utf-8', errors='ignore')
        return None
    
    def _log(self, message: str):
        """Affiche un message si mode verbose."""
        if self.verbose:
            print(f"    [DEBUG] {message}")
    
    def check_sqli(self) -> Dict:
        """
        Vérifie SQL Injection dans auth.php
        VULNÉRABLE: Concaténation de variables dans la query
        SÉCURISÉ: Utilisation de prepare() avec execute()
        """
        content = self._read_file("auth.php")
        if not content:
            return self._no_file_result("auth.php")
        
        evidence = []
        is_fixed = True
        details = ""
        
        # Patterns vulnérables
        vuln_patterns = [
            (r'\$db->query\s*\([^)]*\$username', "Query avec variable $username directe"),
            (r"'\s*\.\s*\$username", "Concaténation de $username"),
            (r'\$username\s*\.\s*[\'"]', "Concaténation de $username"),
            (r"WHERE\s+username\s*=\s*'\$", "Variable dans clause WHERE"),
        ]
        
        for pattern, desc in vuln_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                is_fixed = False
                evidence.append(f"Pattern vulnérable trouvé: {desc}")
                self._log(f"SQLI vulnérable: {desc}")
        
        # Patterns sécurisés attendus
        has_prepare = bool(re.search(r'\$db->prepare\s*\(', content))
        has_execute = bool(re.search(r'->execute\s*\(\s*\[', content))
        
        if has_prepare and has_execute:
            evidence.append("Utilisation de prepare/execute détectée")
            if is_fixed:
                details = "Requêtes préparées correctement implémentées"
        else:
            if is_fixed:
                # Pas de pattern vulnérable mais pas de prepare non plus = suspect
                is_fixed = False
                evidence.append("Pas de prepare/execute trouvé")
                details = "Méthode de sécurisation non reconnue"
        
        if not is_fixed:
            details = "Injection SQL toujours possible via concaténation"
        
        return {
            'fixed': is_fixed,
            'weight': WEIGHTS['sqli'],
            'points': WEIGHTS['sqli'] if is_fixed else 0,
            'details': details,
            'evidence': evidence
        }
    
    def check_idor(self) -> Dict:
        """
        Vérifie IDOR dans profile.php
        VULNÉRABLE: Pas de vérification que l'utilisateur peut voir ce profil
        SÉCURISÉ: Check $_SESSION['user_id'] == $requestedId
        """
        content = self._read_file("profile.php")
        if not content:
            return self._no_file_result("profile.php")
        
        evidence = []
        is_fixed = False
        details = ""
        
        # Patterns de sécurisation attendus
        secure_patterns = [
            (r'\$_SESSION\s*\[\s*[\'"]user_id[\'"]\s*\]\s*==\s*\$requestedId', "Check session user_id == requestedId"),
            (r'\$_SESSION\s*\[\s*[\'"]user_id[\'"]\s*\]\s*===\s*\$requestedId', "Check strict session"),
            (r'if\s*\(\s*!\s*\$isOwnProfile\s*\)', "Vérification isOwnProfile"),
            (r'if\s*\(\s*\$requestedId\s*!==?\s*\$_SESSION', "Comparaison ID avec session"),
            # Si l'accès est restreint au profil propre uniquement
            (r'header\s*\(\s*[\'"]Location.*\$_SESSION\s*\[\s*[\'"]user_id', "Redirection vers profil propre"),
        ]
        
        for pattern, desc in secure_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                is_fixed = True
                evidence.append(f"Protection trouvée: {desc}")
                self._log(f"IDOR protégé: {desc}")
                break
        
        # Vérifier si le module refuse l'accès aux autres profils
        if re.search(r'(Accès\s+(refusé|interdit)|forbidden|unauthorized)', content, re.IGNORECASE):
            evidence.append("Message d'erreur d'accès détecté")
            is_fixed = True
        
        if is_fixed:
            details = "Vérification d'autorisation implémentée"
        else:
            details = "Accès direct aux profils sans vérification d'autorisation"
            evidence.append("Aucune vérification d'autorisation trouvée")
        
        return {
            'fixed': is_fixed,
            'weight': WEIGHTS['idor'],
            'points': WEIGHTS['idor'] if is_fixed else 0,
            'details': details,
            'evidence': evidence
        }
    
    def check_xss(self) -> Dict:
        """
        Vérifie XSS stocké dans wall.php
        VULNÉRABLE: Echo du contenu sans échappement
        SÉCURISÉ: htmlspecialchars() ou strip_tags()
        """
        content = self._read_file("wall.php")
        if not content:
            return self._no_file_result("wall.php")
        
        evidence = []
        is_fixed = True
        details = ""
        
        # Chercher l'affichage du contenu des posts
        # Pattern vulnérable : <?= $post['content'] ?> ou echo $post['content']
        vuln_patterns = [
            (r'<\?=\s*\$post\s*\[\s*[\'"]content[\'"]\s*\]', "Affichage direct du contenu"),
            (r'echo\s+\$post\s*\[\s*[\'"]content[\'"]\s*\]', "Echo direct du contenu"),
            (r'<\?=\s*\$message\s*\?>', "Affichage direct de $message"),
        ]
        
        # Pattern sécurisé : htmlspecialchars($post['content'])
        secure_patterns = [
            (r'htmlspecialchars\s*\(\s*\$post\s*\[\s*[\'"]content[\'"]\s*\]', "htmlspecialchars sur content"),
            (r'strip_tags\s*\(\s*\$post\s*\[\s*[\'"]content[\'"]\s*\]', "strip_tags sur content"),
            (r'htmlentities\s*\(\s*\$post\s*\[\s*[\'"]content[\'"]\s*\]', "htmlentities sur content"),
        ]
        
        # Vérifier la présence de patterns sécurisés
        has_secure = False
        for pattern, desc in secure_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                has_secure = True
                evidence.append(f"Échappement trouvé: {desc}")
                self._log(f"XSS protégé: {desc}")
                break
        
        # Vérifier la présence de patterns vulnérables
        for pattern, desc in vuln_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                if not has_secure:
                    is_fixed = False
                    evidence.append(f"Pattern vulnérable: {desc}")
                    self._log(f"XSS vulnérable: {desc}")
        
        if has_secure:
            is_fixed = True
            details = "Contenu correctement échappé avant affichage"
        elif not is_fixed:
            details = "Contenu affiché sans échappement HTML"
        else:
            # Pas de pattern vulnérable ni sécurisé trouvé
            details = "Structure de code modifiée - vérification manuelle recommandée"
            evidence.append("Patterns attendus non trouvés")
        
        return {
            'fixed': is_fixed,
            'weight': WEIGHTS['xss'],
            'points': WEIGHTS['xss'] if is_fixed else 0,
            'details': details,
            'evidence': evidence
        }
    
    def check_rce(self) -> Dict:
        """
        Vérifie RCE dans calc.php
        VULNÉRABLE: Présence de eval() sur entrée utilisateur
        SÉCURISÉ: Suppression de eval() ou whitelist stricte
        """
        content = self._read_file("calc.php")
        if not content:
            return self._no_file_result("calc.php")
        
        evidence = []
        is_fixed = True
        details = ""
        
        # Pattern vulnérable : eval() présent
        if re.search(r'\beval\s*\(', content):
            # Vérifier si c'est dans un commentaire
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if re.search(r'\beval\s*\(', line):
                    # Ignorer les lignes commentées
                    stripped = line.strip()
                    if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                        evidence.append(f"Ligne {i+1}: eval() commenté (OK)")
                        continue
                    is_fixed = False
                    evidence.append(f"Ligne {i+1}: eval() actif détecté")
                    self._log(f"RCE vulnérable: eval() trouvé ligne {i+1}")
        
        # Alternatives sécurisées
        secure_alternatives = [
            (r'preg_match\s*\(\s*[\'"][^\']*\d.*[\'"]', "Validation par regex stricte"),
            (r'(bc_add|bc_sub|bc_mul|bc_div)', "Utilisation de fonctions bc_*"),
            (r'filter_var\s*\(.*FILTER_(VALIDATE|SANITIZE)', "Utilisation de filter_var"),
        ]
        
        for pattern, desc in secure_alternatives:
            if re.search(pattern, content):
                evidence.append(f"Alternative sécurisée: {desc}")
        
        if is_fixed:
            details = "eval() supprimé ou neutralisé"
        else:
            details = "eval() toujours actif - RCE possible"
        
        return {
            'fixed': is_fixed,
            'weight': WEIGHTS['rce'],
            'points': WEIGHTS['rce'] if is_fixed else 0,
            'details': details,
            'evidence': evidence
        }
    
    def check_logic(self) -> Dict:
        """
        Vérifie Logic Error dans admin.php
        VULNÉRABLE: Vérification via cookie ou champ caché
        SÉCURISÉ: Vérification via $_SESSION['is_admin']
        """
        content = self._read_file("admin.php")
        if not content:
            return self._no_file_result("admin.php")
        
        evidence = []
        is_fixed = True
        details = ""
        
        # Patterns vulnérables
        vuln_patterns = [
            (r'\$_COOKIE\s*\[\s*[\'"]is_admin[\'"]\s*\]', "Vérification via cookie is_admin"),
            (r'\$_POST\s*\[\s*[\'"]admin_check[\'"]\s*\]', "Vérification via POST admin_check"),
        ]
        
        for pattern, desc in vuln_patterns:
            if re.search(pattern, content):
                # Vérifier si c'est commenté
                lines = content.split('\n')
                for line in lines:
                    if re.search(pattern, line) and not line.strip().startswith('//'):
                        is_fixed = False
                        evidence.append(f"Pattern vulnérable: {desc}")
                        self._log(f"LOGIC vulnérable: {desc}")
                        break
        
        # Pattern sécurisé attendu
        secure_patterns = [
            (r'\$_SESSION\s*\[\s*[\'"]is_admin[\'"]\s*\]\s*===?\s*1', "Check session is_admin === 1"),
            (r'isLoggedIn\s*\(\s*\)\s*&&\s*\$_SESSION\s*\[\s*[\'"]is_admin[\'"]\s*\]', "isLoggedIn + check admin"),
        ]
        
        has_secure = False
        for pattern, desc in secure_patterns:
            if re.search(pattern, content):
                has_secure = True
                evidence.append(f"Protection trouvée: {desc}")
                self._log(f"LOGIC protégé: {desc}")
        
        if has_secure and is_fixed:
            details = "Vérification admin correctement implémentée via session"
        elif is_fixed:
            details = "Vérifications client-side retirées"
        else:
            details = "Vérification admin basée sur données client (cookie/POST)"
        
        return {
            'fixed': is_fixed,
            'weight': WEIGHTS['logic'],
            'points': WEIGHTS['logic'] if is_fixed else 0,
            'details': details,
            'evidence': evidence
        }
    
    def check_debug(self) -> Dict:
        """
        Vérifie Information Disclosure dans debug.php
        VULNÉRABLE: Header X-Debug-Flag avec le secret
        SÉCURISÉ: Header supprimé ou module désactivé
        """
        content = self._read_file("debug.php")
        
        # Si le fichier est supprimé, c'est considéré comme sécurisé
        if not content:
            return {
                'fixed': True,
                'weight': WEIGHTS['debug'],
                'points': WEIGHTS['debug'],
                'details': "Module debug.php supprimé",
                'evidence': ["Fichier non trouvé - probablement supprimé"]
            }
        
        evidence = []
        is_fixed = True
        details = ""
        
        # Pattern vulnérable
        vuln_pattern = r"header\s*\(\s*['\"]X-Debug-Flag"
        
        if re.search(vuln_pattern, content, re.IGNORECASE):
            # Vérifier si c'est commenté
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if re.search(vuln_pattern, line, re.IGNORECASE):
                    if line.strip().startswith('//') or line.strip().startswith('/*'):
                        evidence.append(f"Ligne {i+1}: Header commenté (OK)")
                    else:
                        is_fixed = False
                        evidence.append(f"Ligne {i+1}: Header X-Debug-Flag actif")
                        self._log(f"DEBUG vulnérable: header trouvé ligne {i+1}")
        
        # Autres headers sensibles à vérifier
        other_headers = [
            (r"header\s*\(\s*['\"]X-Powered-By", "X-Powered-By exposé"),
            (r"header\s*\(\s*['\"]X-Server-Mode.*development", "Mode development exposé"),
        ]
        
        for pattern, desc in other_headers:
            if re.search(pattern, content, re.IGNORECASE):
                evidence.append(f"Avertissement: {desc}")
        
        if is_fixed:
            details = "Headers sensibles supprimés ou commentés"
        else:
            details = "Header X-Debug-Flag expose le secret"
        
        return {
            'fixed': is_fixed,
            'weight': WEIGHTS['debug'],
            'points': WEIGHTS['debug'] if is_fixed else 0,
            'details': details,
            'evidence': evidence
        }
    
    def check_prompt(self) -> Dict:
        """
        Vérifie Prompt Injection dans secubot.php
        VULNÉRABLE: Secret dans le system prompt
        SÉCURISÉ: Secret retiré ou validation robuste
        """
        content = self._read_file("secubot.php")
        if not content:
            return {
                'fixed': True,
                'weight': WEIGHTS['prompt'],
                'points': WEIGHTS['prompt'],
                'details': "Module secubot.php supprimé",
                'evidence': ["Fichier non trouvé - probablement supprimé"]
            }
        
        evidence = []
        is_fixed = True
        details = ""
        
        # Pattern vulnérable : secret dans le prompt
        vuln_patterns = [
            (r'SECRET_PROMPT_INJECTION', "Constante SECRET_PROMPT_INJECTION utilisée"),
            (r'\$systemPrompt.*secret', "Mot 'secret' dans systemPrompt"),
            (r'code\s+secret.*est\s*:', "Révélation du code dans le prompt"),
        ]
        
        for pattern, desc in vuln_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                # Vérifier si c'est dans le prompt actif (pas commenté)
                is_fixed = False
                evidence.append(f"Pattern vulnérable: {desc}")
                self._log(f"PROMPT vulnérable: {desc}")
        
        # Vérifications de sécurité alternatives
        secure_patterns = [
            (r'rate.?limit', "Rate limiting détecté"),
            (r'(blacklist|blocklist|forbidden.?words)', "Liste de mots interdits"),
        ]
        
        for pattern, desc in secure_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                evidence.append(f"Protection partielle: {desc}")
        
        if is_fixed:
            details = "Secret retiré du prompt système"
        else:
            details = "Secret toujours présent dans le prompt système"
        
        return {
            'fixed': is_fixed,
            'weight': WEIGHTS['prompt'],
            'points': WEIGHTS['prompt'] if is_fixed else 0,
            'details': details,
            'evidence': evidence
        }
    
    def _no_file_result(self, filename: str) -> Dict:
        """Résultat pour un fichier manquant."""
        return {
            'fixed': False,
            'weight': 0,
            'points': 0,
            'details': f"Fichier {filename} non trouvé",
            'evidence': [f"Le fichier modules/{filename} n'existe pas"]
        }
    
    def run_all_checks(self) -> Dict:
        """Exécute toutes les vérifications."""
        return {
            'sqli': self.check_sqli(),
            'idor': self.check_idor(),
            'xss': self.check_xss(),
            'rce': self.check_rce(),
            'logic': self.check_logic(),
            'debug': self.check_debug(),
            'prompt': self.check_prompt(),
        }


def calculate_score(results: Dict) -> Tuple[float, str]:
    """Calcule le score total et attribue une note."""
    total_points = sum(r['points'] for r in results.values())
    max_points = sum(WEIGHTS.values())
    
    percentage = (total_points / max_points) * 100 if max_points > 0 else 0
    
    # Attribution de la note
    if percentage >= 90:
        grade = "A"
    elif percentage >= 80:
        grade = "B"
    elif percentage >= 70:
        grade = "C"
    elif percentage >= 60:
        grade = "D"
    elif percentage >= 50:
        grade = "E"
    else:
        grade = "F"
    
    return round(percentage, 1), grade


def generate_report(instance_uuid: str, instance_path: Path, 
                   results: Dict, score: float, grade: str) -> Path:
    """Génère le rapport JSON pour une instance."""
    report = {
        'uuid': instance_uuid,
        'validated_at': datetime.now().isoformat(),
        'score': score,
        'max_score': 100,
        'grade': grade,
        'vulnerabilities': results
    }
    
    report_path = instance_path / "validation_report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    
    return report_path


def validate_instance(instance_uuid: str, verbose: bool = False) -> Optional[Dict]:
    """Valide une instance et retourne les résultats."""
    instance_path = INSTANCES_DIR / instance_uuid
    
    if not instance_path.exists():
        print(f"  [ERROR] Instance {instance_uuid} non trouvée")
        return None
    
    print(f"  [CHECK] Validation de {instance_uuid}...")
    
    checker = VulnerabilityChecker(instance_path, verbose)
    results = checker.run_all_checks()
    score, grade = calculate_score(results)
    
    # Générer le rapport
    report_path = generate_report(instance_uuid, instance_path, results, score, grade)
    
    # Afficher le résumé
    fixed_count = sum(1 for r in results.values() if r['fixed'])
    total_count = len(results)
    
    print(f"    Score: {score}% ({grade})")
    print(f"    Failles corrigées: {fixed_count}/{total_count}")
    
    if verbose:
        for vuln_name, result in results.items():
            status = "✅" if result['fixed'] else "❌"
            print(f"      {status} {vuln_name}: {result['details']}")
    
    print(f"    Rapport: {report_path}")
    
    return {
        'uuid': instance_uuid,
        'score': score,
        'grade': grade,
        'results': results
    }


def update_csv(csv_path: Path, scores: Dict[str, float]):
    """Met à jour le CSV avec les scores."""
    if not csv_path.exists():
        print(f"[ERROR] CSV non trouvé: {csv_path}")
        return
    
    # Lire le CSV existant
    rows = []
    fieldnames = []
    
    with open(csv_path, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)
    
    # Ajouter la colonne score si elle n'existe pas
    if 'score' not in fieldnames:
        fieldnames.append('score')
    if 'grade' not in fieldnames:
        fieldnames.append('grade')
    
    # Mettre à jour les scores
    for row in rows:
        uuid = row.get('uuid', '')
        if uuid in scores:
            row['score'] = scores[uuid]['score']
            row['grade'] = scores[uuid]['grade']
    
    # Écrire le CSV mis à jour
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"[CSV] Scores ajoutés à {csv_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Valide les corrections de sécurité des instances SecuLab"
    )
    parser.add_argument("--instance", help="UUID d'une instance à valider")
    parser.add_argument("--csv", help="Chemin du CSV pour validation batch")
    parser.add_argument("--verbose", "-v", action="store_true", 
                       help="Affiche les détails de chaque vérification")
    
    args = parser.parse_args()
    
    if not args.instance and not args.csv:
        parser.print_help()
        sys.exit(1)
    
    print("=" * 50)
    print("SecuLab CTF - Validation des Corrections")
    print("=" * 50)
    
    scores = {}
    
    if args.instance:
        # Validation d'une seule instance
        result = validate_instance(args.instance, args.verbose)
        if result:
            scores[result['uuid']] = {
                'score': result['score'],
                'grade': result['grade']
            }
    
    elif args.csv:
        # Validation batch depuis le CSV
        csv_path = Path(args.csv)
        if not csv_path.exists():
            print(f"[ERROR] CSV non trouvé: {csv_path}")
            sys.exit(1)
        
        with open(csv_path, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            instances = [row['uuid'] for row in reader if 'uuid' in row]
        
        print(f"[INFO] {len(instances)} instances à valider\n")
        
        for i, uuid in enumerate(instances, 1):
            print(f"[{i}/{len(instances)}] Instance {uuid}")
            result = validate_instance(uuid, args.verbose)
            if result:
                scores[result['uuid']] = {
                    'score': result['score'],
                    'grade': result['grade']
                }
            print()
        
        # Mettre à jour le CSV avec les scores
        update_csv(csv_path, scores)
    
    # Résumé final
    if scores:
        print("=" * 50)
        print("Résumé")
        print("=" * 50)
        avg_score = sum(s['score'] for s in scores.values()) / len(scores)
        print(f"Instances validées: {len(scores)}")
        print(f"Score moyen: {avg_score:.1f}%")


if __name__ == "__main__":
    main()
