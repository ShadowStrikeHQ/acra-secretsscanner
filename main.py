import argparse
import ast
import logging
import os
import re
import sys
import radon.raw
import radon.complexity

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecretsScanner:
    """
    Scans Python source code files for potential secrets and vulnerabilities.
    """

    def __init__(self, filepath, output_file=None):
        """
        Initializes the SecretsScanner with the file path to scan.

        Args:
            filepath (str): The path to the Python file to scan.
            output_file (str, optional): Path to the file to save scan results. Defaults to None.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        self.filepath = filepath
        self.output_file = output_file
        self.results = []  # List to store findings

    def scan(self):
        """
        Performs the scan of the specified file for secrets and vulnerabilities.
        """
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                source_code = f.read()

            self.scan_secrets(source_code)
            self.scan_vulnerabilities(source_code)
            self.analyze_complexity(source_code)

            if self.output_file:
                self.write_results_to_file(self.results)
            else:
                self.print_results(self.results)

        except FileNotFoundError as e:
            logging.error(f"Error: File not found - {e}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            sys.exit(1)

    def scan_secrets(self, source_code):
        """
        Scans the source code for potential exposed secrets using regular expressions.

        Args:
            source_code (str): The source code to scan.
        """

        # Regular expressions for common secret patterns
        api_key_regex = r"(?:API|api)[ _-]*KEY[ _-]*[=:][ ]*['\"]?([a-zA-Z0-9_-]+)['\"]?"
        password_regex = r"(?:password|pwd)[ _-]*[=:][ ]*['\"]?([a-zA-Z0-9!@#$%^&*()_+=-`~\[\]\{\}\|;':\",./<>?]+)['\"]?"
        private_key_regex = r"-----BEGIN(?: RSA| DSA| EC) PRIVATE KEY-----[\n\r]*(.+?)[\n\r]*-----END(?: RSA| DSA| EC) PRIVATE KEY-----"
        aws_secret_key_regex = r"AKIA[0-9A-Z]{16}"

        secrets_patterns = {
            "API Key": api_key_regex,
            "Password": password_regex,
            "Private Key": private_key_regex,
            "AWS Secret Key": aws_secret_key_regex
        }

        for secret_type, pattern in secrets_patterns.items():
            matches = re.finditer(pattern, source_code)
            for match in matches:
                secret = match.group(1) if match.groups() else match.group(0)
                line_number = source_code.count('\n', 0, match.start()) + 1
                self.results.append({
                    "type": "Secret",
                    "secret_type": secret_type,
                    "description": f"Possible exposed {secret_type} found.",
                    "line_number": line_number,
                    "secret": secret,
                    "evidence": match.group(0)
                })
                logging.warning(f"Possible exposed {secret_type} found on line {line_number}")

    def scan_vulnerabilities(self, source_code):
        """
        Scans the source code for potential security vulnerabilities.

        Args:
            source_code (str): The source code to scan.
        """
        try:
            tree = ast.parse(source_code)

            # Insecure string formatting vulnerability check
            for node in ast.walk(tree):
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Str):
                    line_number = node.lineno
                    self.results.append({
                        "type": "Vulnerability",
                        "vulnerability_type": "Insecure String Formatting",
                        "description": "Potential insecure string formatting vulnerability using % operator.",
                        "line_number": line_number,
                        "code_snippet": ast.get_source_segment(source_code, node),
                        "severity": "High"
                    })
                    logging.warning(f"Potential insecure string formatting vulnerability found on line {line_number}")

                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format" and isinstance(node.func.value, ast.Str):
                    line_number = node.lineno
                    self.results.append({
                        "type": "Vulnerability",
                        "vulnerability_type": "Insecure String Formatting",
                        "description": "Potential insecure string formatting vulnerability using .format() method.",
                        "line_number": line_number,
                        "code_snippet": ast.get_source_segment(source_code, node),
                        "severity": "Medium"
                    })
                    logging.warning(f"Potential insecure string formatting vulnerability found on line {line_number}")

                # Hardcoded credentials check
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            if target.id.lower() in ["password", "pwd", "api_key", "secret_key", "token"]:
                                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                    line_number = node.lineno
                                    self.results.append({
                                        "type": "Vulnerability",
                                        "vulnerability_type": "Hardcoded Credentials",
                                        "description": f"Potential hardcoded credential found in variable '{target.id}'.",
                                        "line_number": line_number,
                                        "code_snippet": ast.get_source_segment(source_code, node),
                                        "severity": "Critical"
                                    })
                                    logging.critical(f"Potential hardcoded credential found on line {line_number}")
        except SyntaxError as e:
            logging.error(f"Syntax error in file: {e}")

    def analyze_complexity(self, source_code):
        """
        Analyzes the code complexity using radon library.

        Args:
            source_code (str): The source code to analyze.
        """
        try:
            # Analyze raw metrics
            raw_metrics = radon.raw.analyze(source_code)

            # Analyze Cyclomatic Complexity
            complexity_metrics = radon.complexity.cc_rank(source_code)
            
            for block in radon.complexity.cc_visit(source_code):
                if block.complexity > 10:
                    self.results.append({
                            "type": "Complexity",
                            "complexity_type": "Cyclomatic Complexity",
                            "description": f"High Cyclomatic Complexity in {block.name} on line {block.lineno} (Complexity: {block.complexity}).",
                            "line_number": block.lineno,
                            "function_name": block.name,
                            "complexity_score": block.complexity
                    })
                    logging.warning(f"High Cyclomatic Complexity in {block.name} on line {block.lineno} (Complexity: {block.complexity}).")


        except Exception as e:
            logging.error(f"Error during complexity analysis: {e}")

    def print_results(self, results):
        """
        Prints the scan results to the console.

        Args:
            results (list): A list of dictionaries containing the scan results.
        """
        if not results:
            print("No issues found.")
            return

        print("Scan Results:")
        for result in results:
            print(f"  Type: {result['type']}")
            if result['type'] == 'Secret':
                print(f"    Secret Type: {result['secret_type']}")
                print(f"    Description: {result['description']}")
                print(f"    Line Number: {result['line_number']}")
                print(f"    Secret (Masked): {'*' * len(result['secret'])}") # Masking the secret
                print(f"    Evidence: {result['evidence']}")
            elif result['type'] == 'Vulnerability':
                print(f"    Vulnerability Type: {result['vulnerability_type']}")
                print(f"    Description: {result['description']}")
                print(f"    Line Number: {result['line_number']}")
                print(f"    Code Snippet: {result['code_snippet']}")
                print(f"    Severity: {result['severity']}")
            elif result['type'] == 'Complexity':
                print(f"    Complexity Type: {result['complexity_type']}")
                print(f"    Description: {result['description']}")
                print(f"    Line Number: {result['line_number']}")
                print(f"    Function Name: {result['function_name']}")
                print(f"    Complexity Score: {result['complexity_score']}")

            print("-" * 20)

    def write_results_to_file(self, results):
        """
        Writes the scan results to a file.

        Args:
            results (list): A list of dictionaries containing the scan results.
        """
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                for result in results:
                    f.write(f"Type: {result['type']}\n")
                    if result['type'] == 'Secret':
                        f.write(f"  Secret Type: {result['secret_type']}\n")
                        f.write(f"  Description: {result['description']}\n")
                        f.write(f"  Line Number: {result['line_number']}\n")
                        f.write(f"  Secret (Masked): {'*' * len(result['secret'])}\n")
                        f.write(f"  Evidence: {result['evidence']}\n")
                    elif result['type'] == 'Vulnerability':
                        f.write(f"  Vulnerability Type: {result['vulnerability_type']}\n")
                        f.write(f"  Description: {result['description']}\n")
                        f.write(f"  Line Number: {result['line_number']}\n")
                        f.write(f"  Code Snippet: {result['code_snippet']}\n")
                        f.write(f"  Severity: {result['severity']}\n")
                    elif result['type'] == 'Complexity':
                        f.write(f"  Complexity Type: {result['complexity_type']}\n")
                        f.write(f"  Description: {result['description']}\n")
                        f.write(f"  Line Number: {result['line_number']}\n")
                        f.write(f"  Function Name: {result['function_name']}\n")
                        f.write(f"  Complexity Score: {result['complexity_score']}\n")

                    f.write("-" * 20 + "\n")
            logging.info(f"Scan results written to {self.output_file}")
        except Exception as e:
            logging.error(f"Error writing results to file: {e}")


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Scan Python source code for potential secrets and vulnerabilities.")
    parser.add_argument("filepath", help="Path to the Python file to scan.")
    parser.add_argument("-o", "--output", dest="output_file", help="Path to the file to save the scan results.", required=False)
    return parser

def main():
    """
    Main function to execute the secrets scanner.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        scanner = SecretsScanner(args.filepath, args.output_file)
        scanner.scan()

    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    """
    Usage examples:
    
    1. Scan a file and print results to console:
       python acra-SecretsScanner.py example.py
       
    2. Scan a file and save results to a file:
       python acra-SecretsScanner.py example.py -o results.txt
    """
    main()