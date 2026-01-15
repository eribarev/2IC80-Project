#!/usr/bin/env python3
"""
Spoofy - Interactive MITM Attack Console

Metasploit-style interface for the MITM attack framework.
Run with: python console.py
"""

import cmd
import sys
from pathlib import Path

from attack_manager import AttackManager, AttackConfig, AttackMode
from dns_spoofer import load_dns_rules
from network_utils import get_interface_info



# BANNER = r"""
#      _______  _______  _______  _______  _______          
#     (  ____ \(  ____ )(  ___  )(  ___  )(  ____ \|\     /|
#     | (    \/| (    )|| (   ) || (   ) || (    \/( \   / )
#     | (_____ | (____)|| |   | || |   | || (__     \ (_) / 
#     (_____  )|  _____)| |   | || |   | ||  __)     \   /  
#           ) || (      | |   | || |   | || (         ) (   
#     /\____) || )      | (___) || (___) || )         | |   
#     \_______)|/       (_______)(_______)|/          \_/   
                                                                            
#                 [ ARP+DNS+SSL Attack Tool ]
#           2IC80 Lab On Offensive Computer Security
# """
BANNER = r"""

       ,-,--.     _ __      _,.---._       _,.---._        _,---.                
     ,-.'-  _\ .-`.' ,`.  ,-.' , -  `.   ,-.' , -  `.   .-`.' ,  \ ,--.-.  .-,--.
    /==/_ ,_.'/==/, -   \/==/_,  ,  - \ /==/_,  ,  - \ /==/_  _.-'/==/- / /=/_ / 
    \==\  \  |==| _ .=. |==|   .=.     |==|   .=.     /==/-  '..-.\==\, \/=/. /  
     \==\ -\ |==| , '=',|==|_ : ;=:  - |==|_ : ;=:  - |==|_ ,    / \==\  \/ -/   
     _\==\ ,\|==|-  '..'|==| , '='     |==| , '='     |==|   .--'   |==|  ,_/    
    /==/\/ _ |==|,  |    \==\ -    ,_ / \==\ -    ,_ /|==|-  |      \==\-, /     
    \==\ - , /==/ - |     '.='. -   .'   '.='. -   .' /==/   \      /==/._/      
     `--`---'`--`---'       `--`--''       `--`--''   `--`---'      `--`-`       
                                                                            
                         [ ARP+DNS+SSL Attack Tool ]
                  2IC80 Lab On Offensive Computer Security
"""

# Color codes for terminal output
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def colorize(text: str, color: str) -> str:
    """Wrap text in color codes."""
    return f"{color}{text}{Colors.RESET}"


# Mode definitions with their required/optional parameters
MODES = {
    "arp-only": {
        "description": "ARP poisoning only - position as MITM",
        "required": ["VICTIM_IP", "TARGET_IP"],
        "optional": ["INTERFACE", "ARP_INTERVAL", "SILENT"],
    },
    "dns-only": {
        "description": "DNS spoofing (race attack) - no MITM needed",
        "required": ["VICTIM_IP", "TARGET_IP", "DNS_RULES"],
        "optional": ["INTERFACE"],
    },
    "arp-dns": {
        "description": "ARP poisoning + DNS spoofing (reliable MITM)",
        "required": ["VICTIM_IP", "TARGET_IP", "DNS_RULES"],
        "optional": ["INTERFACE", "ARP_INTERVAL", "SILENT"],
    },
    "arp-ssl": {
        "description": "ARP poisoning + SSL stripping",
        "required": ["VICTIM_IP", "TARGET_IP"],
        "optional": ["INTERFACE", "ARP_INTERVAL", "SILENT"],
    },
    "arp-dns-ssl": {
        "description": "Complete attack: ARP + DNS + SSL",
        "required": ["VICTIM_IP", "TARGET_IP", "DNS_RULES"],
        "optional": ["INTERFACE", "ARP_INTERVAL", "SILENT"],
    },
}

# Default values for options
DEFAULT_OPTIONS = {
    "VICTIM_IP": "",
    "TARGET_IP": "",
    "INTERFACE": "",  # Empty = auto-detect
    "DNS_RULES": "dns_rules.json",
    "ARP_INTERVAL": "2.0",
    "SILENT": "false",  # Silent ARP mode: listen for ARP requests instead of continuous poisoning
}


class SpoofyConsole(cmd.Cmd):
    """Interactive console for Spoofy MITM framework."""

    intro = ""
    
    def __init__(self):
        super().__init__()
        self.current_mode: str | None = None
        self.options: dict[str, str] = DEFAULT_OPTIONS.copy()
        self.manager: AttackManager | None = None
        self._update_prompt()

    def _update_prompt(self) -> None:
        """Update the prompt based on current mode."""
        if self.current_mode:
            self.prompt = colorize(f"spoofy", Colors.RED) + \
                         colorize(f" attack", Colors.RESET) + \
                         colorize(f"({self.current_mode})", Colors.CYAN) + " > "
        else:
            self.prompt = colorize("spoofy", Colors.RED) + " > "
    def preloop(self) -> None:
        """Show banner on startup."""
        print(colorize(BANNER, Colors.YELLOW))
        print(f"  {len(MODES)} modes loaded")
        print(f"  Type {colorize('help', Colors.CYAN)} for commands\n")

    def emptyline(self) -> bool:
        """Do nothing on empty line."""
        return False

    # ==================== COMMANDS ====================

    def do_use(self, arg: str) -> None:
        """Select an attack mode. Usage: use <mode>"""
        arg = arg.strip()
        if not arg:
            print(colorize("Usage: use <mode>", Colors.RED))
            print(f"  Available: {', '.join(MODES.keys())}")
            return
        
        if arg not in MODES:
            print(colorize(f"Unknown mode: {arg}", Colors.RED))
            print(f"  Available: {', '.join(MODES.keys())}")
            return
        
        self.current_mode = arg
        self._update_prompt()
        print(colorize(f"Using mode: {arg}", Colors.GREEN))
        print(f"  {MODES[arg]['description']}")

    def complete_use(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        """Tab completion for use command."""
        return [m for m in MODES.keys() if m.startswith(text)]

    def do_set(self, arg: str) -> None:
        """Set an option value. Usage: set <option> <value>"""
        parts = arg.split(None, 1)
        if len(parts) < 2:
            print(colorize("Usage: set <option> <value>", Colors.RED))
            return
        
        option, value = parts[0].upper(), parts[1]
        
        if option not in self.options:
            print(colorize(f"Unknown option: {option}", Colors.RED))
            print(f"  Options: {', '.join(self.options.keys())}")
            return
        
        self.options[option] = value
        print(f"{option} => {value}")

    def complete_set(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        """Tab completion for set command."""
        # Complete option names
        parts = line.split()
        if len(parts) <= 2 and not line.endswith(' '):
            return [o for o in self.options.keys() if o.lower().startswith(text.lower())]
        return []

    def do_show(self, arg: str) -> None:
        """Show information. Usage: show options | show modes"""
        arg = arg.strip().lower()
        
        if arg == "options":
            self._show_options()
        elif arg == "modes":
            self._show_modes()
        else:
            print(colorize("Usage: show options | show modes", Colors.RED))

    def complete_show(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        """Tab completion for show command."""
        options = ["options", "modes"]
        return [o for o in options if o.startswith(text.lower())]

    def _show_options(self) -> None:
        """Display current options table."""
        if not self.current_mode:
            print(colorize("- No mode selected", Colors.YELLOW))
            required = list(self.options.keys())
            optional: list[str] = []
        else:
            mode_info = MODES[self.current_mode]
            required = list(mode_info["required"])
            optional = list(mode_info["optional"])

        print(f"\n  Mode: {colorize(self.current_mode or '(none)', Colors.CYAN)}\n")
        print(f"  {'Name':<15} {'Current':<25} {'Required':<10} Description")
        print(f"  {'-'*14} {'-'*24} {'-'*9} {'-'*30}")
        
        descriptions = {
            "VICTIM_IP": "Target victim IP address",
            "TARGET_IP": "Gateway/machine to impersonate",
            "INTERFACE": "Network interface (auto-detect if empty)",
            "DNS_RULES": "Path to DNS rules JSON file",
            "ARP_INTERVAL": "ARP poison interval in seconds",
            "SILENT": "Silent ARP mode (true/false)",
        }
        
        # Show required options first
        for opt in required:
            value = self.options.get(opt, "")
            display_val = value if value else colorize("(not set)", Colors.RED)
            req_str = colorize("yes", Colors.RED)
            print(f"  {opt:<15} {display_val:<25} {req_str:<19} {descriptions.get(opt, '')}")
        
        # Then optional
        for opt in optional:
            if opt not in required:
                value = self.options.get(opt, "")
                display_val = value if value else "(default)"
                print(f"  {opt:<15} {display_val:<25} {'no':<10} {descriptions.get(opt, '')}")
        
        print()

    def _show_modes(self) -> None:
        """Display available modes."""
        print(f"\n  {'Mode':<15} Description")
        print(f"  {'-'*14} {'-'*50}")
        for name, info in MODES.items():
            marker = colorize("*", Colors.GREEN) if name == self.current_mode else " "
            print(f" {marker}{name:<15} {info['description']}")
        print()

    def do_run(self, arg: str) -> None:
        """Run the selected attack mode."""
        if not self.current_mode:
            print(colorize("Error: No mode selected", Colors.RED))
            return
        
        # Validate required options
        mode_info = MODES[self.current_mode]
        missing = []
        for opt in mode_info["required"]:
            if not self.options.get(opt):
                missing.append(opt)
        
        if missing:
            print(colorize(f"Missing: {', '.join(missing)}", Colors.RED))
            return
        
        # Validate DNS rules file if needed
        if "DNS_RULES" in mode_info["required"]:
            rules_path = Path(self.options["DNS_RULES"])
            if not rules_path.exists():
                print(colorize(f"File not found: {rules_path}", Colors.RED))
                return

        # Get interface info
        try:
            iface_input = self.options["INTERFACE"] or None
            iface, attacker_ip = get_interface_info(iface_input)
        except (OSError, RuntimeError, ValueError) as e:
            print(colorize(f"Interface error: {e}", Colors.RED))
            return

        # Parse SILENT option (accepts true/false, yes/no, 1/0)
        silent_val = self.options.get("SILENT", "false").lower()
        silent = silent_val in ("true", "yes", "1", "on")

        print(f"\nStarting {colorize(self.current_mode, Colors.CYAN)}...")
        print(f"  Interface : {iface} ({attacker_ip})")
        print(f"  Victim    : {self.options['VICTIM_IP']}")
        print(f"  Target    : {self.options['TARGET_IP']}")
        if "ARP_INTERVAL" in mode_info.get("optional", []):
            print(f"  ARP intvl : {self.options.get('ARP_INTERVAL', '2.0')}s")
        if "SILENT" in mode_info.get("optional", []):
            print(f"  ARP mode  : {'silent (reactive)' if silent else 'all-out (continuous)'}")
        print()

        # Load DNS rules if needed
        dns_rules_dict = None
        if "DNS_RULES" in mode_info["required"]:
            try:
                dns_rules_dict = load_dns_rules(self.options["DNS_RULES"])
            except (FileNotFoundError, ValueError) as e:
                print(colorize(f"DNS rules error: {e}", Colors.RED))
                return

        # Build config
        config = AttackConfig(
            mode=AttackMode(self.current_mode),
            iface=iface,
            attacker_ip=attacker_ip,
            victim_ip=self.options["VICTIM_IP"],
            gateway_ip=self.options["TARGET_IP"],
            dns_rules=dns_rules_dict,
            arp_interval=float(self.options.get("ARP_INTERVAL", "2.0")),
            silent=silent,
        )

        # Create and run manager
        self.manager = AttackManager(config=config)
        
        try:
            self.manager.start()
            self.manager.wait()
        except KeyboardInterrupt:
            pass  # Signal handler in manager will handle this
        except (RuntimeError, ValueError) as e:
            print(colorize(f"\nError: {e}", Colors.RED))
        finally:
            if self.manager:
                self.manager.stop()
                self.manager = None
            print()  # Clean newline after attack ends

    def do_back(self, arg: str) -> None:
        """Deselect the current mode."""
        if self.current_mode:
            print(f"Leaving mode: {self.current_mode}")
            self.current_mode = None
            self._update_prompt()
        else:
            print("No mode selected.")

    def do_info(self, arg: str) -> None:
        """Show detailed info about current or specified mode."""
        mode = arg.strip() if arg.strip() else self.current_mode
        if not mode:
            print(colorize("Usage: info <mode>", Colors.RED))
            return
        
        if mode not in MODES:
            print(colorize(f"Unknown mode: {mode}", Colors.RED))
            return
        
        info = MODES[mode]
        print(f"\n  Mode: {colorize(mode, Colors.CYAN)}")
        print(f"  {info['description']}")
        print(f"\n  Required: {', '.join(info['required'])}")
        print(f"  Optional: {', '.join(info['optional'])}\n")

    def complete_info(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        """Tab completion for info command."""
        return [m for m in MODES.keys() if m.startswith(text)]

    def do_exit(self, arg: str) -> bool:
        """Exit the console."""
        print("\nGoodbye!\n")
        return True

    def do_quit(self, arg: str) -> bool:
        """Exit the console."""
        return self.do_exit(arg)

    def do_EOF(self, arg: str) -> bool:
        """Handle Ctrl+D."""
        print()
        return self.do_exit(arg)

    # Help customization
    def do_help(self, arg: str) -> None:
        """Show help for commands."""
        if arg:
            super().do_help(arg)
        else:
            print(f"""
  {colorize('Core Commands', Colors.BOLD)}
  =============
    use <mode>       Select an attack mode
    show options     Show current option settings
    show modes       List available attack modes
    set <opt> <val>  Set an option value
    run              Execute the selected mode
    back             Deselect current mode
    info [mode]      Show mode details
    help [command]   Show help
    exit / quit      Exit the console

  {colorize('Example', Colors.BOLD)}
  =======
    use arp-dns
    set VICTIM_IP 10.0.0.20
    set TARGET_IP 10.0.0.1
    set DNS_RULES dns_rules.json
    run
""")


def main():
    """Entry point for the console."""
    try:
        console = SpoofyConsole()
        console.cmdloop()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
