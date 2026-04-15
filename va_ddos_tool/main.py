import argparse
from va_ddos_tool.blocker import main as run_blocker

def main():
    parser = argparse.ArgumentParser(description="VA DDoS Tool")
    parser.add_argument("--mode", choices=["block"], required=True)

    args = parser.parse_args()

    if args.mode == "block":
        run_blocker()

if __name__ == "__main__":
    main()
