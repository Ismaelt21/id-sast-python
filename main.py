from engine.pysast import PySAST


def main() -> None:
    from cli.main import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()

