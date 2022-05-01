import argparse


def attach_run_postprocessing(subparser: argparse.ArgumentParser):
    def func(args):
        args.subfunc(args)

    subparser.set_defaults(func=func)
    subsubparsers = subparser.add_subparsers(title="postprocessing command", dest="postprocessing_command")
    subsubparsers.required = True

