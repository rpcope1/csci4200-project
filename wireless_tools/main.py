import argparse
import logging
import sys
from logging.handlers import WatchedFileHandler

from wireless_tools.capture import attach_run_capture
from wireless_tools.analysis import attach_run_analysis
from wireless_tools.automated import attach_run_automated


LOG_FORMAT = "[%(asctime)s] - %(levelname)s - %(message)s - " \
             "(%(name)s : %(funcName)s : %(lineno)d : Thread/PID(%(thread)d/%(process)d))"


main_logger = logging.getLogger(__name__)

argument_parser = argparse.ArgumentParser("wireless-tools")
argument_parser.add_argument(
    "-v", "--verbose", action="count", default=0, help="Report with increasing verbosity"
)
argument_parser.add_argument(
    "-lf", "--log-file", type=str, default="-", help="The log file to write to. Default: - (write to stderr)."
)
subparsers = argument_parser.add_subparsers(title="commands", dest="command")
subparsers.required = True

attach_run_capture(subparsers.add_parser("capture-802.11-traffic"))
attach_run_analysis(subparsers.add_parser("analyze-802.11-traffic"))
attach_run_automated(subparsers.add_parser("automated-802.11-analysis"))


def setup_logging(log_file, verbosity, enable_sigusr1_debug=False):
    root_logger = logging.getLogger('')
    handlers = []
    config = {'debug_mode': False}

    def set_log_level(level):
        root_logger.setLevel(level)
        for handler in handlers:
            handler.setLevel(log_level)
            root_logger.addHandler(handler)

    if log_file == "-":
        handlers.append(logging.StreamHandler(sys.stdout))
    else:
        handlers.append(WatchedFileHandler(log_file))

    if verbosity >= 2:
        log_level = logging.DEBUG
    elif verbosity == 1:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING
    config['log_level'] = logging
    for handler in handlers:
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        root_logger.addHandler(handler)
    set_log_level(log_level)

    if enable_sigusr1_debug:
        import signal

        def sigusr1_handler(*args, **kwargs):
            if config['debug_mode']:
                set_log_level(config['log_level'])
                config['debug_mode'] = False
            else:
                set_log_level(logging.DEBUG)
                config['debug_mode'] = True

        signal.signal(
            signal.SIGUSR1,
            sigusr1_handler
        )
    return handlers, config


def main(args=None):
    args = args or argument_parser.parse_args()
    setup_logging(args.log_file, args.verbose, True)

    try:
        main_logger.info("Executing command: {0}".format(args.command))
        args.func(args)
    except KeyboardInterrupt:
        main_logger.warning("Keyboard Interrupt caught, exiting...")
        raise
    except BaseException:
        main_logger.exception("Unhandled exception executing command: {0}".format(args.command))
        raise
