import argparse
import tempfile
import json
import os
import logging
import threading

from wireless_tools.iperf_driver import run_iperf_client
from wireless_tools.capture import run_capture
from wireless_tools.analysis import run_full_analyzer

automated_logger = logging.getLogger(__name__)


class IperfClientConfig(object):
    def __init__(self, hostname, port, username, pword):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.pword = pword

    @classmethod
    def from_raw(cls, raw):
        return cls(
            raw["hostname"],
            raw["port"],
            raw["username"],
            raw["pword"]
        )


class AutomatedConfig(object):
    def __init__(self, iperf_server, iperf_clients, bandwidths, wireless_device, run_seconds,
                 udp_mode, tos_value):
        self.iperf_server = iperf_server
        self.iperf_clients = iperf_clients
        self.bandwidths = bandwidths
        self.wireless_device = wireless_device
        self.run_seconds = run_seconds
        self.udp_mode = udp_mode
        self.tos_value = tos_value

    @classmethod
    def from_raw(cls, raw):
        return cls(
            raw["iperf_server"],
            [IperfClientConfig.from_raw(c) for c in raw["iperf_clients"]],
            raw["bandwidths"],
            raw["wireless_device"],
            raw["run_seconds"],
            raw["udp_mode"],
            raw["tos_value"]
        )


    @classmethod
    def from_file(cls, fname):
        with open(fname, 'r') as f:
            return cls.from_raw(json.load(f))


def run_automated_tests(config, output_directory):
    os.makedirs(output_directory, exist_ok=True)

    for bandwidth in config.bandwidths:
        iperf_threads = []
        automated_logger.info("Capture time: {0}".format(config.run_seconds))
        automated_logger.info("Starting iperf clients for bandwidth: {0}".format(bandwidth))
        for client_config in config.iperf_clients:
            iperf_threads.append(
                threading.Thread(
                    target=run_iperf_client,
                    args=[client_config.hostname, client_config.port, client_config.username,
                          client_config.pword, config.iperf_server],
                    kwargs={
                        "bandwidth": bandwidth,
                        "time": int(config.run_seconds * 1.1),
                        "udp_mode": config.udp_mode,
                        "tos_value": config.tos_value
                    }
                )
            )
        for t in iperf_threads:
            t.start()
        with tempfile.TemporaryDirectory() as d:
            automated_logger.info("Starting capture....")
            run_capture(
                config.wireless_device, d, config.run_seconds, channels=[11]
            )
            automated_logger.info("Capture completed. Waiting for iperf clients to finish.")
            for t in iperf_threads:
                t.join(30)
            automated_logger.info("Running analysis...")
            run_full_analyzer(
                os.path.join(d, "channel-11.pcap"),
                output_file=os.path.join(output_directory, "analysis-{0}.json".format(bandwidth))
            )
            automated_logger.info("Analysis completed.")


def attach_run_automated(subparser: argparse.ArgumentParser):
    def func(args):
        run_automated_tests(
            args.config_file,
            args.output_directory
        )

    subparser.set_defaults(func=func)
    subparser.add_argument("config_file", type=AutomatedConfig.from_file)
    subparser.add_argument("output_directory", type=str)
