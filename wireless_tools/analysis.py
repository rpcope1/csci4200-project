from scapy.layers import dot11
from scapy.all import PcapReader
import pcapy
import dpkt
import argparse
import logging

from collections import defaultdict, namedtuple
from enum import Enum

analysis_logger = logging.getLogger(__name__)


def binary_to_mac(binary):
    if isinstance(binary, bytes):
        return ':'.join(("{:02x}".format(c)) for c in binary)
    else:
        return ':'.join(("{:02x}".format(ord(c))) for c in binary)


BeaconTimingInfo = namedtuple("BeaconTimingInfo", ("capture_time", "ap_timestamp", "interval", "channel"))


class AbstractAnalysis(object):
    def __init__(self):
        pass

    def analyze_frame(self, header, payload):
        pass

    @staticmethod
    def _pcap_ts_to_float(pcap_ts):
        return (pcap_ts[0]*1.0) + (pcap_ts[1]/1e5)

    @staticmethod
    def _scapy_radiotap(payload):
        return dot11.RadioTap(payload)

    @classmethod
    def _scapy_80211(cls, payload):
        return cls._scapy_radiotap(payload).payload

    @staticmethod
    def _dpkt_radiotap(payload):
        return dpkt.radiotap.Radiotap(payload)

    @classmethod
    def _dpkt_80211(cls, payload):
        return cls._dpkt_radiotap(payload).data

    def summarize(self):
        return ""

    @classmethod
    def attach_run(cls, subparser: argparse.ArgumentParser):
        def subfunc(args):
            analyzer = cls()
            run_generic_analysis(args.analysis_file, analyzer.analyze_frame)
            print(analyzer.summarize())
        subparser.set_defaults(subfunc=subfunc)


class SimpleRetryFractionAnalysis(AbstractAnalysis):
    def __init__(self):
        super(SimpleRetryFractionAnalysis, self).__init__()
        self.retry_count = 0
        self.total_count = 0

    def analyze_frame(self, header, payload):
        frame = self._dpkt_80211(payload)
        if frame.retry:
            self.retry_count += 1
        self.total_count += 1

    @property
    def retry_fraction(self):
        return (self.retry_count*1.0)/self.total_count

    def summarize(self):
        return "Retry Fraction: {0}".format(self.retry_fraction)


class BeaconJitterAnalysis(AbstractAnalysis):
    def __init__(self):
        super(BeaconJitterAnalysis, self).__init__()
        self.bssid_beacon_timing = defaultdict(list)

    def analyze_frame(self, header, payload):
        wireless_frame = self._dpkt_80211(payload)
        scapy_wireless_frame = self._scapy_80211(payload)

        if wireless_frame.type == dpkt.ieee80211.MGMT_TYPE and wireless_frame.subtype == dpkt.ieee80211.M_BEACON:
            bssid = wireless_frame.mgmt.bssid
            seen_time = self._pcap_ts_to_float(header.getts())
            beacon = wireless_frame.beacon
            beacon_time = beacon.timestamp
            beacon_interval = beacon.interval
            # beacon_channel = scapy_wireless_frame.get("channel")
            beacon_channel = None
            t = BeaconTimingInfo(seen_time, beacon_time, beacon_interval, beacon_channel)
            self.bssid_beacon_timing[bssid].append(t)
            analysis_logger.info("{0}".format(t))
            assert False





def run_generic_analysis(fname, apply_to_frame):
    capture = pcapy.open_offline(fname)
    header, payload = capture.next()

    while header:
        apply_to_frame(header, payload)
        header, payload = capture.next()


def attach_run_analysis(subparser: argparse.ArgumentParser):
    def func(args):
        args.subfunc(args)

    subparser.set_defaults(func=func)
    subparser.add_argument("analysis_file", type=str, help="PCAP file to analyze.")
    subsubparsers = subparser.add_subparsers(title="analysis commands", dest="analysis_command")
    subsubparsers.required = True

    SimpleRetryFractionAnalysis.attach_run(subsubparsers.add_parser("SimpleRetryFraction"))
    BeaconJitterAnalysis.attach_run(subsubparsers.add_parser("BeaconJitterAnalysis"))
