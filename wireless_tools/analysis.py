from scapy.layers import dot11
import pcapy
import dpkt
import argparse
import logging
import struct
import statistics
import json

from functools import lru_cache
from collections import defaultdict, namedtuple
from enum import Enum

analysis_logger = logging.getLogger(__name__)


def binary_to_mac(binary):
    if isinstance(binary, bytes):
        return ':'.join(("{:02x}".format(c)) for c in binary)
    else:
        return ':'.join(("{:02x}".format(ord(c))) for c in binary)


BeaconTimingInfo = namedtuple("BeaconTimingInfo", ("capture_time", "ap_timestamp", "interval", "channel", "seq_num"))


@lru_cache(128)
def scapy_radiotap(buf):
    return dot11.RadioTap(buf)


@lru_cache(128)
def dpkt_radiotap(buf):
    return dpkt.radiotap.Radiotap(buf)


class AbstractAnalysis(object):
    RESULT_FILE_NAME = "???.json"

    def __init__(self):
        pass

    def analyze_frame(self, header, payload):
        pass

    @staticmethod
    def _pcap_ts_to_float(pcap_ts):
        return (pcap_ts[0]*1.0) + (pcap_ts[1]/1e6)

    @staticmethod
    def _scapy_radiotap(payload):
        return scapy_radiotap(payload)

    @classmethod
    def _scapy_80211(cls, payload):
        return cls._scapy_radiotap(payload).payload

    @staticmethod
    def _dpkt_radiotap(payload):
        return dpkt_radiotap(payload)

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
            if args.output_file is not None:
                analyzer.write_result_data(args.output_file)
        subparser.set_defaults(subfunc=subfunc)

    def get_result_data(self):
        return {}

    def write_result_data(self, fname=None):
        fname = fname or self.RESULT_FILE_NAME
        with open(fname, 'w') as f:
            json.dump(self.get_result_data(), f)


class MultipleAnalysis(AbstractAnalysis):
    RESULT_FILE_NAME = "full.json"

    def __init__(self, sub_analyzers):
        super(MultipleAnalysis, self).__init__()
        self.sub_analyzers = sub_analyzers

    def analyze_frame(self, header, payload):
        for _, sub_analyzer in self.sub_analyzers.items():
            sub_analyzer.analyze_frame(header, payload)

    def summarize(self):
        result = ""
        for name, sub_analyzer in self.sub_analyzers.items():
            result += ("============\n{0}\n============\n\n".format(name) + sub_analyzer.summarize() + "\n----\n\n")
        return result

    def get_result_data(self):
        return {name: sub_analyzer.get_result_data() for name, sub_analyzer in self.sub_analyzers.items()}


class SimpleRetryFractionAnalysis(AbstractAnalysis):
    RESULT_FILE_NAME = "simple-retry-fraction.json"

    def __init__(self):
        super(SimpleRetryFractionAnalysis, self).__init__()
        self.retry_count = 0
        self.data_retry_count = 0
        self.total_count = 0
        self.data_total_count = 0

    def analyze_frame(self, header, payload):
        try:
            frame = self._dpkt_80211(payload)
            if frame.retry:
                self.retry_count += 1
            if frame.type == dpkt.ieee80211.DATA_TYPE:
                if frame.retry:
                    self.data_retry_count += 1
                self.data_total_count += 1
        except dpkt.dpkt.UnpackError:
            pass
        self.total_count += 1

    @property
    def retry_fraction(self):
        return (self.retry_count*1.0)/self.total_count

    @property
    def data_retry_fraction(self):
        return (self.data_retry_count*1.0)/self.data_total_count

    def summarize(self):
        return "Retry Fraction: {0} / Data Retry Fraction: {1}".format(self.retry_fraction, self.data_retry_fraction)

    def get_result_data(self):
        return {
            "retry_count": self.retry_count,
            "data_retry_count": self.data_retry_count,
            "total_count": self.total_count,
            "data_total_count": self.data_total_count,
            "retry_fraction": self.retry_fraction,
            "data_retry_fraction": self.data_retry_fraction
        }


class CounterAnalysis(AbstractAnalysis):
    RESULT_FILE_NAME = "counters.json"

    def __init__(self):
        super(CounterAnalysis, self).__init__()
        self.type_subtype_counters = defaultdict(lambda: defaultdict(int))
        self.rate_counters = defaultdict(int)
        self.unknown_frame_counter = 0
        self.approx_occupied_duration = 0.0
        self.approx_capture_start_time = None
        self.approx_capture_end_time = None

    def analyze_frame(self, header, payload):
        frame_time = self._pcap_ts_to_float(header.getts())
        if self.approx_capture_start_time is None or frame_time < self.approx_capture_start_time:
            self.approx_capture_start_time = frame_time
        if self.approx_capture_end_time is None or frame_time > self.approx_capture_end_time:
            self.approx_capture_end_time = frame_time

        try:
            radiotap = self._dpkt_radiotap(payload)
            if radiotap.rate_present:
                rate = (radiotap.rate.val * (512/8)*1024)
                self.rate_counters[radiotap.rate.val] += 1
            else:
                # take a guess
                rate = 1.0*1024*(1024/8)
            self.approx_occupied_duration += radiotap.length/rate

            frame = self._dpkt_80211(payload)
            self.type_subtype_counters[frame.type][frame.subtype] += 1
        except dpkt.dpkt.UnpackError:
            self.unknown_frame_counter += 1

    @property
    def data_ratio(self):
        data_count = sum(self.type_subtype_counters[2].values())
        total_count = sum(i for v in self.type_subtype_counters.values() for i in v.values())
        return (1.0*data_count)/total_count

    @property
    def approx_occupied_ratio(self):
        return self.approx_occupied_duration/(self.approx_capture_end_time - self.approx_capture_start_time)

    def summarize(self):
        return json.dumps(self.get_result_data(), indent=2)

    def get_result_data(self):
        return {
            "type_subtype_counters": self.type_subtype_counters,
            "data_ratio": self.data_ratio,
            "rate_counters": self.rate_counters,
            "unknown_frames": self.unknown_frame_counter,
            "approx_occupied_duration": self.approx_occupied_duration,
            "approx_start_time": self.approx_capture_start_time,
            "approx_end_time": self.approx_capture_end_time,
            "approx_occupied_ratio": self.approx_occupied_ratio
        }


class BeaconJitterAnalysis(AbstractAnalysis):
    RESULT_FILE_NAME = "beacon-jitter-analysis.json"

    def __init__(self):
        super(BeaconJitterAnalysis, self).__init__()
        self.bssid_beacon_timing = defaultdict(list)
        self.bssid_ssid_map = {}

    def analyze_frame(self, header, payload):
        try:
            wireless_frame = self._dpkt_80211(payload)
            scapy_wireless_frame = self._scapy_80211(payload)

            if wireless_frame.type == dpkt.ieee80211.MGMT_TYPE and wireless_frame.subtype == dpkt.ieee80211.M_BEACON:
                bssid = wireless_frame.mgmt.bssid
                seen_time = self._pcap_ts_to_float(header.getts())
                beacon_time = scapy_wireless_frame.timestamp
                beacon_interval = scapy_wireless_frame.beacon_interval
                sequence_number = None
                beacon_channel = None
                t = BeaconTimingInfo(seen_time, beacon_time, beacon_interval, beacon_channel, sequence_number)
                self.bssid_beacon_timing[bssid].append(t)
                self.bssid_ssid_map[bssid] = wireless_frame.ssid.data.decode("utf-8")
        except dpkt.dpkt.UnpackError:
            pass

    def _generate_jitter_values(self):
        jitter_values = {}
        for bssid, payloads in self.bssid_beacon_timing.items():
            if len(payloads) > 1:
                payloads = sorted(payloads, key=lambda v: v.ap_timestamp)
                nominal_interval = payloads[0].interval * 1024e-6
                jitter = []
                for i in range(len(payloads)-1):
                    current_jitter_ms = (payloads[i+1].capture_time - payloads[i].capture_time) - nominal_interval
                    current_jitter_ms *= 1e3
                    jitter.append(current_jitter_ms)
                if len(jitter) > 1:
                    jitter_values[bssid] = jitter
        return jitter_values

    def summarize(self):
        summary = ""
        for bssid, jitter_data in self._generate_jitter_values().items():
            jitter_data = [abs(d) for d in jitter_data]
            jitter_data_corrected = [d for d in jitter_data if abs(d) < 102.4]
            if len(jitter_data_corrected) > 2:
                jitter_mean_corrected = statistics.mean(jitter_data_corrected)
                jitter_stddev_corrected = statistics.stdev(jitter_data_corrected)
            else:
                jitter_mean_corrected = None
                jitter_stddev_corrected = None
            summary += "BSSID: {0} ({1})\n-----\n\tMin: {2}ms\n\tMax: {3}ms\n\tAvg: {4}ms\n\tStd Dev: {5}ms\n" \
                       "\tAvg (Corrected): {6}\n\tStd Dev (Corrected): {7}\n\n".format(
                binary_to_mac(bssid), self.bssid_ssid_map[bssid], min(jitter_data), max(jitter_data),
                statistics.mean(jitter_data), statistics.stdev(jitter_data),
                jitter_mean_corrected, jitter_stddev_corrected
            )
        return summary

    def get_result_data(self):
        return {
            "jitter_data": {binary_to_mac(bssid): data for bssid, data in self._generate_jitter_values().items()},
            "ssid_map": {binary_to_mac(bssid): ssid for bssid, ssid in self.bssid_ssid_map.items()}
        }


def run_generic_analysis(fname, apply_to_frame):
    capture = pcapy.open_offline(fname)
    header, payload = capture.next()

    while header:
        apply_to_frame(header, payload)
        header, payload = capture.next()


def run_full_analyzer(analysis_file, output_file=None):
    analyzers = {
        "SimpleRetryFraction": SimpleRetryFractionAnalysis(),
        "BeaconJitterAnalysis": BeaconJitterAnalysis(),
        "CounterAnalysis": CounterAnalysis()
    }
    analyzer = MultipleAnalysis(analyzers)
    run_generic_analysis(analysis_file, analyzer.analyze_frame)
    print(analyzer.summarize())
    if output_file is not None:
        analyzer.write_result_data(output_file)


def attach_run_analysis(subparser: argparse.ArgumentParser):
    def func(args):
        args.subfunc(args)

    def attach_run_all(subparser: argparse.ArgumentParser):
        def subfunc(args):
            run_full_analyzer(args.analysis_file, output_file=args.output_file)
        subparser.set_defaults(subfunc=subfunc)

    subparser.set_defaults(func=func)
    subparser.add_argument("analysis_file", type=str, help="PCAP file to analyze.")
    subparser.add_argument("-o", "--output-file", type=str, default=None, help="Data output file.")
    subsubparsers = subparser.add_subparsers(title="analysis commands", dest="analysis_command")
    subsubparsers.required = True

    SimpleRetryFractionAnalysis.attach_run(subsubparsers.add_parser("SimpleRetryFraction"))
    BeaconJitterAnalysis.attach_run(subsubparsers.add_parser("BeaconJitterAnalysis"))
    CounterAnalysis.attach_run(subsubparsers.add_parser("CounterAnalysis"))
    attach_run_all(subsubparsers.add_parser("RunAll"))
