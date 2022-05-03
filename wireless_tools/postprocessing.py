import argparse
from matplotlib import pyplot
import re
import json
import os


FILE_REGEX = re.compile(r"analysis-(?P<bandwidth>[^.]+).json")


def _filter_jitter_values(j):
    return [i for i in j if abs(i) < 20.0]


def _missing_beacon_counts(j):
    return sum(int(i//102.4) for i in j if abs(i) >= 100.0)


def _load_data_files(analysis_dir):
    data = {}
    for f in os.listdir(analysis_dir):
        if FILE_REGEX.match(f):
            with open(os.path.join(analysis_dir, f), 'r') as wat:
                data[f] = json.load(wat)
    return data


def _bandwidth_decoder(v):
    multiplier = v[-1]
    if multiplier == "M":
        val = 1024*1024
    elif multiplier == "K":
        val = 1024
    else:
        assert False
    return int(v[:-1])*val


def _bandwidth_sorter(keys):
    def fname_to_raw_bw(f):
        bandwidth = FILE_REGEX.match(f).groupdict()["bandwidth"]
        return _bandwidth_decoder(bandwidth)
    return sorted(list(keys), key=fname_to_raw_bw)


def attach_run_jitter_postprocessing(subparser: argparse.ArgumentParser):
    def subfunc(args):
        data = _load_data_files(args.analysis_dir)


        ssid_to_bssid = None
        for f in data.keys():
            ssid_to_bssid = {v: k for k, v in data[f]["BeaconJitterAnalysis"]["ssid_map"].items()}

        for ssid in args.ssid:
            missing_beacon_data = []
            ssid_utilization_data = []
            bssid = ssid_to_bssid[ssid]
            fig = pyplot.figure()
            fig.suptitle("Jitter Analysis for SSID: {0}".format(ssid))
            gs = fig.add_gridspec(2, 2)
            ax1 = fig.add_subplot(gs[0, :])
            ax2 = fig.add_subplot(gs[1, 0])
            ax3 = fig.add_subplot(gs[1, 1])
            cmap = pyplot.get_cmap()

            for f in _bandwidth_sorter(data.keys()):
                bandwidth = FILE_REGEX.match(f).groupdict()["bandwidth"]
                ax1.hist(
                    _filter_jitter_values(data[f]["BeaconJitterAnalysis"]['jitter_data'][bssid]),
                    histtype='step',
                    label=f,
                    bins=200
                )
                missing_beacon_data.append(
                    (_bandwidth_decoder(bandwidth), bandwidth,
                     _missing_beacon_counts(data[f]["BeaconJitterAnalysis"]['jitter_data'][bssid]))
                )
                ssid_utilization_data.append(
                    (_bandwidth_decoder(bandwidth), bandwidth,
                     [v for v in data[f]["BeaconUtilizationAnalysis"]["bssid_utilization_ratio"].get(bssid, {}).values()])
                )
            missing_beacon_data = sorted(missing_beacon_data, key=lambda v: v[0])
            ssid_utilization_data = sorted(ssid_utilization_data, key=lambda v: v[0])
            ax1.legend(loc='best')
            ax1.set_xlabel("Beacon Jitter (ms)")
            ax1.set_ylabel("Bin Count")
            ax2.bar(
                [i for i in range(len(missing_beacon_data))],
                [v[2] for v in missing_beacon_data],
                color=cmap.colors
            )
            ax2.set_ylabel("Missing Beacons")
            ax2.set_xticks(
                [i for i in range(len(missing_beacon_data))]
            )
            ax2.set_xticklabels(
                [v[1] for v in missing_beacon_data],
                rotation=45
            )
            ax3.boxplot(
                [v[2] for v in ssid_utilization_data]
            )
            ax3.set_ylabel("AP Reported Utilization")
            ax3.set_xticks(
                [i+1 for i in range(len(missing_beacon_data))]
            )
            ax3.set_xticklabels(
                [v[1] for v in missing_beacon_data],
                rotation=45
            )
        pyplot.show()

    subparser.set_defaults(subfunc=subfunc)
    subparser.add_argument("ssid", nargs="+")


def attach_run_retry_ratio_postprocessing(subparser: argparse.ArgumentParser):
    def subfunc(args):
        data = _load_data_files(args.analysis_dir)


        ssid_to_bssid = None
        for f in data.keys():
            ssid_to_bssid = {v: k for k, v in data[f]["BeaconJitterAnalysis"]["ssid_map"].items()}

        for ssid in args.ssid:
            retry_data = []
            data_retry_data = []
            ssid_utilization_data = []
            bssid = ssid_to_bssid[ssid]
            fig = pyplot.figure()
            fig.suptitle("Retry Ratio Analysis for SSID: {0}".format(ssid))
            gs = fig.add_gridspec(3, 1)
            ax1 = fig.add_subplot(gs[0, 0])
            ax2 = fig.add_subplot(gs[1, 0])
            ax3 = fig.add_subplot(gs[2, 0])

            for f in _bandwidth_sorter(data.keys()):
                bandwidth = FILE_REGEX.match(f).groupdict()["bandwidth"]
                retry_data.append(
                    (_bandwidth_decoder(bandwidth), bandwidth, data[f]["SimpleRetryFraction"]["retry_fraction"])
                )
                data_retry_data.append(
                    (_bandwidth_decoder(bandwidth), bandwidth, data[f]["SimpleRetryFraction"]["data_retry_fraction"])
                )
                ssid_utilization_data.append(
                    (_bandwidth_decoder(bandwidth), bandwidth,
                     [v for v in
                      data[f]["BeaconUtilizationAnalysis"]["bssid_utilization_ratio"].get(bssid, {}).values()])
                )

            retry_data = sorted(retry_data, key=lambda v: v[0])
            data_retry_data = sorted(data_retry_data, key=lambda v: v[0])
            ax1.bar(
                [i for i in range(len(retry_data))],
                [v[2] for v in retry_data],
            )
            ax1.set_ylabel("Retry Ratio (All)")
            ax1.set_xticks(
                [i for i in range(len(retry_data))]
            )
            ax1.set_xticklabels(
                [v[1] for v in retry_data],
                rotation=45
            )
            ax2.bar(
                [i for i in range(len(data_retry_data))],
                [v[2] for v in data_retry_data],
            )
            ax2.set_ylabel("Data Retry Ratio (All)")
            ax2.set_xticks(
                [i for i in range(len(data_retry_data))]
            )
            ax2.set_xticklabels(
                [v[1] for v in data_retry_data],
                rotation=45
            )
            ax3.boxplot(
                [v[2] for v in ssid_utilization_data]
            )
            ax3.set_ylabel("AP Reported Utilization")
            ax3.set_xticks(
                [i+1 for i in range(len(ssid_utilization_data))]
            )
            ax3.set_xticklabels(
                [v[1] for v in ssid_utilization_data],
                rotation=45
            )
        pyplot.show()

    subparser.set_defaults(subfunc=subfunc)
    subparser.add_argument("ssid", nargs="+")


def attach_run_postprocessing(subparser: argparse.ArgumentParser):
    def func(args):
        args.subfunc(args)

    subparser.set_defaults(func=func)
    subparser.add_argument("analysis_dir", type=str)
    subsubparsers = subparser.add_subparsers(title="postprocessing command", dest="postprocessing_command")
    subsubparsers.required = True
    attach_run_jitter_postprocessing(subsubparsers.add_parser("jitter-post-processing"))
    attach_run_retry_ratio_postprocessing(subsubparsers.add_parser("retry-ratio-post-processing"))

