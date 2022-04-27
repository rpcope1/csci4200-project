#!/usr/bin/env python

import sys
from matplotlib import pyplot
import re
import json
import os

output_directory = sys.argv[1]
ap_ssid = sys.argv[2]

file_regex = re.compile(r"analysis-(?P<bandwidth>[^.]+).json")

data = {}

bssid = None


def filter_jitter_values(j):
    return [i for i in j if abs(i) < 20.0]


for f in os.listdir(output_directory):
    if file_regex.match(f):
        with open(os.path.join(output_directory, f), 'r') as wat:
            data[f] = json.load(wat)

        ssid_to_bssid = {v: k for k, v in data[f]["BeaconJitterAnalysis"]["ssid_map"].items()}
        bssid = ssid_to_bssid[ap_ssid]

assert bssid

for f in data.keys():
    pyplot.hist(filter_jitter_values(data[f]["BeaconJitterAnalysis"]['jitter_data'][bssid]), histtype='step', label=f, bins=200)
pyplot.legend(loc='best')
pyplot.show()