# CSCI 4200 -- Introduction to Wireless Systems Spring 2022: Final Project
Author: Robert Cope

## Background:

We seek to study the behavior of wireless 802.11 systems as a function of channel utilization, and look for metrics that
correlate with actual channel utilization and saturation. This codebase allows us to study both "beacon jitter", 
frame retry ration, and other metrics when a controlled (or uncontrolled) amount of traffic is present.

## How to run:
Install the requirements in requirements.txt. Then

```
python3 run_tools.py ${COMMAND}
```

where command is one of: ```capture-802.11-traffic```, ```analyze-802.11-traffic```, ```automated-802.11-analysis```,
```attack-802.11-traffic```, or ```postprocess-802.11-analysis```.

## What we found

* Beacon jitter and retry ratios don't appear to be a reliable metric of channel utilization.
* Certain attacks like the channel quiet attack, and attacks against the NAV using CTS-to-self don't seem to work in the 2.4 GHz channels.
* 802.11 utilization can be readily obtained by sniffing beacon frames, and getting the QBSS load element tag, which contains a sensed channel utilization and the number of clients attached to the AP. This seems to be present on most recent access points.