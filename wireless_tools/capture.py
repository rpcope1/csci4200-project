from pyric import pyw
import pcapy
import time
import os
import argparse
import logging

MiB = 1024 * 1024

DEFAULT_CAPTURE_CHANNELS = (
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
)

capture_logger = logging.getLogger(__name__)


def setup_device(device_name):
    dev = pyw.getcard(device_name)

    assert 'monitor' in pyw.devmodes(dev)
    if pyw.modeget(dev) != 'monitor':
        capture_logger.info("Setting device {0} to monitor mode.".format(device_name))
        pyw.down(dev)
        pyw.modeset(dev, 'monitor')
        pyw.up(dev)
    else:
        capture_logger.info("Device {0} already in monitor mode.".format(device_name))
    return dev


def capture_channel(device, device_name, channel, output_file, sample_seconds, supported_channels=None):
    capture_logger.info(
        "Beginning capture of channel {0} with device {1} for {2} seconds".format(channel, device_name, sample_seconds)
    )
    if supported_channels is not None:
        assert channel in supported_channels

    pyw.chset(device, channel)
    capture = pcapy.create(device_name)
    capture.set_snaplen(65535)
    capture.set_timeout(0)
    capture.set_promisc(True)
    capture.set_buffer_size(30 * MiB)

    capture_count = 0

    start_time = time.time()

    capture.activate()
    dumper = capture.dump_open(output_file)

    header, data = capture.next()

    current_time = time.time()
    while header and (current_time - start_time) <= sample_seconds:
        dumper.dump(header, data)
        header, data = capture.next()
        current_time = time.time()
        capture_count += 1
    capture_logger.info("{0} packets captured.".format(capture_count))
    dumper.close()
    capture.close()
    return capture_count


def run_capture(device_name, output_dir, sample_seconds, file_prefix="", channels=DEFAULT_CAPTURE_CHANNELS):
    os.makedirs(output_dir, exist_ok=True)
    dev = setup_device(device_name)

    supported_channels = pyw.devchs(dev)

    for channel in channels:
        output_file = os.path.join(output_dir, file_prefix + "channel-{0}.pcap".format(channel))
        capture_channel(
            dev, device_name, channel, output_file, sample_seconds, supported_channels=supported_channels
        )


def attach_run_capture(subparser: argparse.ArgumentParser):
    def func(args):
        return run_capture(
            args.device_name,
            args.output_dir,
            args.sample_seconds,
            channels=args.channel
        )

    subparser.set_defaults(func=func)
    subparser.add_argument("device_name", type=str, help="The wireless device name.")
    subparser.add_argument("output_dir", type=str, help="The output directory to write pcap files to.")
    subparser.add_argument("sample_seconds", type=int, help="The number of seconds per channel to capture data for.")
    subparser.add_argument(
        "-c", "--channel", type=int, nargs="+", default=DEFAULT_CAPTURE_CHANNELS,
        help="Channels to monitor while capturing."
    )
