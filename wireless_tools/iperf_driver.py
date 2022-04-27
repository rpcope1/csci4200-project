import paramiko
import re
import time
import threading

csv_regex = re.compile("(?P<timestamp>[^,]+),(?P<source_addr>[^,]+),(?P<source_port>[^,]+),(?P<dest_addr>[^,]+),"
                       "(?P<dest_port>[^,]+),(?P<transfer_id>[^,]+),(?P<interval>[^,]+),(?P<transferred_bytes>[^,]+),"
                       "(?P<bits_per_second>[^\n,]+)([^\n]*)\n")


def build_iperf_client_args(remote_host, bandwidth=None, port=None, udp_mode=False, dual_test=False,
                            time=None, parallel=None, reverse=False, enhanced=False, tos_value=None, extra_args=None):
    args = ["-c", str(remote_host), "-y", "C"]
    if bandwidth is not None:
        args.extend(["-b", str(bandwidth)])
    if port is not None:
        args.extend(["-p", str(port)])
    if udp_mode:
        args.append("-u")
    if dual_test:
        args.append("-d")
    if time is not None:
        args.extend(["-t", str(time)])
    if parallel is not None:
        args.extend(["-P", str(parallel)])
    if reverse:
        args.append("-R")
    if enhanced:
        args.append("-e")
    if tos_value is not None:
        args.extend(["-S", str(tos_value)])
    if extra_args is not None:
        args.extend(extra_args)
    return " ".join(args)


def run_iperf_client(hostname, port, username, pword, remote_iperf_host, bandwidth=None,
                     iperf_port=None, udp_mode=False, dual_test=False, time=None, parallel=None, reverse=False,
                     enhanced=False, tos_value=None, extra_args=None):
    s = paramiko.SSHClient()
    s.load_system_host_keys()
    s.connect(hostname, port, username, pword)
    (stdin, stdout, stderr) = s.exec_command(("timeout {0} iperf ".format(time or 10)) + build_iperf_client_args(
        remote_iperf_host, bandwidth=bandwidth, port=iperf_port, udp_mode=udp_mode,
        dual_test=dual_test, time=time, parallel=parallel, reverse=reverse,
        enhanced=enhanced, tos_value=tos_value, extra_args=extra_args
    ) + " && sleep 1")
    results = []
    for line in stdout.readlines():
        match = csv_regex.match(line)
        if match:
            results.append(match.groupdict())
    s.close()
    return results
