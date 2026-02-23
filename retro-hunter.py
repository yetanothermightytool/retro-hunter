#!/usr/bin/env python3
import os
import subprocess
import argparse
import datetime
import time
import signal
import socket
import logging
import requests
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from dateutil import parser as dtparser
import concurrent.futures

# Load variables from .env.local
load_dotenv(dotenv_path=".env.local")

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Script variables
api_url      = os.getenv("VEEAM_API_URL")
api_version  = "1.3-rev0"
mnt_base     = "/mnt"
results_dir  = "/tmp/output"
scanner_path = "./scanner.py"

# Logging setup
def setup_logging(hostname=None, verbose=False):
   os.makedirs(results_dir, exist_ok=True)
   level = logging.DEBUG if verbose else logging.INFO
   handlers = [logging.StreamHandler()]
   if hostname:
       handlers.append(logging.FileHandler(os.path.join(results_dir, f"{hostname}.log")))
   logging.basicConfig(
       level=level,
       format="%(asctime)s [%(levelname)s] %(message)s",
       datefmt="%Y-%m-%dT%H:%M:%S",
       handlers=handlers
   )

log = logging.getLogger(__name__)

# Get local IP for iSCSI Mount
def get_local_ip():
   s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   try:
       s.connect(("1.1.1.1", 80))
       return s.getsockname()[0]
   finally:
       s.close()

# Get Veeam REST API Bearer Token
def connect_veeam_rest_api(api_url, username, password):
   url = f"{api_url}/api/oauth2/token"
   headers = {
       "Content-Type": "application/x-www-form-urlencoded",
       "x-api-version": api_version,
       "accept": "application/json"
   }
   data = {"grant_type": "password", "username": username, "password": password}
   try:
       response = requests.post(url, headers=headers, data=data, verify=False)
       response.raise_for_status()
       return response.json()["access_token"]
   except requests.RequestException as e:
       log.error(f"Authentication failed: {e}")
       raise

# Get encrypted password (Fernet)
def get_password():
   with open("encryption_key.key", "rb") as key_file:
       key = key_file.read()
   with open("encrypted_password.bin", "rb") as password_file:
       encrypted_password = password_file.read()
   return Fernet(key).decrypt(encrypted_password).decode()

# Veeam REST API GET Function
def get_veeam_rest_api(api_url, endpoint, token, params=None):
   url = f"{api_url}/api/{endpoint}"
   headers = {
       "accept": "application/json",
       "x-api-version": api_version,
       "Authorization": f"Bearer {token}"
   }
   try:
       response = requests.get(url, headers=headers, params=params, verify=False)
       response.raise_for_status()
       return response.json()
   except requests.RequestException as e:
       log.error(f"GET {endpoint} failed: {e}")
       raise

# Veeam REST API POST Function
def post_veeam_rest_api(api_url, endpoint, token, body):
   url = f"{api_url}/api/{endpoint}"
   headers = {
       "accept": "application/json",
       "x-api-version": api_version,
       "Content-Type": "application/json",
       "Authorization": f"Bearer {token}"
   }
   try:
       response = requests.post(url, headers=headers, json=body, verify=False)
       response.raise_for_status()
       return response.json()
   except requests.RequestException as e:
       log.error(f"POST {endpoint} failed: {e}")
       raise

# Veeam REST API Logout
def post_logout(api_url, token):
   url = f"{api_url}/api/oauth2/logout"
   headers = {
       "accept": "application/json",
       "x-api-version": api_version,
       "Authorization": f"Bearer {token}"
   }
   requests.post(url, headers=headers, verify=False)
   log.info("Logout successful.")

# Display Veeam Backup & Replication Restore Points
def display_restore_points(restorePoint):
   print("\n{:<5} {:<25} {:<20} {:<15} {:<15}".format(
       "Index", "Hostname", "Creation Time", "Malware Status", "Backup Type"))
   print("-" * 85)
   for idx, point in enumerate(restorePoint["data"][:10]):
       time_str = dtparser.isoparse(point["creationTime"]).strftime("%Y-%m-%d %H:%M:%S")
       status = point["malwareStatus"]
       status_display = "✅ Clean" if status.lower() == "clean" else "🐞 " + status

       backup_type = point.get("type", "unknown").lower()
       if "full" in backup_type:
           type_display = "Full"
       elif "increment" in backup_type:
           type_display = "Incremental"
       else:
           type_display = backup_type.capitalize()

       print("{:<5} {:<25} {:<20} {:<15} {:<15}".format(
           idx, point["name"], time_str, status_display, type_display))

class TimeoutException(Exception): pass
def timeout_handler(signum, frame): raise TimeoutException

def select_restore_point(restorePoint):
   max_index = min(len(restorePoint["data"]), 10) - 1
   try:
       signal.signal(signal.SIGALRM, timeout_handler)
       print(f"\n⏳ You have 15 seconds to select. (Default 0 if nothing selected)")
       signal.alarm(15)
       choice = input(f"❓ Enter number (0-{max_index}): ")
       signal.alarm(0)
       index = int(choice) if choice.isdigit() else 0
       if index < 0 or index > max_index:
           log.warning(f"Invalid selection {index}, defaulting to 0.")
           return 0
       return index
   except TimeoutException:
       print("⏱️ Timeout – using Index 0")
       return 0

# Run Scanner Script
def run_scanner(mount_path, host2scan, workers, yaramode, rp_id, rp_ts, rp_status, csv_path=None):
   if not os.path.exists(scanner_path):
       log.error("scanner.py not found.")
       return
   cmd = [
       "sudo", "python3", scanner_path,
       "--mount", mount_path,
       "--workers", str(workers),
       "--yara", str(yaramode),
       "--hostname", str(host2scan),
       "--restore_point_id", str(rp_id) or "",
       "--rp_timestamp", str(rp_ts) or "",
       "--rp_status", str(rp_status) or "",
   ]
   if csv_path:
       cmd.extend(["--csv", str(csv_path)])
   log.info(f"[{host2scan}] Scanning mount: {mount_path}")
   subprocess.run(cmd)

# Run Store Script
def run_store(mount_path, host2scan, rp_id, rp_ts, rp_status):
   store_script = "./store.py"
   if not os.path.exists(store_script):
       log.error("store.py not found.")
       return
   cmd = [
       "python3", store_script,
       "--mount", str(mount_path),
       "--hostname", str(host2scan),
       "--restorepoint-id", str(rp_id),
       "--rp-timestamp", str(rp_ts),
       "--rp-status", str(rp_status),
   ]
   log.info(f"[{host2scan}] Indexing files from mount {mount_path}")
   subprocess.run(cmd)

# Run Event Parser Script
def run_evtscan(mount_path, host2scan, rp_id, rp_ts, rp_status, days=None, evtlogs=None):
   evt_script = "./event-parser.py"
   if not os.path.exists(evt_script):
       log.error("event-parser.py not found.")
       return

   logs_to_scan = ["Security.evtx"]
   if evtlogs:
       logs_to_scan = [l.strip() for l in evtlogs.split(",") if l.strip()]

   for logname in logs_to_scan:
       cmd = [
           "python3", evt_script,
           "--mount", str(mount_path),
           "--hostname", str(host2scan),
           "--restorepoint-id", str(rp_id),
           "--rp-timestamp", str(rp_ts),
           "--rp-status", str(rp_status),
           "--logfile", logname
       ]
       if days:
           cmd.extend(["--days", str(days)])
       log.info(f"[{host2scan}] Parsing {logname} from mount {mount_path}")
       subprocess.run(cmd)

# Run Registry Scan
def run_regscan(mount_path, host2scan, rp_id, rp_ts, rp_status):
   store_script = "./registry-scan.py"
   if not os.path.exists(store_script):
       log.error("registry-scan.py not found.")
       return
   cmd = [
       "python3", store_script,
       "--mount", str(mount_path),
       "--hostname", str(host2scan),
       "--restorepoint-id", str(rp_id),
       "--rp-timestamp", str(rp_ts),
       "--rp-status", str(rp_status),
   ]
   log.info(f"[{host2scan}] Getting Windows Registry keys from mount {mount_path}")
   subprocess.run(cmd)

# Run iSCSI Scan
def run_iscsi_scan(mount_id, session_info, host2scan, workers, yaramode, args, rp_id, rp_ts, rp_status):
   before = subprocess.check_output("lsblk -nd -o NAME", shell=True).decode().splitlines()
   ip = session_info["serverIps"][0]
   port = session_info["serverPort"]
   log.info(f"[{host2scan}] iSCSI login to {ip}:{port}")
   subprocess.run(f"sudo iscsiadm -m discovery -t sendtargets -p {ip}:{port}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
   subprocess.run(f"sudo iscsiadm -m node -p {ip}:{port} -l", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
   time.sleep(10)

   after = subprocess.check_output("lsblk -nd -o NAME", shell=True).decode().splitlines()
   new_disks = [dev for dev in after if dev not in before]
   if not new_disks:
       log.error(f"[{host2scan}] No new iSCSI disks found.")
       return

   mounted_paths = []
   for dev in new_disks:
       for part in range(1, 5):
           dev_path = f"/dev/{dev}{part}"
           if not os.path.exists(dev_path):
               continue
           try:
               fs_type = subprocess.check_output(f"lsblk -no FSTYPE {dev_path}", shell=True).decode().strip()
               if fs_type in ("ntfs", "xfs", "ext4"):
                   mnt_path = os.path.join(mnt_base, f"{host2scan}_{dev}{part}")
                   os.makedirs(mnt_path, exist_ok=True)
                   subprocess.run(f"sudo mount -t {fs_type} {dev_path} {mnt_path}", shell=True)
                   log.info(f"[{host2scan}] ✅ Mounted {dev_path} -> {mnt_path}")
                   mounted_paths.append(mnt_path)
           except Exception as e:
               log.warning(f"[{host2scan}] Skipping {dev_path}: {e}")
               continue

   log.info(f"[{host2scan}] Running scan on mounted volumes [iSCSI]...")
   for mnt_path in mounted_paths:
       if args.scan:
           run_scanner(mnt_path, host2scan, workers, yaramode, rp_id, rp_ts, rp_status, args.csv)
       if args.store:
           run_store(mnt_path, host2scan, rp_id, rp_ts, rp_status)
       if args.evtscan:
           run_evtscan(mnt_path, host2scan, rp_id, rp_ts, rp_status, args.days, args.evtlogs)
       if args.regscan:
           run_regscan(mnt_path, host2scan, rp_id, rp_ts, rp_status)
   time.sleep(10)

   log.info(f"[{host2scan}] Cleaning up...")
   for path in mounted_paths:
       subprocess.run(f"sudo umount {path}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
       subprocess.run(f"sudo rmdir {path}", shell=True)

   subprocess.run(f"sudo iscsiadm -m node -p {ip}:{port} -u", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
   subprocess.run(f"sudo iscsiadm -m node -p {ip}:{port} -o delete", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Run Mount & Scan
def do_mount_scan(token, scanhost, local_ip, rp_id, hostname, use_iscsi, workers, yaramode, args, rp_ts, rp_status):
   setup_logging(hostname=hostname, verbose=getattr(args, "verbose", False))

   mount_body = {
       "restorePointId": rp_id,
       "type": "ISCSITarget" if use_iscsi else "FUSELinuxMount",
       "targetServerName": scanhost,
       "targetServerCredentialsId": get_veeam_rest_api(api_url, "v1/backupInfrastructure/managedServers", token, params={"nameFilter": scanhost})["data"][0]["credentialsId"],
       "allowedIps": [local_ip]
   }

   if args.dryrun:
       log.info(f"[{hostname}] Dry run – would mount restore point {rp_id} from {rp_ts}")
       return

   log.info(f"[{hostname}] Publishing disk content...")
   try:
       mount_resp = post_veeam_rest_api(api_url, "v1/dataIntegration/publish", token, body=mount_body)
   except Exception as e:
       log.error(f"[{hostname}] Failed to publish: {e}")
       return

   mount_id = mount_resp.get("id")
   log.info(f"[{hostname}] Waiting for mount to become ready...")

   max_attempts = 6
   delay_sec = 10

   for attempt in range(max_attempts):
       try:
           mount_info = get_veeam_rest_api(api_url, f"v1/dataIntegration/{mount_id}", token)
           disks = mount_info.get("info", {}).get("disks", [])
           if disks or mount_info.get("info", {}).get("mountPath"):
               log.info(f"[{hostname}] Mount is ready after {attempt + 1} attempt(s).")
               break
           else:
               log.info(f"[{hostname}] Attempt {attempt + 1}/{max_attempts}: Still waiting...")
       except Exception as e:
           log.warning(f"[{hostname}] API error during mount check: {e}")
       time.sleep(delay_sec)
   else:
       log.error(f"[{hostname}] Mount did not become ready after {max_attempts * delay_sec}s. OS might not be supported.")
       return

   if use_iscsi:
       run_iscsi_scan(mount_id, mount_info.get("info", {}), hostname, workers, yaramode, args, rp_id, rp_ts, rp_status)
   else:
       all_mounts = []
       disks = mount_info.get("info", {}).get("disks", [])
       for disk in disks:
           all_mounts.extend(disk.get("mountPoints", []))

       if not all_mounts:
           fallback_mount = mount_info.get("info", {}).get("mountPath")
           if fallback_mount and os.path.exists(fallback_mount):
               log.warning(f"[{hostname}] No mount points returned by API. Falling back to mount path {fallback_mount}")
               all_mounts = [fallback_mount]
           else:
               log.error(f"[{hostname}] No usable mount path found. Skipping.")
               return

       for path in sorted(all_mounts):
           if args.scan:
               log.info(f"[{hostname}] Running scan on {path} [FUSE]...")
               run_scanner(path, hostname, workers, yaramode, rp_id, rp_ts, rp_status, args.csv)
           if args.store:
               run_store(path, hostname, rp_id, rp_ts, rp_status)
           evtx_file = os.path.join(path, "Windows", "System32", "winevt", "Logs", "Security.evtx")
           if os.path.exists(evtx_file):
               if args.evtscan:
                   run_evtscan(path, hostname, rp_id, rp_ts, rp_status, args.days, args.evtlogs)
           if args.regscan:
               run_regscan(path, hostname, rp_id, rp_ts, rp_status)

   time.sleep(10)
   log.info(f"[{hostname}] Unpublishing...")
   time.sleep(3)
   post_veeam_rest_api(api_url, f"v1/dataIntegration/{mount_id}/unpublish", token, body=mount_body)
   log.info(f"[{hostname}] Unpublished.")

def main():
   parser = argparse.ArgumentParser(description="VBR Scanner - Powered by Veeam Data Integration API")
   parser.add_argument("--host2scan", help="Specify host to scan")
   parser.add_argument("--repo2scan", help="Specify repository to scan hosts from")
   parser.add_argument("--all", action="store_true", help="Scan all valid hosts from the repo")
   parser.add_argument("--iscsi", action="store_true", help="Use iSCSI instead of FUSE")
   parser.add_argument("--maxhosts", type=int, default=1, help="Max parallel hosts to scan (default 1)")
   parser.add_argument("--workers", default=4, help="Number of workers for scanning (default 4)")
   parser.add_argument("--yaramode", default="off", help="YARA scan mode: off (default), all, suspicious, content, highentropy")
   parser.add_argument("--scan", action="store_true", help="Run scanner.py after mount")
   parser.add_argument("--store", action="store_true", help="Run store.py after mount")
   parser.add_argument("--csv", help="Save results to CSV file (optional)")
   parser.add_argument("--evtscan", action="store_true", help="Run event-parser.py after mount")
   parser.add_argument("--regscan", action="store_true", help="Run registry-scan.py after mount")
   parser.add_argument("--evtlogs", help="Comma-separated list of EVTX log files to scan")
   parser.add_argument("--days", type=int, help="Limit EVTX parsing to events within N days before restore point")
   parser.add_argument("--dryrun", action="store_true", help="Show what would be scanned without actually mounting")
   parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
   args = parser.parse_args()

   setup_logging(verbose=args.verbose)

   username = os.getenv("VEEAM_API_USER")
   if not username:
       log.error("VEEAM_API_USER not set in .env.local")
       return None
   password = get_password()

   log.info("🐻 Getting Bearer Token...")
   token = connect_veeam_rest_api(api_url, username, password)

   scanhost = socket.gethostname()
   local_ip = get_local_ip()
   valid_platforms = ["VMware", "HyperV", "WindowsPhysical", "LinuxPhysical"]

   if args.repo2scan:
       log.info(f"Looking up repository: {args.repo2scan}")
       all_repos = get_veeam_rest_api(api_url, "v1/backupInfrastructure/repositories", token)

       repo = next((r for r in all_repos["data"] if r["name"].strip() == args.repo2scan.strip()), None)
       if not repo:
           all_sobr = get_veeam_rest_api(api_url, "v1/backupInfrastructure/scaleOutRepositories", token)
           sobr = next((s for s in all_sobr["data"] if s["name"].strip() == args.repo2scan.strip()), None)
           if not sobr:
               log.error("Repository not found (neither standard nor scale-out).")
               return token
           log.info("Found Scale-Out Repository.")
           extents = [e["id"] for e in sobr.get("performanceTier", {}).get("performanceExtents", [])]
           if not extents:
               log.error("No extents found in Scale-Out Repository.")
               return token
           backups = get_veeam_rest_api(api_url, "v1/backups", token)
           backup_ids = [b["id"] for b in backups["data"] if b["repositoryId"] == sobr["id"]]
       else:
           backups = get_veeam_rest_api(api_url, "v1/backups", token)
           backup_ids = [b["id"] for b in backups["data"] if b["repositoryId"] == repo["id"]]

       hostnames = []
       for bid in backup_ids:
           rps = get_veeam_rest_api(api_url, "v1/restorePoints", token, params={"backupIdFilter": bid})
           for rp in rps.get("data", []):
               if rp.get("platformName", "") in valid_platforms:
                   hostnames.append(rp["name"])

       if not hostnames:
           log.error("No valid restore points in this repository.")
           return token

       hostnames = sorted(set(hostnames))

       if args.all:
           log.info(f"Scanning latest restore point of {len(hostnames)} valid host(s)...")
           with concurrent.futures.ThreadPoolExecutor(max_workers=args.maxhosts) as executor:
               futures = []
               for host in hostnames:
                   query = {
                       "skip": "0", "limit": "1", "orderColumn": "CreationTime",
                       "orderAsc": "false", "nameFilter": host
                   }
                   rp = get_veeam_rest_api(api_url, "v1/restorePoints", token, params=query)
                   if rp.get("data"):
                       restore_id = rp["data"][0]["id"]
                       ts = dtparser.isoparse(rp["data"][0]["creationTime"]).strftime("%Y-%m-%d %H:%M:%S")
                       rp_status = rp["data"][0].get("malwareStatus", "unknown")
                       futures.append(executor.submit(
                           do_mount_scan, token, scanhost, local_ip,
                           restore_id, host, args.iscsi, args.workers,
                           args.yaramode, args, ts, rp_status
                       ))
               for f in concurrent.futures.as_completed(futures):
                   try:
                       f.result()
                   except Exception as e:
                       log.error(f"Host scan failed: {e}")
           return token

       log.info(f"\n{len(hostnames)} host(s) found in repository:")
       for idx, name in enumerate(hostnames):
           print(f"  {idx}. {name}")
       selected = select_restore_point({
           "data": [{"name": name, "creationTime": datetime.datetime.now().isoformat(), "malwareStatus": "unknown", "type": "unknown"} for name in hostnames]
       })
       args.host2scan = hostnames[selected]
       log.info(f"Selected host: {args.host2scan}")

   if args.host2scan:
       rp_query = {
           "skip": "0", "limit": "10",
           "orderColumn": "CreationTime", "orderAsc": "false",
           "nameFilter": args.host2scan
       }
       log.info(f"Getting 10 latest restore points for {args.host2scan}...")
       restorePoint = get_veeam_rest_api(api_url, "v1/restorePoints", token, params=rp_query)
       if not restorePoint.get("data"):
           log.error("No restore points found.")
           return token

       display_restore_points(restorePoint)
       selected = select_restore_point(restorePoint)
       selected_rp = restorePoint["data"][selected]
       ts = dtparser.isoparse(selected_rp["creationTime"]).strftime("%Y-%m-%d %H:%M:%S")
       rp_id = selected_rp["id"]
       rp_status = selected_rp.get("malwareStatus", "unknown")

       log.info(f"Selected restore point {rp_id} created on {ts}")
       do_mount_scan(token, scanhost, local_ip, rp_id, args.host2scan, args.iscsi, args.workers, args.yaramode, args, ts, rp_status)
       return token

   log.error("You must specify either --host2scan or --repo2scan")
   return token

if __name__ == "__main__":
   token = main()
   if token:
       log.info("Logout...")
       post_logout(api_url, token)
