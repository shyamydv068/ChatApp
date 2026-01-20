# Malware Analysis — CTF Lab Quick-Start Guide

A compact, easy-to-read README for analysts working in a malware analysis / CTF lab. Focuses on safe setup, fast triage, core techniques, essential commands, YARA usage, and a one-page cheat-sheet you can memorize.

> WARNING: Always analyze malware in isolated, disposable environments (VM snapshots, air-gapped when possible). Never run unknown samples on production or personal machines.

---

## Goals
- Quickly triage CTF/contest samples and extract IOCs.
- Learn core static, dynamic, memory, and network techniques.
- Use YARA to detect and classify samples.
- Produce reproducible notes and artifacts for writeups.

---

## Lab setup (minimal, reproducible)
- Host OS: Linux or macOS (keeps VMs separated).
- VMs:
  - Analysis Windows VM (FLARE VM or clean Windows) — for running/testing Windows malware.
  - REMnux (Linux) — for reversing, scripts, YARA, network tooling.
  - Kali or a dedicated monitoring VM — for network captures, tooling.
- Network:
  - Isolated LAN or NAT with controlled DNS/proxy (mitmproxy or DNS sinkhole).
  - Option: capture-only bridge to host (tcpdump/Wireshark).
- Snapshots: create a snapshot before every experiment; revert after use.
- Tools to install (quick):
  - Static: file, strings, exiftool, binwalk, pefile (Python)
  - Reverse: rizin/radare2, Ghidra, x64dbg (Windows)
  - Dynamic: Sysinternals (Procmon, procexp), strace/ltrace (Linux)
  - Memory: Volatility3, DumpIt
  - Network: tcpdump, tshark, Wireshark, mitmproxy
  - Sandbox: Cuckoo (optional), Any.Run (web)
  - Detection: yara, yara-python, suricata (optional)

---

## Fast triage workflow (5–10 minutes)
1. Collect
   - Copy sample to analysis VM; compute hashes.
   - Save original filename, SHA256, acquisition time.
   - Example: `sha256sum sample.exe`
2. Static quick checks
   - File type: `file sample.exe`
   - Strings: `strings -a -n 8 sample.exe | less`
   - PE info (Python/pefile) or `rizin -v sample.exe`
   - Check YARA: `yara -s rules.yar sample.exe`
   - Check VirusTotal / any.run only for extra signal.
3. Decide: if trivial (known malware), document and move to IOC extraction. If unknown or packed → dynamic.
4. Dynamic (in snapshot)
   - Start Procmon, Wireshark/tcpdump.
   - Execute sample in VM (no creds); monitor processes, files, registry, network.
   - Capture pcap: `tcpdump -i eth0 -w capture.pcap host attacker.example.com`
5. Memory & deeper
   - Dump memory: DumpIt (Windows).
   - Run Volatility yarascan / malfind.
   - Re-scan dropped files and memory with YARA.
6. Extract IOCs
   - Domains, IPs, hashes, file paths, mutexes, registry keys.
7. Report / Writeup
   - Document steps, artifacts, commands, and final verdict.

---

## Essential commands (copy-paste)

Hashes
```
sha256sum sample.bin
# PowerShell
Get-FileHash .\sample.exe -Algorithm SHA256
```

Static
```
file sample.bin
strings -a -n 8 sample.exe | less
7z l suspicious.zip
olevba suspicious.docm
```

PE / imports (Python)
```
python - <<'PY'
import pefile
pe = pefile.PE('sample.exe')
for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
    print(entry.dll)
PY
```

Dynamic (Windows)
```
# start Procmon (GUI) and capture events, then run sample
procdump -ma <pid> dump.dmp
```

Dynamic (Linux)
```
strace -ff -o trace.out ./sample
ltrace -o ltrace.out ./sample
```

Network
```
tcpdump -i eth0 -w capture.pcap host suspicious.example.com
tshark -r capture.pcap -Y "http || dns" -V
```

Memory & volatility
```
# capture memory with DumpIt on Windows, then:
volatility3 -f mem.raw windows.pslist.PsList
volatility3 -f mem.raw windows.malfind.Malfind
# yarascan example (volatility or direct):
yara -s rules.yar mem.raw
```

YARA
```
yara -s rules.yar sample.exe
yara -r rules.yar samples/
```

---

## YARA: quick examples & workflow

Simple YARA rule (HTTP beacon)
```yara
rule Suspicious_HTTP_Beacon {
  meta:
    author = "ctf-lab"
    desc = "Detects simple HTTP beacon"
  strings:
    $a = "POST /api/heartbeat" ascii nocase
    $b = "User-Agent: Mozilla/5.0 (Windows NT" ascii
  condition:
    any of ($a, $b) and filesize < 5MB
}
```

PE API-based rule
```yara
import "pe"
rule PE_Injection_APIs {
  meta: author="ctf-lab"
  strings:
    $s1 = "CreateRemoteThread" ascii nocase
    $s2 = "VirtualAlloc" ascii nocase
  condition:
    pe and any of ($s1, $s2) and filesize < 10MB
}
```

Scan workflow
1. Run `yara -s` on the sample to get matched strings and offsets.
2. If YARA hits in memory dumps, follow pointer to process/region and extract strings.
3. Put YARA rules under version control; test them against clean corpora (to reduce false positives).

Programmatic scan example (Python)
```python
import yara, os, json
rules = yara.compile(filepath='rules.yar')
out = []
for root,_,files in os.walk('samples'):
  for f in files:
    path = os.path.join(root,f)
    try:
      m = rules.match(path)
      if m: out.append({"file":path,"rules":[r.rule for r in m]})
    except Exception as e:
      print("err",path,e)
print(json.dumps(out,indent=2))
```

---

## Memory-focused tips (CTF useful)
- Many CTFs use packed/encrypted payloads; strings on disk may be minimal — always dump memory after execution.
- Use Volatility's malfind and yarascan to find injected/decrypted code segments.
- When you find a region with suspect strings, dump it (`volatility dumpfiles` or raw offset extraction) and analyze it as a binary.

---

## Common techniques you'll encounter (and what to look for)
- Packers/obfuscation: high entropy sections, few imports → try UPX, dynamic unpacking.
- LOLbins (living-off-the-land): PowerShell, certutil, rundll32 → check command-line telemetry.
- Process injection: missing file artifacts but suspicious network/activity → check memory and parent/child relationships.
- C2 over HTTP(S)/DNS: look for regular beacons or encoded query strings.

---

## Minimal test harness for rules (CTF-friendly)
1. Create `tests/samples/` with a few known "malicious" test files and clean binaries.
2. Use the Python test script from the YARA section to ensure rules trigger on malice and not on clean files.
3. Add a small `README` entry documenting test expectations.

---

## One-page cheat-sheet (memorize)
- Save sample → hash it → file/strings → yara scan → run in snapshot → capture proc & pcap → dump memory → volatility yarascan → extract IOCs → document.
- Quick red flags: strange imports, CreateRemoteThread, VirtualAlloc, encoded PowerShell, new domain, high entropy section.

---

## Recording & writeups (CTF submissions)
- Keep a reproducible notebook: commands, VM snapshot id, pcap, memory dumps, procmon logs, and final verdict.
- Include: SHA256, YARA hits, key strings, network endpoints, brief behavior summary, and reproduction steps.

---

## References & quick links
- REMnux — https://remnux.org
- FLARE VM — https://github.com/mandiant/flare-vm
- YARA — https://github.com/VirusTotal/yara
- Volatility3 — https://github.com/volatilityfoundation/volatility3
- Cuckoo Sandbox — https://cuckoosandbox.org

---

If you want, I can:
- Generate a repo skeleton (rules/, tests/, lab-notes/) with example rules and test samples.
- Produce a printable one-page cheat-sheet PDF for lab benches.
Which do you prefer?
