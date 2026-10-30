# 🐺 CERBERUS

## eBPF-Based Intrusion Prevention System for Linux

Cerberus is a Linux-based **Intrusion Prevention System (IPS)** built using **eBPF and BPF LSM**.

Unlike traditional monitoring systems that only observe suspicious activity, Cerberus can actively participate in Linux security decisions and **block unauthorized operations before they are completed**.

The project currently demonstrates real-time **file access monitoring and prevention** using an eBPF program running inside the Linux kernel.

---

# 🎯 Project Goal

The goal of Cerberus is to build a lightweight, real-time Intrusion Prevention System using eBPF.

The project evolves through the following stages:

```text
Monitoring
    ↓
Detection
    ↓
Prevention
    ↓
Dynamic Security Policies
    ↓
Complete IPS Architecture
```

Instead of continuously polling system activity from user space, Cerberus attaches eBPF programs directly to kernel events and security hooks.

This allows the system to inspect operations with very low overhead.

---

# 🧠 Core Concept

The basic architecture of Cerberus is:

```text
                 USER SPACE
┌───────────────────────────────────────┐
│                                       │
│         Cerberus Agent (C++)          │
│                                       │
│  • Loads eBPF program                 │
│  • Receives security events           │
│  • Displays blocked activity          │
│  • Will manage security policies      │
│                                       │
└───────────────────▲───────────────────┘
                    │
                    │ Ring Buffer
                    │
┌───────────────────┴───────────────────┐
│                                       │
│             KERNEL SPACE              │
│                                       │
│         Cerberus eBPF Program         │
│                                       │
│  • Intercepts security operations     │
│  • Inspects file access               │
│  • Applies security rules             │
│  • Allows or blocks operations        │
│                                       │
└───────────────────▲───────────────────┘
                    │
                    │
              Linux Kernel
                    │
                    │
              User Process
```

---

# 🛠️ Technology Stack

| Technology     | Purpose                                         |
| -------------- | ------------------------------------------------ |
| **C**          | eBPF kernel program                             |
| **C++**        | User-space Cerberus agent                       |
| **eBPF**       | Safe programmable logic inside the Linux kernel |
| **BPF LSM**    | Security enforcement and blocking               |
| **libbpf**     | Communication between user space and eBPF       |
| **bpftool**    | BPF inspection and skeleton generation          |
| **Clang/LLVM** | Compiling C code into BPF bytecode              |
| **CO-RE**      | Kernel compatibility using BTF information      |

---

# 📂 Project Structure

```text
cerberus/
│
├── build/
│   ├── cerberus_agent
│   ├── ips_core.bpf.o
│   └── ips_core.skel.h
│
├── headers/
│   └── vmlinux.h
│
├── include/
│   └── cerberus/
│       └── common.h          shared kernel/user ABI
│
├── src/
│   ├── bpf/                  kernel-side eBPF
│   │   ├── ips_core.bpf.c    single BPF translation unit
│   │   ├── maps.bpf.h        map definitions
│   │   ├── helpers.bpf.h     events + rule key builders
│   │   ├── rules.bpf.h       rule/sandbox matching logic
│   │   └── hooks/
│   │       ├── file_open.bpf.h
│   │       └── socket_connect.bpf.h
│   │
│   └── agent/                user-space agent
│       ├── main.cpp          lifecycle, signals, main loop
│       ├── bpf_loader.{h,cpp} skeleton load/attach + map FDs
│       ├── policy.{h,cpp}    rule codec + map operations
│       ├── config.{h,cpp}    policy file parsing
│       ├── events.{h,cpp}    ring buffer + alert output
│       ├── cli.{h,cpp}       interactive commands/status
│       └── util.h            shared text helpers
│
├── tests/
│   ├── test_cli.sh
│   ├── test_phase35.sh
│   ├── test_phase4.sh
│   └── test_net.sh
│
├── blocklist.example.txt
├── Makefile
├── .gitignore
└── README.md
```

---

# 🧩 Module Architecture

The codebase is split by responsibility rather than by
file size, and the split preserves the single BPF
translation unit that owns all maps.

```text
                        USER SPACE
┌──────────────────────────────────────────────────┐
│  main.cpp        lifecycle, signals, event loop  │
│      │                                           │
│      ├── bpf_loader   skeleton, attach, map FDs  │
│      ├── config       policy-file parsing        │
│      ├── cli          command parsing/dispatch   │
│      ├── events       ring buffer + alerts       │
│      └── policy       rules + mode + rule views  │
│                                 (all share util) │
└───────────────────────▲──────────────────────────┘
                        │ ring buffer
┌───────────────────────┴──────────────────────────┐
│  BPF translation unit: src/bpf/ips_core.bpf.c    │
│      ├── maps.bpf.h       all map definitions    │
│      ├── helpers.bpf.h    emit_event, key build  │
│      ├── rules.bpf.h      deny/sandbox checks    │
│      └── hooks/file_open.bpf.h                   │
└──────────────────────────────────────────────────┘
```

The BPF object stays a single compilation unit so every
hook program shares the same maps and ring buffer; the
files are split by responsibility, not by object file.

To add a hook, create `src/bpf/hooks/<name>.bpf.h`
with its `SEC(...)` program, include it from
`ips_core.bpf.c`, and expose any new maps through
`src/agent/bpf_loader.cpp`. No map pinning or map-in-map
indirection is needed.

---

# 🧩 Components

## 1️⃣ `include/cerberus/common.h`

This file contains structures shared between:

* Kernel-space eBPF program
* User-space C++ agent

Current event structure:

```c
struct event {
    unsigned int pid;
    unsigned int uid;
    unsigned char denied;    /* 1 = blocked, 0 = monitor-only */
    unsigned char rule_type; /* NAME or PATH rule      */
    unsigned char evt_type;  /* FILE_OPEN (future: NET) */
    char comm[16];
    char rule[256];          /* matched rule key        */
};
```

### Why is this needed?

The kernel program sends security events to user space.

Both sides must understand the event data in the **same format**.

```text
Kernel creates:

struct event
        ↓
Ring Buffer
        ↓
User Space receives:

struct event
```

---

# 2️⃣ eBPF Kernel Program

Files:

```text
src/bpf/ips_core.bpf.c      entry translation unit
src/bpf/maps.bpf.h          all maps
src/bpf/helpers.bpf.h       events + key builders
src/bpf/rules.bpf.h         rule/sandbox matching
src/bpf/hooks/file_open.bpf.h
```

The `lsm/file_open` hook lives in
`src/bpf/hooks/file_open.bpf.h`; the other files are
included by the single translation unit so all hooks
share the same maps.

This is the core security enforcement component.

The current program attaches to:

```c
SEC("lsm/file_open")
```

This means Cerberus is attached to the Linux Security Module file-opening hook.

The flow is:

```text
Process attempts to open a file
            ↓
Linux performs security check
            ↓
LSM file_open hook
            ↓
Cerberus eBPF program runs
            ↓
Check security policy
            ↓
      ┌─────┴─────┐
      │           │
    ALLOW       BLOCK
      │           │
      ▼           ▼
Continue      Return -EPERM
                  ↓
           Operation denied
```

---

# 🛡️ Current Blocking Implementation

Rules are stored in a **BPF hash map** and can be changed at runtime without recompiling the eBPF program.

Two kinds of rules are supported:

```text
NAME rule
    "sensitive.txt"

    Matches that file name anywhere on the filesystem.

PATH rule
    "secrets/sensitive.txt"

    Matches that parent-directory / file-name pair
    anywhere on the filesystem.

    Stored as the last two components of the path.
```

Because file names can never contain `/`, the two rule shapes can share one map without ambiguity.

Cerberus runs in one of two modes, selected at runtime:

```text
MONITOR   -> report matching access, never deny  (default)
ENFORCE   -> report matching access and return -EPERM
```

The mode is a value in a BPF array map (`policy_mode`), so switching between observing and preventing does **not** require reloading the program.

When a rule matches, the eBPF program returns:

```c
return -EPERM;   /* ENFORCE mode */
```

`EPERM` means:

```text
Operation not permitted
```

Linux then denies the operation.

Example:

```text
cat: /tmp/sensitive.txt: Operation not permitted
```

This proves that Cerberus is performing **real prevention**, not just monitoring.

---

# 📡 Ring Buffer Communication

Cerberus uses a BPF Ring Buffer for communication between:

```text
Kernel Space
        ↓
User Space
```

The flow is:

```text
Suspicious Operation
        ↓
eBPF detects violation
        ↓
Create event
        ↓
Reserve Ring Buffer space
        ↓
Store PID
Store Process Name
Store Filename
        ↓
Submit event
        ↓
User-Space Agent receives event
        ↓
Display alert
```

Example output:

```text
[BLOCKED INTRUSION] PID: 1234 | UID: 1000 | Process: cat | Target: /tmp/sensitive.txt
[MONITOR ALERT]     PID: 1235 | UID: 1000 | Process: vim | Target: sensitive.txt
```

`BLOCKED INTRUSION` means the operation was denied.
`MONITOR ALERT` means the operation was reported but allowed.

---

# 🖥️ User-Space Agent

Files:

```text
src/agent/main.cpp        lifecycle, signals, main loop
src/agent/bpf_loader.*    skeleton load/attach, map FDs
src/agent/policy.*        rule codec, map operations, mode
src/agent/config.*        policy file loading
src/agent/events.*        ring buffer consumer + alerts
src/agent/cli.*           interactive commands and status
```

The user-space agent is responsible for:

* Loading the eBPF program
* Attaching the eBPF program
* Connecting to the Ring Buffer
* Receiving security events
* Displaying blocked activity
* Managing rules and policy mode

The agent uses the automatically generated BPF skeleton.

The flow is:

```text
Open BPF Skeleton
        ↓
Load BPF Program
        ↓
Attach Program to LSM Hook
        ↓
Connect to Ring Buffer
        ↓
Wait for Events
        ↓
Display Security Alerts
```

---

# 🦴 What is the BPF Skeleton?

The skeleton is automatically generated using:

```bash
bpftool gen skeleton
```

It provides an easy interface for the C++ application to interact with the eBPF program.

Instead of manually handling every BPF object and map, the agent can use functions such as:

```cpp
ips_core_bpf__open_and_load();
```

and:

```cpp
ips_core_bpf__attach();
```

Pipeline:

```text
src/bpf/ips_core.bpf.c
        ↓
Clang
        ↓
build/ips_core.bpf.o
        ↓
bpftool
        ↓
build/ips_core.skel.h
        ↓
src/agent/*.cpp
```

---

# ⚙️ Build Pipeline

Cerberus uses a `Makefile` to automate compilation.

The build process is:

```text
1. Generate vmlinux.h
        ↓
2. Compile eBPF C program
        ↓
3. Generate BPF skeleton
        ↓
4. Compile C++ agent
```

Detailed flow:

```text
Linux Kernel BTF
        ↓
bpftool
        ↓
headers/vmlinux.h
        ↓
────────────────────────────

src/bpf/ips_core.bpf.c
        ↓
clang -target bpf
        ↓
build/ips_core.bpf.o
        ↓
────────────────────────────

bpftool gen skeleton
        ↓
build/ips_core.skel.h
        ↓
────────────────────────────

src/agent/*.cpp
        ↓
g++
        ↓
build/cerberus_agent
```

---

# 🚀 Building the Project

## Clean previous build

```bash
make clean
```

## Build Cerberus

```bash
make
```

Expected pipeline:

```text
Generate vmlinux.h
        ↓
Compile BPF program
        ↓
Generate skeleton
        ↓
Compile Cerberus agent
```

---

# ▶️ Running Cerberus

Run the agent with root privileges:

```bash
sudo ./build/cerberus_agent
```

Optionally, pass a policy file as the first argument:

```bash
sudo ./build/cerberus_agent /etc/cerberus/blocklist.txt
```

Without an argument, the agent tries to load `blocklist.txt` from the working directory.

Expected output:

```text
[+] Loaded 2 rule(s) from blocklist.txt

[+] Cerberus BPF IPS is ACTIVE.
[+] Mode: MONITOR (matching access is only reported)
[+] Type 'help' for commands.

cerberus>
```

Keep this terminal running.

### Interactive CLI

The `cerberus>` prompt is displayed as soon as the BPF
program is active, before any input is typed:

```text
cerberus> help
cerberus> addpath /tmp/sensitive.txt
cerberus> mode enforce
cerberus> status
cerberus> quit
```

Commands never block event delivery. A pasted batch of
commands is processed line by line, and commands can also
be piped into the agent. `quit`, `exit`, or Ctrl-C stop
the agent and detach the LSM hook.

### CLI Test

```bash
sudo tests/test_cli.sh
```

covers immediate prompt display, batched command
processing, enforcement from the CLI, and clean exit.

---

# 🧪 Testing Active Prevention

Create a protected test file:

```bash
touch /tmp/sensitive.txt
```

Tell Cerberus to protect it, and switch to blocking mode:

```text
cerberus> addpath /tmp/sensitive.txt
cerberus> mode enforce
```

Then attempt to access it:

```bash
cat /tmp/sensitive.txt
```

Expected result:

```text
cat: /tmp/sensitive.txt: Operation not permitted
```

This confirms that Cerberus successfully intercepted and blocked the operation.

Switching back to safe observation:

```text
cerberus> mode monitor
```

```bash
cat /tmp/sensitive.txt
```

now succeeds, while the agent reports a `MONITOR ALERT`.

---

# 🔍 Verifying the BPF LSM Program

Check active Linux Security Modules:

```bash
cat /sys/kernel/security/lsm
```

The output should contain:

```text
bpf
```

Example:

```text
lockdown,capability,yama,selinux,bpf,...
```

To verify that Cerberus is loaded:

```bash
sudo bpftool prog list | grep lsm
```

Expected output should include something similar to:

```text
lsm name restrict_file_open
```

This confirms:

```text
Cerberus eBPF Program
        ↓
Successfully Loaded
        ↓
Attached to Linux Security Framework
```

---

# 📈 Development Progress

## ✅ Phase 1 — eBPF Monitoring

Completed.

Cerberus originally used a tracepoint:

```text
tracepoint/syscalls/sys_enter_openat
```

The system could:

* Detect `openat` system calls
* Capture process ID
* Capture process name
* Capture file name
* Send information to user space

Architecture:

```text
Process
    ↓
openat syscall
    ↓
eBPF Tracepoint
    ↓
Collect Information
    ↓
Ring Buffer
    ↓
User Space
```

### Limitation

Tracepoints can observe events, but they cannot prevent the operation.

So Cerberus was only a monitoring system.

---

# ✅ Phase 2 — Active Prevention Using BPF LSM

Completed.

The architecture was changed from:

```text
Tracepoint
    ↓
Observe Only 👀
```

to:

```text
BPF LSM
    ↓
Security Decision 🛡️
```

Cerberus now attaches to:

```text
lsm/file_open
```

This allows the program to participate in the Linux security decision.

The program can return:

```text
0
```

Meaning:

```text
Allow Operation
```

or:

```text
-EPERM
```

Meaning:

```text
Deny Operation
```

### Result

Cerberus successfully blocked:

```bash
cat /tmp/sensitive.txt
```

with:

```text
Operation not permitted
```

🎉 **Cerberus is now functioning as an actual Intrusion Prevention System prototype.**

---

# ✅ Phase 3 — Dynamic Blocklist Using BPF Hash Maps

Completed.

The security policy lives in a **BPF hash map** and is managed at runtime:

```text
User Space Agent
        │
        │ Add / Remove Rules (CLI or config file)
        ▼
┌──────────────────────┐
│    BPF Hash Map      │
│                      │
│  NAME + PATH rules   │
└──────────┬───────────┘
           │
           ▼
     Cerberus eBPF
           │
           ▼
      Security Check
           │
      ┌────┴────┐
      │         │
    Match     No Match
      │         │
      ▼         ▼
  REPORT /    ALLOW
  ENFORCE
```

No recompilation or reload is needed to change the policy.

---

# ✅ Phase 3.5 — Production-Grade Rule Handling

Completed.

### Monitor vs Enforce Mode

Cerberus is **monitor-only by default**. Matching access is reported to the agent but never denied until the mode is switched:

```text
mode monitor    -> observe; safe default
mode enforce    -> matching access returns -EPERM
```

The mode lives in a BPF array map, so it changes instantly at runtime.

### Policy File

Rules can be loaded from a config file at startup (default: `blocklist.txt` in the working directory, or pass another path as the first argument):

```text
# policy file format
mode monitor
name sensitive.txt
path /tmp/sensitive.txt
```

See `blocklist.example.txt`.

### Interactive Commands

```text
add <name>          add a file name rule
addpath <path>      add a parent/file path rule
remove <name>       remove a file name rule
rmpath <path>       remove a path rule
list                list all loaded rules
mode <m>            switch policy mode (monitor|enforce)
status              show mode and counters
help                show the help text
quit                stop Cerberus
```

### Clean Shutdown

The agent handles `SIGINT` / `SIGTERM`, detaches the BPF LSM program, and reports a summary:

```text
[+] Cerberus stopped. Events received: 42
```

### Integration Test

```bash
sudo tests/test_phase35.sh
```

covers config loading, both modes, runtime rule changes, ring buffer alerts and clean shutdown.

---

# ✅ Phase 4 — Process-Based Security Policies

Completed.

Rules can now be scoped to **who** performs the access, not just **what** is accessed.

### Rule Model

```text
GLOBAL rule       any process  -> target
PROCESS rule      comm         -> target
UID rule          uid          -> target
SANDBOX           comm         -> allowlist only
```

Precedence inside the LSM hook:

```text
1. Sandbox check
       if the process is sandboxed:
           allow if the target is allowlisted
           otherwise default-deny

2. Global rules
3. Process-scoped rules
4. UID-scoped rules
```

All rule types respect the global monitor/enforce mode.

### Scoped Rules

```text
cerberus> addproc bash /etc/shadow
[+] Scoped rule added: proc bash -> path /etc/shadow

cerberus> adduid 1000 shadow
[+] Scoped rule added: uid 1000 -> name shadow
```

`addproc bash /etc/shadow` denies only `bash`; `grep`, `cat`, ... still work.
`adduid 1000 shadow` denies every process running as uid 1000.

Targets containing `/` are PATH rules; plain names are
NAME rules.

### Sandbox Mode

```text
cerberus> sandbox static-tool
cerberus> allow static-tool /etc/static-tool.conf
```

A sandboxed process may only open allowlisted targets.
An empty allowlist denies every open by that process.

> ⚠️ A strict sandbox also denies the dynamic loader's
> own opens, so dynamically linked programs cannot start
> unless their loader and libraries are allowlisted.
> Use static binaries, or allowlist the loader paths.

### Policy File

```text
mode enforce
proc cat secret.txt
uid 1000 shadow
sandbox static-tool
allow static-tool /etc/static-tool.conf
```

### Interactive Commands

```text
addproc <comm> <target>   deny process access to target
rmproc <comm> <target>    remove a process rule
adduid <uid> <target>     deny uid access to target
rmuid <uid> <target>      remove a uid rule
sandbox <comm>            allowlist-only mode for process
unsandbox <comm>          disable sandbox for process
allow <comm> <target>     allow sandboxed process a target
unallow <comm> <target>   remove an allowlist entry
list                      list rules, allowlist and sandboxes
```

### Integration Test

```bash
sudo tests/test_phase4.sh
```

covers process rules, uid rules, sandbox default-deny,
allowlisting, monitor-mode reporting and list output.

---

# ✅ Phase 5 (revised) — IP-Based Network Security

Completed.

After a first attempt at DNS-based blocking proved too
complex, network security was rebuilt from the Phase 4
baseline as simple, reliable IP-based policy.

The eBPF program now also attaches to:

```c
SEC("lsm/socket_connect")
```

This means Cerberus inspects every outgoing connection
attempt (TCP `connect()` and connected UDP sockets)
through the same BPF LSM mechanism as file access.

### What is captured

Every outgoing IPv4/IPv6 connection attempt produces a
network event through the same ring buffer:

```text
[NET CONNECT BLOCKED] PID:   1234 | UID:     0 | Process: curl | Target: 192.0.2.10:80 (tcp)
[NET WOULD BLOCK   ] PID:   1235 | UID:  1000 | Process: nc   | Target: 192.0.2.10:9999 (tcp)
[NET OUTBOUND      ] PID:   1235 | UID:  1000 | Process: curl | Target: 198.51.100.7:443 (tcp)
```

Events carry timestamp, PID, UID, process name,
destination address and port, protocol, which IP policy
matched, and the verdict.

### IP Rules and Precedence

Rules are exact IPv4 or IPv6 addresses stored in BPF
hash maps, changed at runtime without reloading:

```text
1. block rule   -> deny in enforce mode
2. allow rule   -> allow
3. no rule      -> allow (no default-deny)
```

Precedence is deterministic: an address that is both
blocked and allowed is always **blocked**. The agent
prints a warning when both kinds of rules exist for the
same IP.

### Mode Separation

The network policy has its own mode, independent of the
file-access mode:

```text
net-mode monitor -> IP rule matches are reported only
net-mode enforce -> blocked IPs return -EPERM to the caller
```

A blocked connection is reported as `NET CONNECT BLOCKED`
only when the kernel actually denied it. Monitor mode
never denies anything and shows `NET WOULD BLOCK` for
matches instead.

### Interactive Commands

```text
block-ip <ip>          block outgoing connections to IP
unblock-ip <ip>        remove an IP block rule
allow-ip <ip>          explicitly allow connections to an IP
remove-allow-ip <ip>   remove an IP allow rule
net-mode <m>           monitor|enforce for network policy only
```

### Policy File

```text
net-mode enforce
net-block 192.0.2.10
net-allow 2001:db8::1
```

### Integration Test

```bash
sudo tests/test_net.sh
```

runs every connection inside an isolated network
namespace and covers validation, add/remove/list,
monitor vs enforce, conflicting rules, runtime updates,
event delivery and file-access coexistence.

---

# 🔮 Planned Future Features

Potential development stages:

### ✅ Dynamic File Blocklist

Implemented in Phase 3 — BPF hash maps with runtime rules, monitor/enforce mode and policy files.

### ✅ Process-Based Rules

Implemented in Phase 4 — process-scoped rules, UID-scoped rules and sandbox allowlists.

### ✅ IP-Based Network Protection

Implemented in Phase 5 (revised) — `lsm/socket_connect` hook, IPv4/IPv6 block and allow maps, separate network monitor/enforce mode.

### 🔹 Network Protection

Monitor and prevent suspicious network activity.

Possible targets:

```text
connect()
send()
execve()
```

### 🔹 Reverse Shell Detection

Detect suspicious combinations such as:

```text
Shell Process
        +
Network Connection
        +
Suspicious Execution
        ↓
Potential Reverse Shell
```

### 🔹 Security Policy Engine

Create centralized policies managed by user space.

### 🔹 Logging and Alerting

Store intrusion events for later analysis.

### 🔹 Dashboard

Potential future architecture:

```text
eBPF Kernel Programs
        ↓
Cerberus Agent
        ↓
Event Processing
        ↓
API
        ↓
Dashboard
```

---

# 🗺️ Cerberus Roadmap

```text
PHASE 1 ✅
eBPF System Call Monitoring
        │
        ▼
PHASE 2 ✅
BPF LSM Active Prevention
        │
        ▼
PHASE 3 ✅
Dynamic Blocklist using BPF Maps
(rules, monitor/enforce mode, policy file)
        │
        ▼
PHASE 4 ✅
Process-Based Security Policies
(process rules, uid rules, sandbox allowlists)
        │
        ▼
PHASE 5
Network Security Monitoring
        │
        ▼
PHASE 6
Attack Detection Engine
        │
        ▼
PHASE 7
Centralized Policy Management
        │
        ▼
PHASE 8
Dashboard and Alerting
```

---

# ⚠️ Current Limitations

The current implementation is a prototype.

Known limitations include:

* PATH rules only match the last two path components (parent directory + file name), not the full absolute path.
* Process rules match the process `comm` name, which the process itself controls; they are not a hard boundary against a malicious privileged user.
* A strict sandbox also blocks the dynamic loader's own file opens; allowlist loader/library paths or use static binaries.
* Rules are loaded from the config file only at startup; there is no live reload yet.
* No persistent event logging yet.
* No centralized configuration.
* IP network rules match exact addresses only (no subnets or CIDR ranges); only outbound `connect()` is covered, not UDP `sendto()` without a prior connect.
* Unlisted destination IPs are always allowed (no default-deny networking, by design).
* No advanced attack correlation yet.

These limitations are intentional next development areas.

---

# 👥 Team Development Workflow

Since Cerberus is a team project, contributors should avoid directly pushing experimental work to `main`.

Recommended workflow:

```bash
git checkout main
git pull
```

Create a feature branch:

```bash
git checkout -b feature-name
```

Make changes and test:

```bash
make clean
make
```

Commit changes:

```bash
git add .
git commit -m "Describe your feature"
```

Push the branch:

```bash
git push -u origin feature-name
```

Then create a Pull Request for review.

Recommended structure:

```text
main
 │
 ├── feature/dynamic-blocklist
 │
 ├── feature/process-rules
 │
 ├── feature/network-monitoring
 │
 └── feature/logging
```

---

# 🧠 Key Learning From This Project

Cerberus demonstrates an important distinction in eBPF security:

```text
Tracepoints
        ↓
Observe events
        ↓
Monitoring
```

vs

```text
BPF LSM
        ↓
Participate in security decisions
        ↓
Prevention
```

The major milestone of the project was moving from:

> **"We can see suspicious activity."**

to:

> **"We can stop suspicious activity."**

---

# 🛡️ Current Status

```text
┌─────────────────────────────────────┐
│         CERBERUS STATUS             │
├─────────────────────────────────────┤
│                                     │
│ eBPF Build Pipeline       ✅        │
│ Kernel BTF / CO-RE        ✅        │
│ Tracepoint Monitoring     ✅        │
│ Ring Buffer Events        ✅        │
│ User-Space Agent          ✅        │
│ BPF LSM Enabled           ✅        │
│ File Access Blocking      ✅        │
│ Dynamic Policies          ✅        │
│ Process / UID Rules       ✅        │
│ IP Network Blocking       ✅        │
│ Advanced Detection        🔜        │
│ Dashboard                 🔜        │
│                                     │
└─────────────────────────────────────┘
```

---

## 🐺 Cerberus

**Observe. Detect. Prevent.**
