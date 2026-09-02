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
├── src/
│   ├── common.h
│   ├── ips_agent.cpp
│   └── ips_core.bpf.c
│
├── Makefile
├── .gitignore
└── README.md
```

---

# 🧩 Components

## 1️⃣ `common.h`

This file contains structures shared between:

* Kernel-space eBPF program
* User-space C++ agent

Current event structure:

```c
struct event {
    int pid;
    char comm[16];
    char filename[256];
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

File:

```text
src/ips_core.bpf.c
```

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

The current prototype checks whether the file name begins with:

```text
sensitive
```

For example:

```text
sensitive.txt
```

When such a file is accessed:

```text
cat /tmp/sensitive.txt
```

Cerberus intercepts the operation through the BPF LSM hook.

The eBPF program then returns:

```c
return -EPERM;
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
[BLOCKED INTRUSION]
PID: 1234
Process: cat
Protected Target: sensitive.txt
```

---

# 🖥️ User-Space Agent

File:

```text
src/ips_agent.cpp
```

The user-space agent is responsible for:

* Loading the eBPF program
* Attaching the eBPF program
* Connecting to the Ring Buffer
* Receiving security events
* Displaying blocked activity

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
ips_core.bpf.c
        ↓
Clang
        ↓
ips_core.bpf.o
        ↓
bpftool
        ↓
ips_core.skel.h
        ↓
C++ Agent
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

src/ips_core.bpf.c
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

src/ips_agent.cpp
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

Expected output:

```text
Cerberus IPS Enforcer Active. Running in BLOCKING mode...
```

Keep this terminal running.

---

# 🧪 Testing Active Prevention

Open another terminal.

Create a protected test file if necessary:

```bash
touch /tmp/sensitive.txt
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

# 🔜 Next Development Steps

## Phase 3 — Dynamic Blocklist Using BPF Hash Maps

### Current Problem

Currently, the security rule is hardcoded:

```text
if filename starts with "sensitive"
```

This means changing the policy requires:

```text
Change C code
        ↓
Recompile
        ↓
Reload BPF program
```

That is not practical for a real IPS.

---

### Solution

Introduce a BPF Hash Map.

Architecture:

```text
User Space Agent
        │
        │ Add / Remove Rules
        ▼
┌──────────────────────┐
│    BPF Hash Map      │
│                      │
│  Blocked Targets     │
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
    BLOCK     ALLOW
```

This will allow security policies to change dynamically without recompiling the eBPF program.

---

# 🔮 Planned Future Features

Potential development stages:

### 🔹 Dynamic File Blocklist

Use BPF Hash Maps for runtime policy management.

### 🔹 Process-Based Rules

Block or allow specific processes.

Example:

```text
Unknown Process
        ↓
Attempts Sensitive File Access
        ↓
Cerberus
        ↓
BLOCK
```

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
PHASE 3 🔜
Dynamic Blocklist using BPF Maps
        │
        ▼
PHASE 4
Process-Based Security Policies
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

* Filename matching is currently hardcoded.
* The current implementation checks the filename rather than maintaining a complete dynamic policy system.
* No persistent event logging yet.
* No centralized configuration.
* No network protection yet.
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
│ Dynamic Policies          🔜        │
│ Advanced Detection        🔜        │
│ Dashboard                 🔜        │
│                                     │
└─────────────────────────────────────┘
```

---

## 🐺 Cerberus

**Observe. Detect. Prevent.**
