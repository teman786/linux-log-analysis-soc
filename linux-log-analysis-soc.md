# Linux Log Analysis for SOC Analysts — Practical Step-by-Step Guide

## 📌 Overview

Linux is widely used in servers, cloud environments, and containerized workloads. Because of this, SOC analysts frequently investigate security alerts originating from Linux systems.

Unlike Windows Event Viewer, Linux commonly stores logs as text files, primarily under:


/var/log/


In this practical guide, we will explore:

* Linux log locations
* Syslog analysis
* Authentication logs
* SSH investigation
* User and privilege changes
* Sudo activity
* System and application logs
* Bash history
* Linux system calls
* `auditd`
* `ausearch`
* Process and file monitoring
* SOC investigation workflow

---

# 1. Exploring Linux Log Files

## Step 1: Navigate to `/var/log`

Most Linux logs are stored inside `/var/log`.

Run:


ls -l /var/log


This shows the available log files and directories.

Typical files include:


auth.log
syslog
kern.log
dpkg.log
apt/
audit/
journal/


> **SOC Tip:** Never assume every Linux machine has exactly the same log files. Logging configuration varies between distributions.

### Screenshot


![Listing Linux logs](screenshots/01-var-log.png)


---

# 2. Understanding `/var/log/syslog`

`syslog` is a general-purpose system log that can contain events from different services and processes.

View the beginning of the file:


cat /var/log/syslog | head


Example:


2025-08-13T13:57:49.388941+00:00 thm-vm systemd-timesyncd[268]: Initial clock synchronization...
2025-08-13T13:59:39.970029+00:00 thm-vm systemd[888]: Starting dbus.socket...
2025-08-13T14:02:22.606216+00:00 thm-vm dbus-daemon[564]: Successfully activated service...


A typical log entry can contain:


Timestamp → Hostname → Process → PID → Message


---

# 3. Filtering Logs with grep

Large log files can contain thousands of events.

Instead of reading everything, use `grep`.

## Find CRON events


cat /var/log/syslog | grep CRON


This displays only entries containing `CRON`.

## Exclude CRON events


cat /var/log/syslog | grep -v CRON


The `-v` option excludes matching lines.

### Why this matters in a SOC

Filtering reduces noise and allows analysts to quickly focus on a specific activity.

For example:


grep SSH /var/log/syslog


or:

grep -i error /var/log/syslog


can quickly narrow an investigation.

---

# 4. Discovering Authentication Logs

One of the most important Linux security logs is:


/var/log/auth.log


On many RHEL-based systems, the equivalent file is:


/var/log/secure


Search for authentication-related files:


grep -R -E "auth|login|session" /var/log


Authentication logs can contain:

* Login events
* Logout events
* SSH authentication
* `sudo`
* `su`
* User creation
* User deletion
* Password changes
* Group modifications
* Cron sessions

---

# 5. Investigating Login and Logout Events

Run:


cat /var/log/auth.log | grep -E 'session opened|session closed'


Example:


pam_unix(login:session): session opened for user bob
pam_unix(login:session): session closed for user bob


Remote SSH sessions may appear as:


pam_unix(sshd:session): session opened for user alice


Cron jobs can also create sessions:


pam_unix(cron:session): session opened for user root


### SOC Investigation

If you see a root session, don't immediately assume a human administrator logged in.

The session could have been created by:

* Cron
* `sudo`
* `su`
* An automated service

Always investigate the process that created the session.

---

# 6. Investigating SSH Logins

SSH is one of the most important sources of Linux authentication activity.

Search for successful and failed SSH authentication:


cat /var/log/auth.log | grep "sshd" | grep -E 'Accepted|Failed'


Example failed login:


Failed password for root from 222.124.17.227 port 50293 ssh2


Example successful login:


Accepted publickey for bob from 10.19.92.18 port 55050 ssh2


From these events, we can identify:


Username
Source IP
Source Port
Authentication Method
Success / Failure
Timestamp


### SOC Detection Idea

Suppose the same source IP generates failed authentication attempts against:


root
admin
ubuntu
test


This could indicate password spraying or brute-force activity.

The analyst should investigate:

1. Source IP
2. Number of failures
3. Number of targeted accounts
4. Time range
5. Whether a successful login occurred afterward

---

# 7. Investigating User Creation and Modification

Search authentication logs for user-management events:


cat /var/log/auth.log | grep -E '(passwd|useradd|usermod|userdel)\['


Important commands represented in the logs include:


passwd
useradd
usermod
userdel


Example:


useradd[1878]: new user: name=backdoor, UID=1002, GID=1002, shell=/bin/sh


Then:


usermod[1906]: add 'backdoor' to group 'sudo'


This creates an important investigation chain:


New Account
     ↓
Group Modification
     ↓
Privileged Group
     ↓
Potential Privilege Escalation


### SOC Tip

Unexpected creation of a user account or addition to a privileged group should be investigated with the surrounding authentication and command-execution events.

---

# 8. Investigating sudo Activity

Commands executed through `sudo` can be found using:


cat /var/log/auth.log | grep -E 'COMMAND='


Example:


sudo: ubuntu : TTY=pts/0 ; COMMAND=/usr/bin/systemctl stop edr


Another example:


sudo: ubuntu : TTY=pts/0 ; COMMAND=/usr/bin/ufw status numbered


Another useful event is:


sudo: ubuntu : TTY=pts/0 ; COMMAND=/usr/bin/su


### Why this is important

An attacker who gains access to a normal account may attempt to:


Run sudo
   ↓
Access root
   ↓
Disable security controls
   ↓
Modify the system


Therefore, `sudo` activity can provide important evidence during an investigation.

---

# 9. Kernel and Package Manager Logs

## Kernel Logs


cat /var/log/kern.log


Kernel logs contain kernel-related messages and errors.

They can become useful during deeper DFIR investigations.

---

## Debian Package Logs

Check:


cat /var/log/dpkg.log


APT logs may also be available under:


ls -l /var/log/apt/


These logs can help determine which software was installed and when.

---

## RHEL-Based Systems

Common package logs include:


/var/log/dnf.log
/var/log/yum.log


### SOC Relevance

If an attacker installs a tool during an intrusion, package-manager logs may provide supporting evidence.

---

# 10. Application-Specific Logs

Security investigations should not rely only on operating-system logs.

Applications and services can produce their own logs.

Examples:


Database → Query logs
Mail Server → Email activity
Web Server → HTTP requests
Containers → Runtime activity

For example, Nginx commonly stores access logs at:


/var/log/nginx/access.log


View them with:


cat /var/log/nginx/access.log


Example:


10.0.1.12 - - [11/08/2025:14:32:10 +0000] "GET / HTTP/1.1" 200 3022
10.0.1.12 - - [11/08/2025:14:32:14 +0000] "GET /login HTTP/1.1" 200 1056
10.0.1.12 - - [11/08/2025:14:33:09 +0000] "POST /login HTTP/1.1" 302 112
10.0.5.21 - - [11/08/2025:17:56:23 +0000] "GET /admin HTTP/1.1" 403 104


An analyst can extract:

* Source IP
* Requested resource
* HTTP method
* Timestamp
* HTTP status code
* Response size

A request such as:


GET /admin → 403


could be relevant during an investigation involving unauthorized access attempts.

---

# 11. Investigating Bash History

Bash can maintain a history of commands executed during an interactive shell session.

View a user's history:


cat /home/ubuntu/.bash_history


Or view the current shell history:


history


Example:


1 echo "hello" > world.txt
2 nano /etc/ssh/sshd_config
3 sudo su
4 ls -la /home/ubuntu


Bash history can provide useful clues about what an attacker or administrator did interactively.

---

# 12. Limitations of Bash History

Bash history is **not a complete audit trail**.

### Leading-space technique

Depending on shell configuration, a command beginning with a space may not be saved:


 echo "You will never see me in logs!"


### Scripts

Commands can also be hidden inside scripts:


nano legit.sh
./legit.sh


The history may only show execution of the script rather than every command contained inside it.

### Alternative shells

An attacker can use another shell:


sh


and execute commands outside the Bash history mechanism.

Therefore:


Bash History ≠ Complete Command Logging


For reliable runtime visibility, additional monitoring is required.

---

# 13. Linux System Calls

Linux does not automatically record every runtime action.

For example, traditional logs may not tell us:


Which process did the user execute?
Who opened a particular file?
Who deleted a file?
Which program created a process?


To understand runtime monitoring, we need to understand **system calls**.

A system call is the interface between a user-space application and the Linux kernel.

Conceptually:


Application
     ↓
System Call
     ↓
Linux Kernel
     ↓
System Resources
     ↓
Result


Linux has hundreds of system calls.

One important system call for process execution is:

execve


---

# 14. Why execve Matters

When a program needs to execute another program, the operating system handles that request through system calls.

For security monitoring, observing system calls can therefore provide visibility into runtime activity.

Examples of activity that can be monitored include:


Process execution
File access
Network activity
System configuration changes


This is the foundation of several Linux security-monitoring technologies.

---

# 15. auditd — Linux Runtime Monitoring

`auditd` stands for **Audit Daemon**.

It provides a mechanism for monitoring selected Linux system activity.

Audit rules are commonly stored under:


/etc/audit/rules.d/


View the rules with:


ls -l /etc/audit/rules.d/

Rules can specify which system calls, files, or processes should be monitored.

### Important SOC Principle

Monitoring everything can generate huge amounts of data.

Therefore:

```text
More Logs ≠ Better Detection
```

A SOC should focus on high-value events and create balanced detection rules.

---

# 16. auditd Log Location

Audit events are commonly stored in:


/var/log/audit/audit.log


You can inspect the file using:


cat /var/log/audit/audit.log


However, raw audit output can be difficult to read.

This is where `ausearch` becomes useful.

---

# 17. Using ausearch

`ausearch` allows analysts to search and filter audit events.

For example:

ausearch -i -k proc_wget


Here:


-i → Interpret values into human-readable form
-k → Search by audit rule key


A resulting event may contain:


type=PROCTITLE
type=CWD
type=EXECVE
type=SYSCALL


---

# 18. Understanding auditd Event Types

## PROCTITLE

Contains information about the process command line.

Example:


proctitle=wget https://files.tryhackme.thm/report.zip


This can immediately show what command was executed.

---

## CWD

CWD means **Current Working Directory**.

Example:


cwd=/root


This tells us where the process was operating from.

---

## EXECVE

This record contains information about the executed command and its arguments.

Example:


argc=2
a0=wget
a1=https://files.tryhackme.thm/report.zip


This provides useful command-line context.

---

## SYSCALL

The `SYSCALL` record contains system-call and process information.

Example:


syscall=execve
ppid=3752
pid=3888
auid=ubuntu
uid=root
tty=pts1
exe=/usr/bin/wget
key=proc_wget


---

# 19. Understanding Important auditd Fields

### PID

pid=3888


The Process ID identifies the process.

### PPID


ppid=3752


The Parent Process ID helps identify which process launched the current process.

This is extremely useful for building a process tree.

---

### AUID


auid=ubuntu


The Audit User ID identifies the original authenticated user associated with the session.

---

### UID


uid=root


This identifies the user under whose privileges the action was executed.

AUID and UID can differ when privilege escalation occurs.

For example:


auid=ubuntu
uid=root


can indicate that the original session belonged to `ubuntu`, while the command ultimately ran with root privileges.

---

### TTY


tty=pts1


This identifies the terminal/session associated with the activity.

---

### EXE


exe=/usr/bin/wget


This identifies the executable that performed the action.

The executable path can be useful in detection rules.

---

### KEY


key=proc_wget


The audit rule key is a label that allows analysts to quickly filter related events.

For example:


ausearch -i -k proc_wget


---

# 20. Investigating File Access

Auditd can also monitor important files.

For example:


ausearch -i -k file_sshconf


This may show activity involving:


/etc/ssh/sshd_config


Example:


type=PROCTITLE ... proctitle=nano /etc/ssh/sshd_config
type=CWD ... cwd=/
type=PATH ... name=/etc/ssh/sshd_config
type=SYSCALL ... syscall=openat


This tells us:


Process → nano
        ↓
File → /etc/ssh/sshd_config
        ↓
System Call → openat


Critical files that may deserve monitoring include:


/etc/ssh/sshd_config
Cron configuration
System configuration
Security-related configuration

---

# 21. Detecting wget Activity

Attackers may use legitimate system utilities to download tools or payloads.

For example:


wget https://files.tryhackme.thm/report.zip


If an audit rule monitors `wget`, the execution can be searched using:


ausearch -i -k proc_wget

The investigation can then connect:


User
 ↓
Process
 ↓
Command
 ↓
URL
 ↓
Downloaded File

This is much more useful than simply knowing that `wget` executed.

---

# 22. Building a Linux Investigation Timeline

During an investigation, events from different log sources can be correlated.

Example:

1. SSH authentication
        ↓
2. User session created
        ↓
3. sudo command executed
        ↓
4. Privileged activity
        ↓
5. wget executed
        ↓
6. File downloaded
        ↓
7. File opened/modified
        ↓
8. Network activity


Instead of investigating each log independently, the SOC analyst should correlate them into a timeline.

---

# 23. Practical SOC Investigation Method

When investigating a suspicious Linux host, follow this approach.

### Step 1 — Identify the suspicious account

Check:

cat /var/log/auth.log | grep -E 'Accepted|Failed'


Determine:

Who?
When?
From where?
How?


---

### Step 2 — Check session activity


cat /var/log/auth.log | grep -E 'session opened|session closed'


Determine when the session started and ended.

---

### Step 3 — Investigate privilege usage



cat /var/log/auth.log | grep -E 'COMMAND='

Look for unexpected:


sudo
su
systemctl
firewall changes
security-tool modifications

---

### Step 4 — Check account changes


cat /var/log/auth.log | grep -E '(passwd|useradd|usermod|userdel)\['


Look for:


Unexpected users
Unexpected password changes
Privileged group additions
Deleted accounts

---

### Step 5 — Check Bash history


cat /home/<username>/.bash_history

Use this as supporting evidence, not as a complete source of truth.

---

### Step 6 — Investigate runtime activity

Check audit events:

ausearch -i -k <audit-key>


Look for:

text
PID
PPID
AUID
UID
EXE
Command line
File paths
System calls


---

### Step 7 — Build the timeline

Correlate:

Authentication
      +
Privilege escalation
      +
Process execution
      +
File activity
      +
Network activity

This allows the SOC analyst to reconstruct the attack chain.

---

# 24. Alternative Linux Runtime Monitoring Tools

"auditd" is not the only option.

Other technologies include:

### Sysmon for Linux

Useful for organizations familiar with Sysmon-style telemetry.

### Falco

An open-source runtime security tool that is particularly useful for containerized environments.

### Osquery

Provides broad endpoint visibility and querying capabilities.

### EDR

Modern EDR platforms can provide Linux process, file, and other runtime telemetry.

Although these tools differ in implementation and presentation, system-level runtime activity remains an important foundation for detection.

---

# 25. Common Commands Cheat Sheet

| Purpose                    | Command                                                                    |
| -------------------------- | -------------------------------------------------------------------------- |
| List logs                  |  ls -l /var/log                                                           |
| View syslog                |  cat /var/log/syslog                                                      |
| First syslog entries       |  cat /var/log/syslog \| head                                              |
| Find CRON                  |  cat /var/log/syslog \| grep CRON                                         |
| Exclude CRON               |  grep -v CRON                                                             |
| Search authentication logs |  grep -R -E "auth\|login\|session" /var/log                            |
| Login/logout               |  cat /var/log/auth.log \| grep -E 'session opened\|session closed'       |
| SSH events                 |  cat /var/log/auth.log \| grep "sshd" \| grep -E 'Accepted\|Failed'      |
| User management            |  cat /var/log/auth.log \| grep -E '(passwd\|useradd\|usermod\|userdel)\[' |
| Sudo commands              |  cat /var/log/auth.log \| grep -E 'COMMAND='                            |
| Bash history               |  cat ~/.bash_history                                                     |
| Current history            |  history                                                                |
| Audit logs                 |  cat /var/log/audit/audit.log                                             |
| Search audit key           |  ausearch -i -k <key>                                                     |
| Audit rules                |  ls -l /etc/audit/rules.d/                                                |

---

# 26. Key SOC Takeaways

Linux log analysis is not about memorizing file paths or commands. The real objective is to understand how different sources contribute to an investigation.

The most important concepts from this practical exercise are:

* Most traditional Linux logs are stored under `/var/log
* `/var/log/auth.log` is critical for authentication investigations.
* SSH logs can reveal successful and failed remote access.
* User-management logs can reveal suspicious account creation and privilege changes.
* `sudo` logs can expose privileged commands.
* Package-manager logs can provide evidence of software installation.
* Application logs provide service-specific visibility.
* Bash history can provide useful clues but has significant limitations.
* `execve` is an important system call for process execution.
* `auditd` provides runtime auditing.
* `ausearch` makes audit events easier to investigate.
* `PID` and `PPID` help reconstruct process relationships.
* `AUID` and `UID` help identify original and effective identities.
* `EXE` identifies the executable involved.
* Audit keys make targeted searching easier.
* Correlating multiple log sources is essential for reconstructing an incident.

---

# 🎯 Final Perspective

A Linux SOC investigation rarely depends on a single log.

A failed SSH login might be insignificant by itself. However, if it is followed by a successful login, privilege escalation, suspicious `sudo` activity, execution of `wget`, creation or modification of files, and additional network activity, the combined timeline becomes much more meaningful.

The key skill is therefore:


Collect
   ↓
Filter
   ↓
Correlate
   ↓
Investigate
   ↓
Build Timeline
   ↓
Determine What Happened
```

For a SOC analyst, learning Linux logging is ultimately about turning raw technical events into a clear understanding of **who did what, when, from where, and how**.
