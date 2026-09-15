# Enterprise SOC Security Incident Runbook: Brute Force & Privilege Escalation Mitigation

## 1. Overview & Threat Vector Description
This runbook defines standard operating procedures for identifying, triaging, investigating, and mitigating unauthorized SSH access attempts, distributed credential stuffing, brute-force login attacks, and subsequent privilege escalation activities on production Enterprise infrastructure.

## 2. Detection Criteria & Indicators of Compromise (IoCs)
- High frequency of failed login events (e.g. >10 failed SSH authentication attempts within 60 seconds from a single IP address).
- Targeted default or high-privilege usernames (e.g., `root`, `admin`, `ubuntu`, `postgres`, `deploy`).
- Spike in syslog authorization failures (`/var/log/auth.log` or `journalctl -u ssh`).
- Unauthorized execution of `sudo su`, `pkexec`, or SUID binary exploits following successful authentication.
- Outbound egress traffic from compromised host to suspicious C2 IP addresses or unknown external endpoints over non-standard ports (e.g., 4444, 8443).

## 3. Immediate Containment Procedure
When a SSH brute force or privilege escalation threat is confirmed:

### Step 3.1: Network Boundary Isolation & IP Blocking
Execute active firewall drop rules to block adversary source IP address across edge routers and host firewalls:
```bash
# Host-level iptables blocking rule
sudo iptables -A INPUT -s <SUSPICIOUS_IP> -j DROP

# UFW Firewall drop rule
sudo ufw deny from <SUSPICIOUS_IP> to any
```

### Step 3.2: Compromised Account Containment
Lock targeted user credentials immediately to prevent further unauthorized sessions:
```bash
# Expire and lock user account
sudo usermod -L <TARGET_USER>
sudo passwd -l <TARGET_USER>

# Terminate active user login sessions
sudo pkill -u <TARGET_USER>
```

### Step 3.3: Privilege Escalation Remediation & Forensic Capture
- Check active processes spawned by user: `ps aux | grep <TARGET_USER>`
- Terminate malicious background processes: `sudo kill -9 <PID>`
- Inspect SUID permissions: `find / -perm -4000 -type f 2>/dev/null`
- Export volatile memory and auth logs (`/var/log/auth.log`) to secure SOC bucket for forensic analysis.

## 4. Post-Incident Review & Prevention
- Enforce multi-factor authentication (MFA) via pam_duo / Google Authenticator for all SSH sessions.
- Disable password-based SSH login in `/etc/ssh/sshd_config` (`PasswordAuthentication no`, `PermitRootLogin no`).
- Configure automated IP banning policies using `fail2ban`.
