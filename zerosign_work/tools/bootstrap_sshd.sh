#!/usr/bin/env bash
set -euo pipefail
if ! command -v sshd >/dev/null 2>&1; then exit 0; fi

ECA="${ECA_UUID:-}"
BF_PATH="/secrets/attester/${ECA}/bf.b64url"
mkdir -p /var/run/sshd /root/.ssh /root/.wellknown
chmod 700 /root/.ssh

# Create authorized_keys with BF comment if BF present
if [[ -n "${ECA}" && -s "${BF_PATH}" ]]; then
  BF="$(cat "${BF_PATH}")"
  # Generate a throwaway SSH keypair for the account (public key content is irrelevant to demo)
  if [[ ! -s /root/.ssh/id_ed25519 ]]; then
    ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519 >/dev/null 2>&1
  fi
  PUB="$(cat /root/.ssh/id_ed25519.pub | cut -d' ' -f1,2)"
  echo "${PUB} zerosign-bf:${BF} attester@vm" > /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
fi

# Minimal hardened sshd_config
cat >/etc/ssh/sshd_config <<'CFG'
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
PrintMotd no
ClientAliveInterval 120
ClientAliveCountMax 2
AllowTcpForwarding no
X11Forwarding no
Subsystem sftp internal-sftp
CFG
test -f /etc/ssh/ssh_host_rsa_key || ssh-keygen -t rsa -b 3072 -N "" -f /etc/ssh/ssh_host_rsa_key
test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key
/usr/sbin/sshd -D & disown
echo "[tools] sshd started; authorized_keys prepared (if BF present)"
