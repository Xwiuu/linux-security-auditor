#!/usr/bin/env bash

check_sshd_available() {
  if command -v sshd >/dev/null 2>&1; then
    finding id=SSH-001 category=ssh severity=pass title="sshd is available" \
      description="The OpenSSH server binary is present on this system." \
      expected="sshd installed" actual="sshd available" \
      recommendation="None."
  else
    finding id=SSH-001 category=ssh severity=info title="sshd is not installed" \
      description="The OpenSSH server binary was not found on this system." \
      expected="sshd installed" actual="sshd missing" \
      recommendation="Install the openssh-server package if remote administration is required."
  fi
}


get_sshd_option() {
  local option="$1"

  sshd -T 2>/dev/null | awk -v key="$option" '$1 == key { print $2; exit }'
}


check_root_login() {
  local value

  if ! value="$(get_sshd_option permitrootlogin)"; then
    finding id=SSH-002 category=ssh severity=info title="Effective SSH configuration unavailable" \
      description="The running sshd configuration could not be read." \
      expected="sshd -T succeeds" actual="sshd -T failed" \
      recommendation="Verify that sshd is installed and the service is running."
    return 0
  fi

  if [[ -z "$value" ]]; then
    finding id=SSH-002 category=ssh severity=info title="Could not determine PermitRootLogin" \
      description="PermitRootLogin was not reported by the running sshd configuration." \
      expected="PermitRootLogin reported" actual="empty" \
      recommendation="Set PermitRootLogin explicitly in /etc/ssh/sshd_config."
  elif [[ "$value" == "no" ]]; then
    finding id=SSH-002 category=ssh severity=pass title="Root login is disabled" \
      description="The SSH daemon refuses direct root logins." \
      expected="PermitRootLogin no" actual="$value" \
      recommendation="None."
  else
    finding id=SSH-002 category=ssh severity=warn title="Root login setting: $value" \
      description="Direct root login over SSH is permitted." \
      expected="PermitRootLogin no" actual="$value" \
      recommendation="Set PermitRootLogin no in /etc/ssh/sshd_config and reload sshd."
  fi
}


check_password_authentication() {
  local value

  if ! value="$(get_sshd_option passwordauthentication)"; then
    finding id=SSH-003 category=ssh severity=info title="Effective SSH configuration unavailable" \
      description="The running sshd configuration could not be read." \
      expected="sshd -T succeeds" actual="sshd -T failed" \
      recommendation="Verify that sshd is installed and the service is running."
    return 0
  fi

  if [[ -z "$value" ]]; then
    finding id=SSH-003 category=ssh severity=info title="Could not determine PasswordAuthentication" \
      description="PasswordAuthentication was not reported by the running sshd configuration." \
      expected="PasswordAuthentication reported" actual="empty" \
      recommendation="Set PasswordAuthentication explicitly in /etc/ssh/sshd_config."
  elif [[ "$value" == "no" ]]; then
    finding id=SSH-003 category=ssh severity=pass title="Password authentication is disabled" \
      description="Only public key authentication is accepted." \
      expected="PasswordAuthentication no" actual="$value" \
      recommendation="None."
  else
    finding id=SSH-003 category=ssh severity=warn title="Password authentication setting: $value" \
      description="The SSH daemon accepts password logins, which are exposed to brute force." \
      expected="PasswordAuthentication no" actual="$value" \
      recommendation="Set PasswordAuthentication no in /etc/ssh/sshd_config once keys are deployed."
  fi
}


check_empty_passwords() {
  local value

  if ! value="$(get_sshd_option permitemptypasswords)"; then
    finding id=SSH-004 category=ssh severity=info title="Effective SSH configuration unavailable" \
      description="The running sshd configuration could not be read." \
      expected="sshd -T succeeds" actual="sshd -T failed" \
      recommendation="Verify that sshd is installed and the service is running."
    return 0
  fi

  if [[ -z "$value" ]]; then
    finding id=SSH-004 category=ssh severity=info title="Could not determine PermitEmptyPasswords" \
      description="PermitEmptyPasswords was not reported by the running sshd configuration." \
      expected="PermitEmptyPasswords reported" actual="empty" \
      recommendation="Set PermitEmptyPasswords explicitly in /etc/ssh/sshd_config."
  elif [[ "$value" == "no" ]]; then
    finding id=SSH-004 category=ssh severity=pass title="Empty passwords are disabled" \
      description="Accounts with an empty password cannot authenticate over SSH." \
      expected="PermitEmptyPasswords no" actual="$value" \
      recommendation="None."
  else
    finding id=SSH-004 category=ssh severity=high title="PermitEmptyPasswords setting: $value" \
      description="Accounts with an empty password can log in over SSH." \
      expected="PermitEmptyPasswords no" actual="$value" \
      recommendation="Set PermitEmptyPasswords no in /etc/ssh/sshd_config and reload sshd."
  fi
}

check_pubkey_authentication() {
  local value

  if ! value="$(get_sshd_option pubkeyauthentication)"; then
    finding id=SSH-005 category=ssh severity=info title="Effective SSH configuration unavailable" \
      description="The running sshd configuration could not be read." \
      expected="sshd -T succeeds" actual="sshd -T failed" \
      recommendation="Verify that sshd is installed and the service is running."
    return 0
  fi

  if [[ -z "$value" ]]; then
    finding id=SSH-005 category=ssh severity=info title="Could not determine PubkeyAuthentication" \
      description="PubkeyAuthentication was not reported by the running sshd configuration." \
      expected="PubkeyAuthentication reported" actual="empty" \
      recommendation="Set PubkeyAuthentication explicitly in /etc/ssh/sshd_config."
  elif [[ "$value" == "yes" ]]; then
    finding id=SSH-005 category=ssh severity=pass title="Public key authentication is enabled" \
      description="Users can authenticate with SSH keys." \
      expected="PubkeyAuthentication yes" actual="$value" \
      recommendation="None."
  else
    finding id=SSH-005 category=ssh severity=warn title="PubkeyAuthentication setting: $value" \
      description="Public key authentication is disabled, forcing password logins." \
      expected="PubkeyAuthentication yes" actual="$value" \
      recommendation="Set PubkeyAuthentication yes in /etc/ssh/sshd_config."
  fi
}


check_max_auth_tries() {
  local value

  if ! value="$(get_sshd_option maxauthtries)"; then
    finding id=SSH-006 category=ssh severity=info title="Effective SSH configuration unavailable" \
      description="The running sshd configuration could not be read." \
      expected="sshd -T succeeds" actual="sshd -T failed" \
      recommendation="Verify that sshd is installed and the service is running."
    return 0
  fi

  if [[ -z "$value" ]]; then
    finding id=SSH-006 category=ssh severity=info title="Could not determine MaxAuthTries" \
      description="MaxAuthTries was not reported by the running sshd configuration." \
      expected="MaxAuthTries reported" actual="empty" \
      recommendation="Set MaxAuthTries explicitly in /etc/ssh/sshd_config."
  elif (( value <= 4 )); then
    finding id=SSH-006 category=ssh severity=pass title="MaxAuthTries is $value" \
      description="Authentication attempts per connection are limited." \
      expected="MaxAuthTries <= 4" actual="$value" \
      recommendation="None."
  else
    finding id=SSH-006 category=ssh severity=warn title="MaxAuthTries is $value" \
      description="Attackers get too many authentication attempts per connection." \
      expected="MaxAuthTries <= 4" actual="$value" \
      recommendation="Set MaxAuthTries 3 or 4 in /etc/ssh/sshd_config."
  fi
}


check_x11_forwarding() {
  local value

  if ! value="$(get_sshd_option x11forwarding)"; then
    finding id=SSH-007 category=ssh severity=info title="Effective SSH configuration unavailable" \
      description="The running sshd configuration could not be read." \
      expected="sshd -T succeeds" actual="sshd -T failed" \
      recommendation="Verify that sshd is installed and the service is running."
    return 0
  fi

  if [[ -z "$value" ]]; then
    finding id=SSH-007 category=ssh severity=info title="Could not determine X11Forwarding" \
      description="X11Forwarding was not reported by the running sshd configuration." \
      expected="X11Forwarding reported" actual="empty" \
      recommendation="Set X11Forwarding explicitly in /etc/ssh/sshd_config."
  elif [[ "$value" == "no" ]]; then
    finding id=SSH-007 category=ssh severity=pass title="X11 forwarding is disabled" \
      description="Remote X11 display forwarding is not allowed." \
      expected="X11Forwarding no" actual="$value" \
      recommendation="None."
  else
    finding id=SSH-007 category=ssh severity=info title="X11Forwarding setting: $value" \
      description="Remote X11 display forwarding is allowed." \
      expected="X11Forwarding no" actual="$value" \
      recommendation="Set X11Forwarding no in /etc/ssh/sshd_config if X11 forwarding is unused."
  fi
}
