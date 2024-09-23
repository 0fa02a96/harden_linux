#!/bin/bash

check_root() {
  if [ "$EUID" -ne 0 ]; then
    echo "Este script debe ejecutarse como root"
    exit 1
  fi
}

update_system() {
  apt-get update -y && apt-get upgrade -y
}

partition_setup() {
  echo "Configurando particiones recomendadas por CIS..."

  # Verificar si las particiones ya están configuradas en /etc/fstab
  grep -q "/var " /etc/fstab || echo "UUID=xxx /var ext4 defaults,nodev 0 2" >> /etc/fstab
  grep -q "/var/tmp " /etc/fstab || echo "UUID=xxx /var/tmp ext4 defaults,nodev,nosuid,noexec 0 2" >> /etc/fstab
  grep -q "/var/log " /etc/fstab || echo "UUID=xxx /var/log ext4 defaults,nodev,nosuid 0 2" >> /etc/fstab
  grep -q "/var/log/audit " /etc/fstab || echo "UUID=xxx /var/log/audit ext4 defaults,nodev,nosuid 0 2" >> /etc/fstab
  grep -q "/home " /etc/fstab || echo "UUID=xxx /home ext4 defaults,nodev 0 2" >> /etc/fstab
  grep -q "/tmp " /etc/fstab || echo "UUID=xxx /tmp ext4 defaults,nodev,nosuid,noexec 0 2" >> /etc/fstab
  grep -q "/boot " /etc/fstab || echo "UUID=xxx /boot ext4 defaults,nodev,nosuid,noexec 0 2" >> /etc/fstab

  echo "Particiones configuradas. Se recomienda reiniciar para que los cambios surjan efecto."
}

configure_audit() {
  echo "Configurando auditd de acuerdo a CIS..."

  apt-get install auditd audispd-plugins -y
  systemctl enable auditd
  systemctl start auditd

  # Configuraciones de CIS para auditd
  echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
  echo "-w /etc/group -p wa -k identity" >> /etc/audit/rules.d/audit.rules
  echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules
  echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules
  echo "-w /etc/sudoers -p wa -k identity" >> /etc/audit/rules.d/audit.rules
  echo "-w /var/log/auth.log -p wa -k logins" >> /etc/audit/rules.d/audit.rules
  echo "-w /var/log/sudo.log -p wa -k sudo" >> /etc/audit/rules.d/audit.rules
  echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
  echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
  echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/rules.d/audit.rules
  echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/rules.d/audit.rules
  echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/audit.rules

  # Monitorear el uso de privilegios root
  echo "-w /etc/sudoers -p wa -k actions" >> /etc/audit/rules.d/audit.rules
  echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/audit.rules

  # Monitorear cambios en el kernel y módulos
  echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/rules.d/audit.rules
  echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/rules.d/audit.rules
  echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/audit.rules
  echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules

  # Reiniciar auditd para aplicar los cambios
  systemctl restart auditd
}

disable_filesystem_mounts() {
  for fs in cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat; do
    echo "install $fs /bin/true" >> /etc/modprobe.d/$fs.conf
  done
}

harden_password_policy() {
  apt-get install libpam-pwquality -y
  sed -i '/pam_pwquality.so/s/^#//g' /etc/pam.d/common-password
  sed -i '/pam_pwquality.so/ s/retry=3/retry=3 minlen=14 difok=4 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
  echo "auth required pam_tally2.so deny=3 unlock_time=600" >> /etc/pam.d/common-auth
}

harden_sysctl() {
  cat <<EOF >> /etc/sysctl.conf
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF
  sysctl -p
}

secure_file_permissions() {
  chown root:root /etc/passwd
  chmod 644 /etc/passwd
  chown root:root /etc/shadow
  chmod 600 /etc/shadow
  chown root:root /etc/gshadow
  chmod 600 /etc/gshadow
  chmod 600 /boot/grub/grub.cfg
}

harden_ssh() {
  sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  sed -i 's/#PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
  sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  sed -i 's/#X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
  sed -i 's/#MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
  echo "AllowUsers tu_usuario" >> /etc/ssh/sshd_config
  echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config
  echo "Compression no" >> /etc/ssh/sshd_config
  echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
  echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
  systemctl restart sshd
}

disable_kernel_modules() {
  for mod in dccp sctp rds tipc; do
    echo "install $mod /bin/true" >> /etc/modprobe.d/$mod.conf
  done
}

limit_sudo_usage() {
  echo "Defaults use_pty" >> /etc/sudoers
  echo "Defaults logfile=/var/log/sudo.log" >> /etc/sudoers
  echo "Defaults timestamp_timeout=5" >> /etc/sudoers
}

install_fail2ban() {
  apt-get install fail2ban -y
  cat <<EOF > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 4
bantime = 600
EOF
  systemctl enable fail2ban
  systemctl restart fail2ban
}

restrict_compilers() {
  chmod 000 /usr/bin/as
  chmod 000 /usr/bin/gcc
  chmod 000 /usr/bin/cc
}

install_limpam_tmpdir() {
  apt-get install libpam-tmpdir -y
  echo "session required pam_tmpdir.so" >> /etc/pam.d/common-session
}

configure_apparmor() {
  apt-get install apparmor apparmor-profiles apparmor-utils -y
  systemctl enable apparmor
  systemctl start apparmor
  aa-enforce /etc/apparmor.d/*
}

apply_hardening() {
  check_root
  update_system
  partition_setup
  configure_audit
  disable_filesystem_mounts
  harden_password_policy
  harden_sysctl
  secure_file_permissions
  harden_ssh
  disable_kernel_modules
  limit_sudo_usage
  install_fail2ban
  restrict_compilers
  install_limpam_tmpdir
  configure_apparmor
  echo "Hardening completo aplicado."
}

apply_hardening
