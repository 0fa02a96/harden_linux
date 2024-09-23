# harden_linux

- check_root(): Verifica si el script se ejecuta como root.
- update_system(): Actualiza el sistema operativo.
- partition_setup(): Configura particiones seguras en /etc/fstab según las recomendaciones de CIS.
- configure_audit(): Configura auditd y las reglas de auditoría recomendadas por CIS.
- disable_filesystem_mounts(): Deshabilita el montaje de ciertos sistemas de archivos innecesarios.
- harden_password_policy(): Configura políticas de contraseñas seguras utilizando libpam-pwquality.
- harden_sysctl(): Aplica configuraciones de seguridad de red y del sistema a través de sysctl.
- secure_file_permissions(): Asegura los permisos de archivos críticos como /etc/passwd y /etc/shadow.
- harden_ssh(): Endurece la configuración del servicio SSH para mejorar la seguridad.
- disable_kernel_modules(): Deshabilita módulos de kernel innecesarios como dccp, sctp, entre otros.
- limit_sudo_usage(): Limita el uso de sudo y configura el registro de comandos sudo.
- install_fail2ban(): Instala y configura fail2ban para proteger el acceso SSH contra ataques de fuerza bruta.
- restrict_compilers(): Restringe el acceso a compiladores como gcc y as.
- install_limpam_tmpdir(): Instala y configura libpam-tmpdir para asegurar que los usuarios tengan directorios temporales privados.
- configure_apparmor(): Instala y habilita perfiles de AppArmor para el control de acceso obligatorio.
- apply_hardening(): Ejecuta todas las funciones anteriores en secuencia para aplicar el hardening completo del sistema.
