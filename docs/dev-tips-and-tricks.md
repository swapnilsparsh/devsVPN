# Development & Testing - Tips & Tricks
- [Development \& Testing - Tips \& Tricks](#development--testing---tips--tricks)
	- [Monitoring Daemon And UI Logs Simultaneously, Multiplexed](#monitoring-daemon-and-ui-logs-simultaneously-multiplexed)
		- [Windows](#windows)
		- [Linux](#linux)
	- [Useful Scripts](#useful-scripts)
		- [Linux](#linux-1)

## Monitoring Daemon And UI Logs Simultaneously, Multiplexed

### Windows

Install Cygwin. If you want greyscale, non-colorized multiplex of daemon and UI logs - start Cygwin shell as an Administrator and run there:
```bash
tail -F -n0 "/cygdrive/c/Program Files/privateLINE Connect/log/privateline-connect-svc.log" /cygdrive/c/Users/$USER/AppData/Roaming/privateline-connect-ui/logs/main.log
```
If you want colorized log multiplex - in Cygwin installer install multitail package, either version below 7.1.3-1, or above it. Multitail v7.1.3-1 has a bug. Start Cygwin shell as an Administrator and run there:
```bash
multitail -N 0 -CS zarafa --retry-all -i "/cygdrive/c/Program Files/privateLINE Connect/log/privateline-connect-svc.log" -i /cygdrive/c/Users/$USER/AppData/Roaming/privateline-connect-ui/logs/main.log
```

### Linux
```bash
# Install ccze via package manager and run command in the shell. (Substitute <username> for the username of the account under which privateline-connect-ui runs.)
sudo tail -F -n0 /var/log/privateline/privateline-connect-svc.log /home/<username>/.config/privateline-connect-ui/logs/main.log | ccze -A
```

## Useful Scripts

### Linux
- Use `cli/References/Linux/plconnect_linux.uninstall_clean.sh` to uninstall all privateLINE packages and purge all privateLINE configuration. Although package uninstall scripts should do this anyway, if they work properly.
- Use `cli/References/Linux/plconnect_linux.print_routes_and_ipv6.sh` to print non-localhost routes (IPv4 and IPv6), and whether IPv6 is disabled.
