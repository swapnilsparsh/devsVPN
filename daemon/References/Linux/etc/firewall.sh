#!/bin/bash

#
#  Daemon for privateLINE Connect Desktop
#  https://github.com/swapnilsparsh/devsVPN/daemon
#
#  Created by Stelnykovych Alexandr.
#  Copyright (c) 2023 IVPN Limited.
#
#  This file is part of the Daemon for privateLINE Connect Desktop.
#
#  The Daemon for privateLINE Connect Desktop is free software: you can redistribute it and/or
#  modify it under the terms of the GNU General Public License as published by the Free
#  Software Foundation, either version 3 of the License, or (at your option) any later version.
#
#  The Daemon for privateLINE Connect Desktop is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
#  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
#  details.
#
#  You should have received a copy of the GNU General Public License
#  along with the Daemon for privateLINE Connect Desktop. If not, see <https://www.gnu.org/licenses/>.
#

# Useful commands
#   List all rules:
#     sudo iptables -L -v
#     or
#     sudo iptables -S

IPv4BIN=iptables
IPv6BIN=ip6tables

LOCKWAITTIME=2

# main chains for PRIVATELINE firewall
IN_PRIVATELINE=PRIVATELINE-IN
OUT_PRIVATELINE=PRIVATELINE-OUT
FORWARD_PRIVATELINE=PRIVATELINE-FORWARD
# chain for DNS rules
OUT_PRIVATELINE_DNS=PRIVATELINE-OUT-DNS
# PRIVATELINE chains for VPN interface rules (applicable when VPN enabled)
# Chanin is processing before OUT_PRIVATELINE_DNS in order to allow connections to port 53
IN_PRIVATELINE_IF0=PRIVATELINE-IN-VPN0
OUT_PRIVATELINE_IF0=PRIVATELINE-OUT-VPN0
# PRIVATELINE chains for VPN interface rules (applicable when VPN enabled)
IN_PRIVATELINE_IF1=PRIVATELINE-IN-VPN
OUT_PRIVATELINE_IF1=PRIVATELINE-OUT-VPN
FORWARD_PRIVATELINE_IF=PRIVATELINE-FORWARD-VPN
# chain for non-VPN depended exceptios (applicable all time when firewall enabled)
# can be used, for example, for 'allow LAN' functionality
IN_PRIVATELINE_STAT_EXP=PRIVATELINE-IN-STAT-EXP
OUT_PRIVATELINE_STAT_EXP=PRIVATELINE-OUT-STAT-EXP
# chain for user-defined exceptios (applicable all time when firewall enabled)
IN_PRIVATELINE_STAT_USER_EXP=PRIVATELINE-IN-STAT-USER-EXP
OUT_PRIVATELINE_STAT_USER_EXP=PRIVATELINE-OUT-STAT-USER-EXP
# chain for non-VPN depended exceptios: only for ICMP protocol (ping)
IN_PRIVATELINE_ICMP_EXP=PRIVATELINE-IN-ICMP-EXP
OUT_PRIVATELINE_ICMP_EXP=PRIVATELINE-OUT-ICMP-EXP

# Chain to allow only specific DNS IP
# (chain rules can be applied when the general "firewall" disabled, for example for Inverse Split Tunnel mode )
PRIVATELINE_OUT_DNSONLY=PRIVATELINE-OUT-DNSONLY

# ### Split Tunnel ###
# Info: The 'mark' value for packets coming from the Split-Tunneling environment.
# Using here value 0xca6c. It is the same as WireGuard marking packets which were processed.
_splittun_packets_fwmark_value=0xca6c
# Split Tunnel iptables rules comment
_splittun_comment="privateLINE Total Shield"
# Split Tunnel cgroup id
_splittun_cgroup_classid=0x70561e1d

# returns 0 if chain exists
function chain_exists()
{
    local bin=$1
    local chain_name=$2
    ${bin} -w ${LOCKWAITTIME} -n -L ${chain_name} >/dev/null 2>&1
}

function create_chain()
{
  local bin=$1
  local chain_name=$2
  chain_exists ${bin} ${chain_name} || ${bin} -w ${LOCKWAITTIME} -N ${chain_name}
}

# erase rules in a chain
function clean_chain() {
  BIN=$1
  CH=$2
  ${BIN} -w ${LOCKWAITTIME} -F ${CH}
}

# Checks if the PRIVATELINE Firewall is enabled
# 0 - if enabled
# 1 - if not enabled
function get_firewall_enabled {
  chain_exists ${IPv4BIN} ${OUT_PRIVATELINE}
}

# allow only specific DNS address: in use by Inverse Split Tunnel mode
# Inverse Split Tunnel mode does not allow to enable "firewall" but have to block unwanted DNS requests anyway

function only_dns {  
  # We can not apply this rules when firewall enabled
  get_firewall_enabled
  if (( $? == 0 )); then
    echo "failed to apply specific DNS rule: Firewall already enabled" >&2
    return 24
  fi

  only_dns_off

  set -e

  DNSIP=$1
  EXCEPTION_IP=$2

  create_chain ${IPv4BIN} ${PRIVATELINE_OUT_DNSONLY}
  ${IPv4BIN} -w ${LOCKWAITTIME} -I OUTPUT -j ${PRIVATELINE_OUT_DNSONLY}

  # Allow communication with IP addresses from EXCEPTION_IP list (if defined)
  # It avoids situation of blocking communication with VPN server over port 53 (e.g. connection trough V2Ray/QUICK on UDP 53)
  if [ ! -z ${EXCEPTION_IP} ]; then
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${PRIVATELINE_OUT_DNSONLY} -d ${EXCEPTION_IP} -p udp --dport 53 -j ACCEPT
  fi

  ${IPv4BIN} -w ${LOCKWAITTIME} -A ${PRIVATELINE_OUT_DNSONLY} -o lo -j ACCEPT  
  ${IPv4BIN} -w ${LOCKWAITTIME} -A ${PRIVATELINE_OUT_DNSONLY} ! -d ${DNSIP} -p tcp --dport 53 -j DROP
  ${IPv4BIN} -w ${LOCKWAITTIME} -A ${PRIVATELINE_OUT_DNSONLY} ! -d ${DNSIP} -p udp --dport 53 -j DROP

  set +e
}

function only_dns_off {  
  chain_exists ${IPv4BIN} ${PRIVATELINE_OUT_DNSONLY}   
  if [ $? -ne 0 ]; then
      return 0
  fi  

  ${IPv4BIN} -w ${LOCKWAITTIME} -D OUTPUT -j ${PRIVATELINE_OUT_DNSONLY}  # disconnect from OUTPUT chain
  ${IPv4BIN} -w ${LOCKWAITTIME} -F ${PRIVATELINE_OUT_DNSONLY}            # erasing all rules in a chain
  ${IPv4BIN} -w ${LOCKWAITTIME} -X ${PRIVATELINE_OUT_DNSONLY}            # delete chain
}

# Load rules
function enable_firewall {
    get_firewall_enabled

    if (( $? == 0 )); then
      echo "Firewall is already enabled. Please disable it first" >&2
      return 0
    fi
    
    only_dns_off

    set -e

    if [ -f /proc/net/if_inet6 ]; then
      ### IPv6 ###

      # IPv6: define chains
      create_chain ${IPv6BIN} ${IN_PRIVATELINE}
      create_chain ${IPv6BIN} ${OUT_PRIVATELINE}
      create_chain ${IPv6BIN} ${FORWARD_PRIVATELINE}

      create_chain ${IPv6BIN} ${IN_PRIVATELINE_IF0}
      create_chain ${IPv6BIN} ${OUT_PRIVATELINE_IF0}

      create_chain ${IPv6BIN} ${OUT_PRIVATELINE_DNS}

      create_chain ${IPv6BIN} ${IN_PRIVATELINE_IF1}
      create_chain ${IPv6BIN} ${OUT_PRIVATELINE_IF1}
      create_chain ${IPv6BIN} ${FORWARD_PRIVATELINE_IF}

      create_chain ${IPv6BIN} ${IN_PRIVATELINE_STAT_USER_EXP}
      create_chain ${IPv6BIN} ${OUT_PRIVATELINE_STAT_USER_EXP}

      # block DNS for IPv6
      #
      # Important: Block DNS before allowing link-local and unique-localaddresses!
      # It will prevent potential DNS leaking in some situations (for example, from VM to a host machine)
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_DNS}
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE_DNS} -p udp --dport 53 -j DROP
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE_DNS} -p tcp --dport 53 -j DROP

      # IPv6: allow  local (lo) interface
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -o lo -j ACCEPT
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE} -i lo -j ACCEPT

      # allow link-local addresses
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE} -s FE80::/10 -j ACCEPT
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -d FE80::/10 -j ACCEPT

      # allow unique-local addresses
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE} -s FD00::/8 -j ACCEPT
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -d FD00::/8 -j ACCEPT

      # allow DHCP port (547out 546in)
      # ${IPv6BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -p udp --dport 547 -j ACCEPT
      # ${IPv6BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE} -p udp --dport 546 -j ACCEPT

      # IPv6: assign our chains to global (global -> PRIVATELINE_CHAIN -> PRIVATELINE_VPN_CHAIN)

      # Note! Using "-I" parameter to add PRIVATELINE rules on the top of iptables rules sequence
      ${IPv6BIN} -w ${LOCKWAITTIME} -I OUTPUT -j ${OUT_PRIVATELINE}
      ${IPv6BIN} -w ${LOCKWAITTIME} -I INPUT -j ${IN_PRIVATELINE}
      ${IPv6BIN} -w ${LOCKWAITTIME} -I FORWARD -j ${FORWARD_PRIVATELINE}

      # Split Tunnel: Allow packets from/to cgroup (bypass PRIVATELINE firewall)
      ${IPv6BIN} -w ${LOCKWAITTIME} -I ${OUT_PRIVATELINE} -m cgroup --cgroup ${_splittun_cgroup_classid} -m comment --comment  "${_splittun_comment}" -j ACCEPT || echo "Failed to add OUTPUT (cgroup) rule for split-tunnel"
      ${IPv6BIN} -w ${LOCKWAITTIME} -I ${IN_PRIVATELINE} -m cgroup --cgroup ${_splittun_cgroup_classid} -m comment --comment  "${_splittun_comment}" -j ACCEPT || echo "Failed to add INPUT (cgroup) rule for split-tunnel"  # this rule is not effective, so we use 'mark' (see the next rule)
      ${IPv6BIN} -w ${LOCKWAITTIME} -I ${IN_PRIVATELINE} -m mark --mark ${_splittun_packets_fwmark_value} -m comment --comment  "${_splittun_comment}" -j ACCEPT  || echo "Failed to add INPUT (mark) rule for split-tunnel"

      # exceptions
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_IF0}
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_IF0}

      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_IF1}
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_IF1}
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${FORWARD_PRIVATELINE} -j ${FORWARD_PRIVATELINE_IF}
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_STAT_USER_EXP}
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_STAT_USER_EXP}

      # IPv6: block everything by default
      ${IPv6BIN} -w ${LOCKWAITTIME} -P INPUT DROP
      ${IPv6BIN} -w ${LOCKWAITTIME} -P OUTPUT DROP
      ${IPv6BIN} -w ${LOCKWAITTIME} -P FORWARD DROP

      # Aggressive block!
      # Note! If the packet does not match any PRIVATELINE rule - DROP it.
      # It prevents traversing packet analysis to the rest rules (if defined) and avoids any leaks
      # This will block all user-defined firewall rules!
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -j DROP
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE}  -j DROP
      ${IPv6BIN} -w ${LOCKWAITTIME} -A ${FORWARD_PRIVATELINE}  -j DROP

    else
      echo "IPv6 disabled: skipping IPv6 rules"
    fi

    ### IPv4 ###

    # define chains
    create_chain ${IPv4BIN} ${IN_PRIVATELINE}
    create_chain ${IPv4BIN} ${OUT_PRIVATELINE}
    create_chain ${IPv4BIN} ${FORWARD_PRIVATELINE}

    create_chain ${IPv4BIN} ${IN_PRIVATELINE_IF0}
    create_chain ${IPv4BIN} ${OUT_PRIVATELINE_IF0}

    create_chain ${IPv4BIN} ${OUT_PRIVATELINE_DNS}

    create_chain ${IPv4BIN} ${IN_PRIVATELINE_IF1}
    create_chain ${IPv4BIN} ${OUT_PRIVATELINE_IF1}
    create_chain ${IPv4BIN} ${FORWARD_PRIVATELINE_IF}

    create_chain ${IPv4BIN} ${IN_PRIVATELINE_STAT_EXP}
    create_chain ${IPv4BIN} ${OUT_PRIVATELINE_STAT_EXP}

    create_chain ${IPv4BIN} ${IN_PRIVATELINE_STAT_USER_EXP}
    create_chain ${IPv4BIN} ${OUT_PRIVATELINE_STAT_USER_EXP}

    create_chain ${IPv4BIN} ${IN_PRIVATELINE_ICMP_EXP}
    create_chain ${IPv4BIN} ${OUT_PRIVATELINE_ICMP_EXP}

    # allow  local (lo) interface
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -o lo -j ACCEPT
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE} -i lo -j ACCEPT

    # allow DHCP port (67out 68in)
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -p udp --dport 67 -j ACCEPT
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE} -p udp --dport 68 -j ACCEPT

    # enable all ICMP ping outgoing request (needed to be able to ping VPN servers)
    #${IPv4BIN} -A ${OUT_PRIVATELINE} -p icmp --icmp-type 8 -d 0/0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
    #${IPv4BIN} -A ${IN_PRIVATELINE} -p icmp --icmp-type 0 -s 0/0 -m state --state ESTABLISHED,RELATED -j ACCEPT

    # assign our chains to global
    # (global -> PRIVATELINE_CHAIN -> PRIVATELINE_VPN_CHAIN)
    # (global -> PRIVATELINE_CHAIN -> IN_PRIVATELINE_STAT_EXP)

    # Note! Using "-I" parameter to add PRIVATELINE rules on the top of iptables rules sequence
    ${IPv4BIN} -w ${LOCKWAITTIME} -I OUTPUT -j ${OUT_PRIVATELINE}
    ${IPv4BIN} -w ${LOCKWAITTIME} -I INPUT -j ${IN_PRIVATELINE}
    ${IPv4BIN} -w ${LOCKWAITTIME} -I FORWARD -j ${FORWARD_PRIVATELINE}

    # Split Tunnel: Allow packets from/to cgroup (bypass PRIVATELINE firewall)
    ${IPv4BIN} -w ${LOCKWAITTIME} -I ${OUT_PRIVATELINE} -m cgroup --cgroup ${_splittun_cgroup_classid} -m comment --comment  "${_splittun_comment}" -j ACCEPT || echo "Failed to add OUTPUT (cgroup) rule for split-tunnel"
    ${IPv4BIN} -w ${LOCKWAITTIME} -I ${IN_PRIVATELINE} -m cgroup --cgroup ${_splittun_cgroup_classid} -m comment --comment  "${_splittun_comment}" -j ACCEPT || echo "Failed to add INPUT (cgroup) rule for split-tunnel"  # this rule is not effective, so we use 'mark' (see the next rule)
    ${IPv4BIN} -w ${LOCKWAITTIME} -I ${IN_PRIVATELINE} -m mark --mark ${_splittun_packets_fwmark_value} -m comment --comment  "${_splittun_comment}" -j ACCEPT || echo "Failed to add INPUT (mark) rule for split-tunnel"

    # exceptions (must be processed before OUT_PRIVATELINE_DNS!)
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_IF0}
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_IF0}

    # block DNS by default
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_DNS}
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE_DNS} -p udp --dport 53 -j DROP
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE_DNS} -p tcp --dport 53 -j DROP

    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_IF1}
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_IF1}
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${FORWARD_PRIVATELINE} -j ${FORWARD_PRIVATELINE_IF}

    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_STAT_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_STAT_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_STAT_USER_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_STAT_USER_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_ICMP_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_ICMP_EXP}

    # block everything by default
    ${IPv4BIN} -w ${LOCKWAITTIME} -P INPUT DROP
    ${IPv4BIN} -w ${LOCKWAITTIME} -P OUTPUT DROP
    ${IPv4BIN} -w ${LOCKWAITTIME} -P FORWARD DROP

    # Aggressive block!
    # Note! If the packet does not match any PRIVATELINE rule - DROP it.
    # It prevents traversing packet analysis to the rest rules (if defined) and avoids any leaks
    # This will block all user-defined firewall rules!
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE} -j DROP
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE}  -j DROP
    ${IPv4BIN} -w ${LOCKWAITTIME} -A ${FORWARD_PRIVATELINE}  -j DROP

    set +e

    echo "PRIVATELINE Firewall enabled"
}

# Remove all rules
function disable_firewall {
    
    only_dns_off

    # Flush rules and delete custom chains

    ### allow everything by default ###
    ${IPv4BIN} -w ${LOCKWAITTIME} -P INPUT ACCEPT
    ${IPv4BIN} -w ${LOCKWAITTIME} -P OUTPUT ACCEPT
    ${IPv4BIN} -w ${LOCKWAITTIME} -P FORWARD ACCEPT

    ${IPv6BIN} -w ${LOCKWAITTIME} -P INPUT ACCEPT
    ${IPv6BIN} -w ${LOCKWAITTIME} -P OUTPUT ACCEPT
    ${IPv6BIN} -w ${LOCKWAITTIME} -P FORWARD ACCEPT

    ### IPv4 ###
    # '-D' Delete matching rule from chain
    ${IPv4BIN} -w ${LOCKWAITTIME} -D OUTPUT -j ${OUT_PRIVATELINE}
    ${IPv4BIN} -w ${LOCKWAITTIME} -D INPUT -j ${IN_PRIVATELINE}
    ${IPv4BIN} -w ${LOCKWAITTIME} -D FORWARD -j ${FORWARD_PRIVATELINE}
    ${IPv4BIN} -w ${LOCKWAITTIME} -D ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_IF0}
    ${IPv4BIN} -w ${LOCKWAITTIME} -D ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_IF0}    
    ${IPv4BIN} -w ${LOCKWAITTIME} -D ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_DNS}    
    ${IPv4BIN} -w ${LOCKWAITTIME} -D ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_IF1}
    ${IPv4BIN} -w ${LOCKWAITTIME} -D ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_IF1}
    ${IPv4BIN} -w ${LOCKWAITTIME} -D ${FORWARD_PRIVATELINE} -j ${FORWARD_PRIVATELINE_IF}    
    ${IPv4BIN} -w ${LOCKWAITTIME} -D ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_STAT_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -D ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_STAT_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -D ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_STAT_USER_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -D ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_STAT_USER_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -D ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_ICMP_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -D ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_ICMP_EXP}

    # '-F' Delete all rules in  chain or all chains
    ${IPv4BIN} -w ${LOCKWAITTIME} -F ${OUT_PRIVATELINE_IF0}
    ${IPv4BIN} -w ${LOCKWAITTIME} -F ${IN_PRIVATELINE_IF0}    
    ${IPv4BIN} -w ${LOCKWAITTIME} -F ${OUT_PRIVATELINE_DNS}
    ${IPv4BIN} -w ${LOCKWAITTIME} -F ${OUT_PRIVATELINE_IF1}
    ${IPv4BIN} -w ${LOCKWAITTIME} -F ${IN_PRIVATELINE_IF1}
    ${IPv4BIN} -w ${LOCKWAITTIME} -F ${FORWARD_PRIVATELINE_IF}
    ${IPv4BIN} -w ${LOCKWAITTIME} -F ${OUT_PRIVATELINE}
    ${IPv4BIN} -w ${LOCKWAITTIME} -F ${IN_PRIVATELINE}
    ${IPv4BIN} -w ${LOCKWAITTIME} -F ${FORWARD_PRIVATELINE}
    ${IPv4BIN} -w ${LOCKWAITTIME} -F ${OUT_PRIVATELINE_STAT_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -F ${IN_PRIVATELINE_STAT_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -F ${OUT_PRIVATELINE_STAT_USER_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -F ${IN_PRIVATELINE_STAT_USER_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -F ${OUT_PRIVATELINE_ICMP_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -F ${IN_PRIVATELINE_ICMP_EXP}
    # '-X' Delete a user-defined chain
    ${IPv4BIN} -w ${LOCKWAITTIME} -X ${OUT_PRIVATELINE_IF0}
    ${IPv4BIN} -w ${LOCKWAITTIME} -X ${IN_PRIVATELINE_IF0}    
    ${IPv4BIN} -w ${LOCKWAITTIME} -X ${OUT_PRIVATELINE_DNS}
    ${IPv4BIN} -w ${LOCKWAITTIME} -X ${OUT_PRIVATELINE_IF1}
    ${IPv4BIN} -w ${LOCKWAITTIME} -X ${IN_PRIVATELINE_IF1}
    ${IPv4BIN} -w ${LOCKWAITTIME} -X ${FORWARD_PRIVATELINE_IF}
    ${IPv4BIN} -w ${LOCKWAITTIME} -X ${OUT_PRIVATELINE}
    ${IPv4BIN} -w ${LOCKWAITTIME} -X ${IN_PRIVATELINE}
    ${IPv4BIN} -w ${LOCKWAITTIME} -X ${FORWARD_PRIVATELINE}
    ${IPv4BIN} -w ${LOCKWAITTIME} -X ${OUT_PRIVATELINE_STAT_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -X ${IN_PRIVATELINE_STAT_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -X ${OUT_PRIVATELINE_STAT_USER_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -X ${IN_PRIVATELINE_STAT_USER_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -X ${OUT_PRIVATELINE_ICMP_EXP}
    ${IPv4BIN} -w ${LOCKWAITTIME} -X ${IN_PRIVATELINE_ICMP_EXP}

    ### IPv6 ###
    ${IPv6BIN} -w ${LOCKWAITTIME} -D OUTPUT -j ${OUT_PRIVATELINE}
    ${IPv6BIN} -w ${LOCKWAITTIME} -D INPUT -j ${IN_PRIVATELINE}
    ${IPv6BIN} -w ${LOCKWAITTIME} -D FORWARD -j ${FORWARD_PRIVATELINE}
    ${IPv6BIN} -w ${LOCKWAITTIME} -D ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_IF0}
    ${IPv6BIN} -w ${LOCKWAITTIME} -D ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_IF0}    
    ${IPv6BIN} -w ${LOCKWAITTIME} -D ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_DNS}
    ${IPv6BIN} -w ${LOCKWAITTIME} -D ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_IF1}
    ${IPv6BIN} -w ${LOCKWAITTIME} -D ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_IF1}
    ${IPv6BIN} -w ${LOCKWAITTIME} -D ${FORWARD_PRIVATELINE} -j ${FORWARD_PRIVATELINE_IF}     
    ${IPv6BIN} -w ${LOCKWAITTIME} -D ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_STAT_EXP}
    ${IPv6BIN} -w ${LOCKWAITTIME} -D ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_STAT_EXP}
    ${IPv6BIN} -w ${LOCKWAITTIME} -D ${OUT_PRIVATELINE} -j ${OUT_PRIVATELINE_STAT_USER_EXP}
    ${IPv6BIN} -w ${LOCKWAITTIME} -D ${IN_PRIVATELINE} -j ${IN_PRIVATELINE_STAT_USER_EXP}

    ${IPv6BIN} -w ${LOCKWAITTIME} -F ${OUT_PRIVATELINE_IF0}
    ${IPv6BIN} -w ${LOCKWAITTIME} -F ${IN_PRIVATELINE_IF0}    
    ${IPv6BIN} -w ${LOCKWAITTIME} -F ${OUT_PRIVATELINE_DNS}
    ${IPv6BIN} -w ${LOCKWAITTIME} -F ${OUT_PRIVATELINE_IF1}
    ${IPv6BIN} -w ${LOCKWAITTIME} -F ${IN_PRIVATELINE_IF1}
    ${IPv6BIN} -w ${LOCKWAITTIME} -F ${FORWARD_PRIVATELINE_IF}
    ${IPv6BIN} -w ${LOCKWAITTIME} -F ${OUT_PRIVATELINE}
    ${IPv6BIN} -w ${LOCKWAITTIME} -F ${IN_PRIVATELINE}
    ${IPv6BIN} -w ${LOCKWAITTIME} -F ${FORWARD_PRIVATELINE}
    ${IPv6BIN} -w ${LOCKWAITTIME} -F ${OUT_PRIVATELINE_STAT_EXP}
    ${IPv6BIN} -w ${LOCKWAITTIME} -F ${IN_PRIVATELINE_STAT_EXP}
    ${IPv6BIN} -w ${LOCKWAITTIME} -F ${OUT_PRIVATELINE_STAT_USER_EXP}
    ${IPv6BIN} -w ${LOCKWAITTIME} -F ${IN_PRIVATELINE_STAT_USER_EXP}

    ${IPv6BIN} -w ${LOCKWAITTIME} -X ${OUT_PRIVATELINE_IF0}
    ${IPv6BIN} -w ${LOCKWAITTIME} -X ${IN_PRIVATELINE_IF0}    
    ${IPv6BIN} -w ${LOCKWAITTIME} -X ${OUT_PRIVATELINE_DNS}
    ${IPv6BIN} -w ${LOCKWAITTIME} -X ${OUT_PRIVATELINE_IF1}
    ${IPv6BIN} -w ${LOCKWAITTIME} -X ${IN_PRIVATELINE_IF1}
    ${IPv6BIN} -w ${LOCKWAITTIME} -X ${FORWARD_PRIVATELINE_IF}
    ${IPv6BIN} -w ${LOCKWAITTIME} -X ${OUT_PRIVATELINE}
    ${IPv6BIN} -w ${LOCKWAITTIME} -X ${IN_PRIVATELINE}
    ${IPv6BIN} -w ${LOCKWAITTIME} -X ${FORWARD_PRIVATELINE}
    ${IPv6BIN} -w ${LOCKWAITTIME} -X ${OUT_PRIVATELINE_STAT_EXP}
    ${IPv6BIN} -w ${LOCKWAITTIME} -X ${IN_PRIVATELINE_STAT_EXP}
    ${IPv6BIN} -w ${LOCKWAITTIME} -X ${OUT_PRIVATELINE_STAT_USER_EXP}
    ${IPv6BIN} -w ${LOCKWAITTIME} -X ${IN_PRIVATELINE_STAT_USER_EXP}
    echo "PRIVATELINE Firewall disabled"
}

function client_connected {
  IFACE=$1

  # allow all packets to VPN interface
  ${IPv4BIN} -w ${LOCKWAITTIME} -C ${OUT_PRIVATELINE_IF1} -o ${IFACE} -j ACCEPT || ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE_IF1} -o ${IFACE} -j ACCEPT
  ${IPv4BIN} -w ${LOCKWAITTIME} -C ${IN_PRIVATELINE_IF1} -i ${IFACE} -j ACCEPT || ${IPv4BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE_IF1} -i ${IFACE} -j ACCEPT
  ${IPv4BIN} -w ${LOCKWAITTIME} -C ${FORWARD_PRIVATELINE_IF} -i ${IFACE} -j ACCEPT || ${IPv4BIN} -w ${LOCKWAITTIME} -A ${FORWARD_PRIVATELINE_IF} -i ${IFACE} -j ACCEPT
  ${IPv4BIN} -w ${LOCKWAITTIME} -C ${FORWARD_PRIVATELINE_IF} -o ${IFACE} -j ACCEPT || ${IPv4BIN} -w ${LOCKWAITTIME} -A ${FORWARD_PRIVATELINE_IF} -o ${IFACE} -j ACCEPT

  if [ -f /proc/net/if_inet6 ]; then
      ### IPv6 ###

      # allow all packets to VPN interface
      ${IPv6BIN} -w ${LOCKWAITTIME} -C ${OUT_PRIVATELINE_IF1} -o ${IFACE} -j ACCEPT || ${IPv6BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE_IF1} -o ${IFACE} -j ACCEPT
      ${IPv6BIN} -w ${LOCKWAITTIME} -C ${IN_PRIVATELINE_IF1} -i ${IFACE} -j ACCEPT || ${IPv6BIN} -w ${LOCKWAITTIME} -A ${IN_PRIVATELINE_IF1} -i ${IFACE} -j ACCEPT
      ${IPv6BIN} -w ${LOCKWAITTIME} -C ${FORWARD_PRIVATELINE_IF} -i ${IFACE} -j ACCEPT || ${IPv6BIN} -w ${LOCKWAITTIME} -A ${FORWARD_PRIVATELINE_IF} -i ${IFACE} -j ACCEPT
      ${IPv6BIN} -w ${LOCKWAITTIME} -C ${FORWARD_PRIVATELINE_IF} -o ${IFACE} -j ACCEPT || ${IPv6BIN} -w ${LOCKWAITTIME} -A ${FORWARD_PRIVATELINE_IF} -o ${IFACE} -j ACCEPT
    fi
}

function client_disconnected {
  ${IPv4BIN} -w ${LOCKWAITTIME} -F ${OUT_PRIVATELINE_IF1}
  ${IPv4BIN} -w ${LOCKWAITTIME} -F ${IN_PRIVATELINE_IF1}
  ${IPv4BIN} -w ${LOCKWAITTIME} -F ${FORWARD_PRIVATELINE_IF}

  if [ -f /proc/net/if_inet6 ]; then
    ### IPv6 ###
    ${IPv6BIN} -w ${LOCKWAITTIME} -F ${OUT_PRIVATELINE_IF1}
    ${IPv6BIN} -w ${LOCKWAITTIME} -F ${IN_PRIVATELINE_IF1}
    ${IPv6BIN} -w ${LOCKWAITTIME} -F ${FORWARD_PRIVATELINE_IF}
  fi
}

function add_exceptions {
  BIN=$1
  IN_CH=$2
  OUT_CH=$3
  shift 3
  EXP=$@

  create_chain ${BIN} ${IN_CH}
  create_chain ${BIN} ${OUT_CH}

  #add new rule
  # '-C' option is checking if the rule already exists (needed to avoid duplicates)
  ${BIN} -w ${LOCKWAITTIME} -C ${IN_CH} -s $@ -j ACCEPT || ${BIN} -w ${LOCKWAITTIME} -A ${IN_CH} -s $@ -j ACCEPT
  ${BIN} -w ${LOCKWAITTIME} -C ${OUT_CH} -d $@ -j ACCEPT || ${BIN} -w ${LOCKWAITTIME} -A ${OUT_CH} -d $@ -j ACCEPT
}

function remove_exceptions {
  BIN=$1
  IN_CH=$2
  OUT_CH=$3
  shift 3
  EXP=$@

  ${BIN} -w ${LOCKWAITTIME} -D ${IN_CH} -s $@ -j ACCEPT
  ${BIN} -w ${LOCKWAITTIME} -D ${OUT_CH} -d $@ -j ACCEPT
}

function add_direction_exception {
  IN_CH=$1
  OUT_CH=$2

  #SRC_PORT=$3
  DST_ADDR=$4
  DST_PORT=$5
  PROTOCOL=$6

  create_chain ${IPv4BIN} ${IN_CH}
  create_chain ${IPv4BIN} ${OUT_CH}

  #add new rule
  # '-C' option is checking if the rule already exists (needed to avoid duplicates)
  ${IPv4BIN} -w ${LOCKWAITTIME} -C ${IN_CH}  -s ${DST_ADDR} -p ${PROTOCOL} --sport ${DST_PORT} -j ACCEPT || ${IPv4BIN} -w ${LOCKWAITTIME} -A ${IN_CH}  -s ${DST_ADDR} -p ${PROTOCOL} --sport ${DST_PORT} -j ACCEPT
  ${IPv4BIN} -w ${LOCKWAITTIME} -C ${OUT_CH} -d ${DST_ADDR} -p ${PROTOCOL} --dport ${DST_PORT} -j ACCEPT || ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_CH} -d ${DST_ADDR} -p ${PROTOCOL} --dport ${DST_PORT} -j ACCEPT
}

function remove_exceptions_icmp {
  IN_CH=$1
  OUT_CH=$2
  shift 2
  EXP=$@

  ${IPv4BIN} -w ${LOCKWAITTIME} -D ${IN_CH} -p icmp --icmp-type 0 -s $@ -m state --state ESTABLISHED,RELATED -j ACCEPT
  ${IPv4BIN} -w ${LOCKWAITTIME} -D ${OUT_CH} -p icmp --icmp-type 8 -d $@ -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
}

function add_exceptions_icmp {
  IN_CH=$1
  OUT_CH=$2
  shift 2
  EXP=$@

  create_chain ${IPv4BIN} ${IN_CH}
  create_chain ${IPv4BIN} ${OUT_CH}

  # remove same rule if exists (just to avoid duplicates)
  ${IPv4BIN} -w ${LOCKWAITTIME} -D ${IN_CH} -p icmp --icmp-type 0 -s $@ -m state --state ESTABLISHED,RELATED -j ACCEPT
  ${IPv4BIN} -w ${LOCKWAITTIME} -D ${OUT_CH} -p icmp --icmp-type 8 -d $@ -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

  #add new rule
  ${IPv4BIN} -w ${LOCKWAITTIME} -A ${IN_CH} -p icmp --icmp-type 0 -s $@ -m state --state ESTABLISHED,RELATED -j ACCEPT
  ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_CH} -p icmp --icmp-type 8 -d $@ -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
}

function main {

    if [[ $1 = "-enable" ]] ; then

      enable_firewall

    elif [[ $1 = "-disable" ]] ; then

      disable_firewall

    elif [[ $1 = "-status" ]] ; then

      get_firewall_enabled

      if (( $? == 0 )); then
        echo "PRIVATELINE Firewall is enabled"
        return 0
      else
        echo "PRIVATELINE Firewall is disabled"
        return 1
      fi

    elif [[ $1 = "-add_exceptions" ]]; then
      get_firewall_enabled || return 0

      shift
      add_exceptions ${IPv4BIN} ${IN_PRIVATELINE_IF0} ${OUT_PRIVATELINE_IF0} $@

    elif [[ $1 = "-remove_exceptions" ]]; then
      shift
      remove_exceptions ${IPv4BIN} ${IN_PRIVATELINE_IF0} ${OUT_PRIVATELINE_IF0} $@

    elif [[ $1 = "-add_exceptions_static" ]]; then

      shift
      add_exceptions ${IPv4BIN} ${IN_PRIVATELINE_STAT_EXP} ${OUT_PRIVATELINE_STAT_EXP} $@

    elif [[ $1 = "-remove_exceptions_static" ]]; then

      shift
      remove_exceptions ${IPv4BIN} ${IN_PRIVATELINE_STAT_EXP} ${OUT_PRIVATELINE_STAT_EXP} $@

    # User exceptions
    elif [[ $1 = "-set_user_exceptions_static" ]]; then

      shift
      clean_chain ${IPv4BIN} ${IN_PRIVATELINE_STAT_USER_EXP}
      clean_chain ${IPv4BIN} ${OUT_PRIVATELINE_STAT_USER_EXP}

      [ -z "$@" ] && return
      add_exceptions ${IPv4BIN} ${IN_PRIVATELINE_STAT_USER_EXP} ${OUT_PRIVATELINE_STAT_USER_EXP} $@

    elif [[ $1 = "-set_user_exceptions_static_ipv6" ]]; then

      if [ -f /proc/net/if_inet6 ]; then
        shift
        clean_chain ${IPv6BIN} ${IN_PRIVATELINE_STAT_USER_EXP}
        clean_chain ${IPv6BIN} ${OUT_PRIVATELINE_STAT_USER_EXP}

        [ -z "$@" ] && return
        add_exceptions ${IPv6BIN} ${IN_PRIVATELINE_STAT_USER_EXP} ${OUT_PRIVATELINE_STAT_USER_EXP} $@
      fi

    # DNS rules
    elif [[ $1 = "-set_dns" ]]; then

      get_firewall_enabled || return 0

      shift

      clean_chain ${IPv4BIN} ${OUT_PRIVATELINE_DNS}

      if [[ -z "$@" ]] ; then
        # block DNS
        ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE_DNS} -p udp --dport 53 -j DROP
        ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE_DNS} -p tcp --dport 53 -j DROP
      else
        # block everything except defined address
        ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE_DNS} ! -d $@ -p udp --dport 53 -j DROP
        ${IPv4BIN} -w ${LOCKWAITTIME} -A ${OUT_PRIVATELINE_DNS} ! -d $@ -p tcp --dport 53 -j DROP
      fi

    # icmp exceptions
    elif [[ $1 = "-add_exceptions_icmp" ]]; then

      shift
      add_exceptions_icmp ${IN_PRIVATELINE_ICMP_EXP} ${OUT_PRIVATELINE_ICMP_EXP} $@

    elif [[ $1 = "-remove_exceptions_icmp" ]]; then

      shift
      remove_exceptions_icmp ${IN_PRIVATELINE_ICMP_EXP} ${OUT_PRIVATELINE_ICMP_EXP} $@

    elif [[ $1 = "-connected" ]]; then

        get_firewall_enabled || return 0

        IFACE=$2
        #SRC_ADDR=$3
        SRC_PORT=$4
        DST_ADDR=$5
        DST_PORT=$6
        PROTOCOL=$7

        # allow all communication trough vpn interface
        client_connected ${IFACE}

        # allow communication with host only srcPort <=> host.dstsPort
        add_direction_exception ${IN_PRIVATELINE_IF0} ${OUT_PRIVATELINE_IF0} ${SRC_PORT} ${DST_ADDR} ${DST_PORT} ${PROTOCOL}
    elif [[ $1 = "-disconnected" ]]; then
        get_firewall_enabled || return 0

        shift
        client_disconnected

        clean_chain ${IPv4BIN} ${OUT_PRIVATELINE_IF0}
        clean_chain ${IPv4BIN} ${IN_PRIVATELINE_IF0}
    elif [[ $1 = "-only_dns" ]]; then
      # allow only specific DNS address: in use by Inverse Split Tunnel mode
      # Inverse Split Tunnel mode does not allow to enable "firewall" but have to block unwanted DNS requests anyway

      DNSIP=$2
      EXCEPTION_IP=$3

      only_dns ${DNSIP} ${EXCEPTION_IP}
    
    elif [[ $1 = "-only_dns_off" ]]; then
      only_dns_off

    else
        echo "Unknown command"
        return 2
    fi
}

main $@
