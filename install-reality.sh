#!/bin/bash
#
# https://github.com/Jaffarrr/Reality/blob/main/install-reality.sh
#
# Copyright (c) https://github.com/Jaffarrr
#

exitalert()  { echo "Error: $1" >&2; exit 1; }

show_intro() {
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	echo "Welcome to XRay Reality and ShadowSocks installer"
	echo "GitHub: https://github.com/Jaffarrr/Reality/blob/main/install-reality.sh"
	echo 
	echo "Copyright (c) https://github.com/Jaffarrr"
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
}

gen_settings() {
	SSPORT="8388"
	SNI="www.nvidia.com"
	METHOD="2022-blake3-aes-128-gcm"
	UUID=`/opt/xray/xray uuid`
	SSPASS=`openssl rand -base64 16`
	KEYS=`/opt/xray/xray x25519 >/opt/xray/keys`
	PRIVKEY=`cat /opt/xray/keys | grep "Private key:" | cut -d: -f2 | sed 's/ //g'`
	PUBKEY=`cat /opt/xray/keys | grep "Public key:" | cut -d: -f2 | sed 's/ //g'`
	rm -f /opt/xray/keys
	SHORTID=`openssl rand -hex 8`
}

check_architecture() {
	ARCC="$(arch)"
	if [[ "$ARCC" == "x86_64" ]]; then
		REL_NAME="Xray-linux-64.zip"
	else
		REL_NAME="Xray-linux-32.zip"
	fi
}

checkVirt() {
        if [ "$(systemd-detect-virt)" == "openvz" ]; then
                echo "OpenVZ is not supported"
                exit 1
        fi
}

install_wget() {
	# Detect some Debian minimal setups where neither wget nor curl are installed
	if ! hash wget 2>/dev/null || ! hash curl 2>/dev/null || ! hash apt-utils 2>/dev/null || ! hash unzip 2>/dev/null; then
			echo "wget/curl/unzip/apt-utils is required to use this installer."
			read -n1 -r -p "Press any key to install wget/curl/unzip/apt-utils and continue..."
		export DEBIAN_FRONTEND=noninteractive
		(
			set -x
			apt-get -yqq update || apt-get -yqq update
			apt-get -yqq install apt-utils >/dev/null
			apt-get -yqq install wget >/dev/null
			apt-get -yqq install curl >/dev/null
			apt-get -yqq install unzip >/dev/null
		) || exitalert "apt-get install failed!"
	fi
}

detect_qrencode() {
				if ! hash qrencode 2>/dev/null; then
				echo "qrencode is not installed, trying to install..."
				(
					apt-get -yqq install qrencode >/dev/null
				) || exitalert "qrencode install failed!"
			fi
}

make_config() {
cat >> /opt/xray/config.json <<EOF
{
  "log": {
    "loglevel": "info"
  },
  "routing": {
    "rules": [],
    "domainStrategy": "AsIs"
  },
  "inbounds": [
    {
      "port": $SSPORT,
      "tag": "ss",
      "protocol": "shadowsocks",
      "settings": {
        "method": "$METHOD",
        "password": "$SSPASS",
        "network": "tcp,udp"
      }
    },
    {
      "port": 443,
      "protocol": "vless",
      "tag": "vless_tls",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "email": "user1@myserver",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "show": false,
            "dest": "$SNI:443",
            "xver": 0,
            "serverNames": [
                "$SNI"
            ],
            "privateKey": "$PRIVKEY",
            "minClientVer": "",
            "maxClientVer": "",
            "maxTimeDiff": 0,
            "shortIds": [
                "$SHORTID"
            ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
#publickey:$PUBKEY
EOF
}

install_xray() {
UX="$USER"
if [[ "$UX" == "root" ]]; then
	UX="$SUDO_USER"
else
	UX="$USER"
fi
cat >> /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=$UX
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/opt/xray/xray run -config /opt/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
}

update_ctl() {
	conf_f="/etc/sysctl.d/99-reality.conf"
	mkdir -p /etc/sysctl.d
	echo "net.ipv4.icmp_echo_ignore_all = 1" > $conf_f
	sysctl -e -q -p "$conf_f"
}

get_settings() {
	detect_ip
	SSPASS="$(cat /opt/xray/config.json | grep password | cut -d: -f2 | sed -e 's/\"//g' -e 's/,//g' -e 's/ //g')"
	SSPORT="$(cat /opt/xray/config.json | grep port | cut -d: -f2 | sed -e 's/\"//g' -e 's/,//g' -e 's/ //g' -e 's/443//g')"
	METHOD="$(cat /opt/xray/config.json | grep method | cut -d: -f2 | sed -e 's/\"//g' -e 's/,//g' -e 's/ //g')"
	SNI="$(cat /opt/xray/config.json | grep -A 1 'serverNames' | cut -d'[' -f2 | sed -e 's/ //g' -e 's/\"//g' -n -e '2p')"
	UUID="$(cat /opt/xray/config.json | grep '"id"' | cut -d: -f2 | sed -e 's/\"//g' -e 's/,//g' -e 's/ //g')"
	PUBKEY="$(cat /opt/xray/config.json | grep publickey | cut -d: -f2)"
	SHORTID="$(cat /opt/xray/config.json | grep -A 1 'shortIds' | cut -d'[' -f2 | sed -e 's/ //g' -e 's/\"//g' -n -e '2p')"
}

detect_ip() {
	# If system has a single IPv4, it is selected automatically.
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		IP=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else	
		echo "Error: Could not detect this server's IP address." >&2
		echo "Abort. No changes were made." >&2
		exit 1
	fi
}

show_settings() {
	echo "Here are setup settings for client"
	echo "~~SHADOWSOCKS~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	echo "Server: $IP"
	echo "Port: $SSPORT"
	echo "Method: $METHOD"
	echo "Password: $SSPASS"
	echo "~~REALITY~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	echo "Server: $IP"
	echo "Port: 443"
	echo "UUID (user login): $UUID"
	echo "Flow: xtls-rprx-vision"
	echo "Package encoding: xudp"
	echo "Transport protocol: tcp"
	echo "Transport encoding: tls"
	echo "SNI: $SNI"
	echo "ALPN: h2"
	echo "uTLS fingerprint: firefox"
	echo "Reality Pbk (Public key): $PUBKEY"
	echo "Reality Sid (Short ID): $SHORTID"
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
}

reality_setup() {

	export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/xray"

	if [ "$(id -u)" != 0 ]; then
        	exitalert "This installer must be run as root. Try 'sudo bash $0'"
	fi

	# Detect Debian users running the script with "sh" instead of bash
	if readlink /proc/$$/exe | grep -q "dash"; then
		exitalert 'This installer needs to be run with "bash", not "sh".'
	fi

	###############################################################################
	if [[ ! -e /etc/systemd/system/xray.service || ! -e /opt/xray/xray ]]; then
	###############################################################################
		show_intro		
		install_wget
		check_architecture
		checkVirt

		LATEST_RELEASE="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep tag_name | cut -d: -f2 | sed -e 's/\"//g' -e 's/ //g' -e 's/,//g')"
		#Don't know why it's https in some cases - check&correct
		while [ "$LATEST_RELEASE" == "https" ]; do
			LATEST_RELEASE="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep tag_name | cut -d: -f2 | sed -e 's/\"//g' -e 's/ //g' -e 's/,//g')"
		done
		echo "Found version: $LATEST_RELEASE"
		if [[ "$LATEST_RELEASE" = "v1.7.5" ]]; then
			echo "$LATEST_RELEASE is not compatible to Reality, changing to v1.8.3 pre-release"
			LATEST_RELEASE="v1.8.3"
		fi

		if [ -e $REL_NAME ]; then
			echo "File $REL_NAME already exists, skipping download..."
		else
			echo "Getting XRay release..."			
			wget https://github.com/XTLS/Xray-core/releases/download/$LATEST_RELEASE/$REL_NAME
		fi

		if [[ -e $REL_NAME  ]]; then
			mkdir /opt/xray >/dev/null 2>&1
			unzip -o $REL_NAME -d /opt/xray >/dev/null
			chmod +x /opt/xray/xray
		
			gen_settings
			install_xray
			make_config
			update_ctl

			systemctl enable xray
			systemctl start xray
			systemctl status xray
			echo
			echo "Finished!"
			echo
			detect_ip
			show_settings
		else
			exitalert "Installation file not found!"
		fi
	else
		show_intro
		echo
		echo "XRay is already installed."
		echo
		echo "Select an option:"
		echo "   1) Show existing settings"
		echo "   2) Show Reality link and QR code to share"
		echo "   3) Show ShadowSocks link and QR code to share"
		echo "   4) Remove XRay"
		echo "   5) Exit"
		read -rp "Option: " option
		until [[ "$option" =~ ^[1-5]$ ]]; do
			echo "$option: invalid selection."
			read -rp "Option: " option
		done
		case "$option" in
		1)
			get_settings
			show_settings
		;;
		2)
			detect_ip
			get_settings
			SETTINGS="vless://$UUID@$IP?security=reality&sni=$SNI&fp=firefox&pbk=$PUBKEY&type=tcp&flow=xtls-rprx-vision&encription=none&sid=$SHORTID&alpn=h2&packetEncoding=xudp#VLESS%20reality%20$IP" 
			echo "Reality link:"
			echo $SETTINGS
			echo $SETTINGS >vless
			echo "Link was saved to file 'vless'"
			detect_qrencode
			qrencode -t ansiutf8 $SETTINGS
		;;
		3)
			detect_ip
			get_settings
			SETTINGS="ss://$METHOD:$SSPASS@$IP:$SSPORT#ss%202022%20$IP"
			echo "ShadowSocks link:"
			echo $SETTINGS
			echo $SETTINGS >ss
			echo "Link was saved to file 'ss'"
			detect_qrencode
			qrencode -t ansiutf8 $SETTINGS
		;;
		4)
			read -rp "Confirm XRay removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -rp "Confirm XRay removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				systemctl disable --now xray
				rm -f /etc/systemd/system/xray.service >/dev/null
				rm -f /opt/xray/config.json >/dev/null
				rm -r /opt/xray
				rm -f /etc/sysctl.d/99-reality.conf
				echo "XRay removed!"
			else
				echo "XRay removal aborted!"
			fi
		;;
		5)
			exit
		;;
		esac
	
	fi
}

reality_setup
