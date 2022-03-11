#!/bin/bash
# Description: Linux lockdown script
# Authors: TNAR5, colonket
# Version: 1.2
# Competitions:
#	- Hivestorm 2020, 2021 
#	- Southwest CCDC Regionals 2022

CURRENT_USER=$(whoami)

# Text Colors
HEADER='\e[1m'
RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
PURPLE='\033[1;35m'

# Operators
function notify()
{
	echo -e "$YELLOW[!]$NC $1"
}

function error()
{
	echo -e "$RED[-]$NC $1"
}

function success()
{
	echo -e "$GREEN[+]$NC $1"
}

function header()
{
	echo -e "$HEADER$1$NC"
}

function heart()
{
	echo -e "$PURPLE[<3]$NC $1"
}

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

echo ""
header "Linux Lockdown Script"
echo "Authors.......: TNAR5, Colonket"
echo "Version.......: 1.1"
echo "OS............: $(uname -o)"
echo "Executing User: $CURRENT_USER"

printf "\n\n"

read -p "[?] Have you read the README and the Forensics Questions? [y/N]" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]];then
	heart "Thank you for reading the info!" 
else
	error "Please read the files on the desktop to make sure that the script is not messing with anything essential."
	exit 1
fi

function choose_editor()
{
	header "\nChoose Text Editor"
	read -p "[?] Do you want to choose your text editor? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		update-alternatives --config editor
	fi
}

# Offline - Modify config
function ssh_lockdown()
{
	header "\nSSH Lockdown"
	if dpkg --get-selections | grep -q "^openssh-server[[:space:]]*install$" >/dev/null;then
		success "SSH is installed switching to secure config."
		cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
		printf "Port 22\nPermitRootLogin no\nListenAddress 0.0.0.0\nMaxAuthTries 3\nMaxSessions 1\nPubkeyAuthentication yes\nPermitEmptyPasswords no\nUsePAM yes\nPrintMotd yes\nAcceptEnv LANG LC_*\nSubsystem\tsftp\t/usr/lib/openssh/sftp-server" > /etc/ssh/sshd_config
	else
		error "SSH is not installed."
	fi
}

# Offline - Modify kernel
function kernel_lockdown()
{
	header "\nKernel Lockdown"
	success "Enabling secure Kernel options."
	cp /etc/sysctl.conf /etc/sysctl.conf.bak
	printf "net.ipv4.conf.default.rp_filter=1\nnet.ipv4.conf.all.rp_filter=1\nnet.ipv4.tcp_syncookies=1\nnet.ipv4.ip_forward=0\nnet.ipv4.conf.all.accept_redirects=0\nnet.ipv6.conf.all.accept_redirects=0\nnet.ipv4.conf.all.send_redirects=0\nnet.ipv4.conf.all.accept_source_route=0\nnet.ipv6.conf.all.accept_source_route=0\nnet.ipv4.conf.all.log_martians=1\nnet.ipv4.icmp_echo_ignore_broadcasts=1\nnet.ipv6.conf.all.disable_ipv6=0\nnet.ipv6.conf.default.disable_ipv6=0\nnet.ipv6.conf.lo.disable_ipv6=1\nkernel.core_uses_pid=1\nkernel.sysrq=0" > /etc/sysctl.conf
	sysctl -w kernel.randomize_va_space=2 >/dev/null;sysctl -w net.ipv4.conf.default.rp_filter=1>/dev/null;sysctl -w net.ipv4.conf.all.rp_filter=1>/dev/null;sysctl -w net.ipv4.tcp_syncookies=1>/dev/null;sysctl -w net.ipv4.ip_forward=0>/dev/null;sysctl -w net.ipv4.conf.all.accept_redirects=0>/dev/null;sysctl -w net.ipv6.conf.all.accept_redirects=0>/dev/null;sysctl -w net.ipv4.conf.all.send_redirects=0>/dev/null;sysctl -w net.ipv4.conf.all.accept_source_route=0>/dev/null;sysctl -w net.ipv6.conf.all.accept_source_route=0>/dev/null;sysctl -w net.ipv4.conf.all.log_martians=1>/dev/null;
}

function lockout_policy()
{
	echo "c"
}

# Offline - Modify users
function user_lockdown()
{
	header "\nUser Lockdown"
	read -p "[?] Do you want to lockdown human users? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		notify "Starting interactive user lockdown."
		success "Backup user list $HOME/users.txt"
		users=($(awk -F ':' '$3>=1000 {print $i}' /etc/passwd | cut -d':' -f1))
		
		printf "%s\n" "${users[@]}" > $HOME/users.txt
		success "Found "${#users[@]}" human users."
		echo

		password="changeMe!123"

		#read -p "[?] HIVESTORM COMPETITON ONLY Do you want to set every users password to '$password'? [y/N]" -n 1 -r
		#echo
		#if [[ $REPLY =~ ^[Yy]$ ]]
		#then
		#	for u in "${users[@]}"
		#	do
		#		# passwd asks to enter new password twice
		#		echo -e "$password\n$password" | passwd $u
		#		success "Changed user $u's password to $password"
		#		echo
		#	done
		#fi

		for u in "${users[@]}"
		do
			read -p "[?] Modify user $u ? [y/N]" -n 1 -r
			echo
			if [[ $REPLY =~ ^[Yy]$ ]]
			then
				header "$u"
				read -p "[?] Remove user $u ? [y/N] " -n 1 -r
				echo
				if [[ $REPLY =~ ^[Yy]$ ]]
				then
				 	if [[ $u == $SUDO_USER ]]
					then
					 	error "You are $u, cannot remove yourself!"
					else
						userdel $u
						groupdel $u
						success "$u has been removed."
					fi
				else
					read -p "[?] Change $u's password? [y/N]" -n 1 -r
					echo
					if [[ $REPLY =~ ^[Yy]$ ]]
					then
						passwd $u
					else
						success "Did not change $u's password"
					fi
					
					read -p "[?] Lock $u's account to prevent login? [y/N]" -n 1 -r
					echo
					if [[ $REPLY =~ ^[Yy]$ ]]
					then
						passwd -l $u
					else
						success "Did not lock $u's account"
					fi


					read -p "[?] Should $u be an administrator? [y/N]" -n 1 -r
					echo
					if [[ $REPLY =~ ^[Yy]$ ]]
					then
						groups $u | grep "sudo" > /dev/null
						if [ $? -eq 0 ];
						then
							success "User $u is already an Administrator - no change."
						else
							usermod -aG sudo $u
							success "User $u was added to the sudo group."
						fi
					else
						groups $u | grep "sudo" > /dev/null
						if [ $? -eq 0 ];
						then
							notify "User $u was an Administrator."
							deluser $u sudo
							success "Removed $u from sudo group."
						else
							success "User $u is already not an Administrator - no change."
						fi
					fi
				fi
			fi
		done
	fi
	read -p "[?] Do you want to check /etc/sudoers? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		read -p "[?] Press any key to check sudoers." -n 1 -r
		echo ""
		success "Launching visudo."
		visudo
	fi
	printf "\n"


}

# Offline - Modify Configs
function check_configs()
{
	header "\nCheck Configs"
	read -p "[?] Would you like to check config files? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		echo "nospoof on" >> /etc/hosts
		sudoedit /etc/hosts
		sudoedit /etc/crontab
		echo "The following users have active crontabs:"
		ls /var/spool/cron/crontabs
		echo ""
		echo "[!] Make sure to set lightdm guest to false and if asked to, disable auto-login. (allow-guest=False)"
		read -p "[?] Press any key to check /etc/lightdm/lightdm.conf" -n 1 -r
		echo ""
		echo "allow-guest=False" >> /etc/lightdm/lightdm.conf
		sudoedit /etc/lightdm/lightdm.conf
		printf "\n"
		success "Finish config editing."
	fi

}

# Offline - Remove packages
function check_bad_programs()
{
	header  "\nChecking for 'bad' programs."

	declare -a bad=(
		"nmap"
		"john"
		"rainbowcrack"
		"ophcrack"
		"nc"
		"netcat"
		"hashcat"
		"telnet"
		"wireshark"
	)

	declare -a possibly_bad=(
		"samba"
		"bind9"
		"vsftpd"
		"apache2"
		"nginx"
		"telnet"
	)

	# Remove bad programs
	for b in "${bad[@]}"
	do
		if dpkg --get-selections | grep -q "^$b[[:space:]]*install$" >/dev/null;then
			notify "$b is installed, removing."
			apt-get purge -y $b
		fi
	done
	apt-get purge netcat*   # Removes any alternative netcat packages

	# Notify of any bad programs that may be a required service
	for pb in "${possibly_bad[@]}"
	do
		if dpkg --get-selections | grep -q "^$pb[[:space:]]*install$" >/dev/null;then
			notify "$pb is installed, remove/disable if not a required service."
		fi
	done
}

function check_services()
{
	header "\nServices"
	read -p "[?] List enabled services? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		success "Displaying enabled services:"
		service --status-all | grep '+'
	fi
	echo ""

	read -p "[?] List active network connections? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		success "Displaying active network connections with 'lsof -nP -i':"
		lsof -nP -i
	fi
	echo ""
}

# Forensics / Hivestorm
function find_media()
{
	chkdir="/home/"
	dmpfile="$HOME/media_files.txt"
	sarray=()
	header "Checking for media files in ${chkdir}"
	success "Checking txt files."
	echo "">$dmpfile
	declare -a extensions=(
		"txt"
		"mp4"
		"mp3"
		"ogg"
		"wav"
		"png"
		"jpg"
		"jpeg"
		"gif"
		"mov"
		"m4a"
		"m4b"
	)
	for i in "${extensions[@]}"
	do
		sarray=($(find $chkdir -type f -name "*.$i" | tee -a $dmpfile))
		echo "Found ${#sarray[@]}"
		success "Checking $i files."
	done
	printf "\n"
	notify "Saving file paths to ${dmpfile}"

}

# Online - Updating packages
function ask_to_install_updates()
{
	header "\nInstalling Updates"
	read -p "[?] Would you like to install updates? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		apt-get update
		apt-get upgrade -y
		apt-get dist-upgrade -y
	fi
}

# Online - Installing a package
function enable_av()
{
	header "\nAnti-Virus lockdown"
	command -v clamscan >/dev/null
	if [ $? -eq 0 ];then
		success "ClamAV found."
		freshclam
		success "Updated definitions."
	else
		error "ClamAV not installed."
		read -p "[?] Would you like to install ClamAV and chkrootkit? [y/N] " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
			apt-get install -y clamav chkrootkit
			ufw enable > /dev/null
			freshclam
			success "ClamAV is now enabled and updated."
		fi
	fi
}

# Online - Installing ufw
function enable_ufw()
{
	header "\nFirewall Lockdown"
	command -v ufw >/dev/null
	if [ $? -eq 0 ];then
		success "UFW found enabling firewall."
		ufw enable > /dev/null
	else
		error "UFW not installed."
		read -p "[?] Would you like to install ufw? [y/N] " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
			apt-get install -y ufw
			ufw enable > /dev/null
			success "UFW is now enabled."
		fi
	fi
}



# Modes - Different Ways to Run this Script
function mode_default(){
	# sudo ./lockdown.sh
	success "RUNNING WITH DEFAULT MODE"
	# User runs script without any arguments

	choose_editor
	ssh_lockdown
	kernel_lockdown
	user_lockdown
	check_configs
	check_bad_programs
	check_services
	enable_ufw
	#enable_av		# Installing clamav isn't neccesary right now 
	ask_to_install_updates
	#find_media 	# Disabled for CCDC
}
function mode_auto(){
	# sudo ./lockdown.sh -a
	success "RUN MODE: AUTOMATIC (just y/n prompts)"

	#choose_editor
	ssh_lockdown
	kernel_lockdown
	#user_lockdown
	#check_configs
	check_bad_programs
	check_services
	enable_ufw
	#enable_av		# Disabled for time
	ask_to_install_updates
	#find_media 	# Disabled for CCDC
}
function mode_autoOffline(){
	# sudo ./lockdown.sh -o
	success "RUN MODE: OFFLINE"

	#choose_editor
	ssh_lockdown
	kernel_lockdown
	#user_lockdown
	#check_configs
	check_bad_programs
	check_services
	#enable_ufw
	#enable_av		# Disabled for time
	#ask_to_install_updates
	#find_media 	# Disabled for CCDC

}
function mode_userLockdown(){
	# sudo ./lockdown.sh -u
	success "RUN MODE: USER LOCKDOWN"

	#choose_editor
	#ssh_lockdown
	#kernel_lockdown
	user_lockdown
	#check_configs
	#check_bad_programs
	#check_services
	#enable_ufw
	#enable_av		# Disabled for time
	#ask_to_install_updates
	#find_media 	# Disabled for CCDC
}

case $1 in
	"-a") 	mode_auto;;
	"-o") 	mode_autoOffline;;
	"-u") 	mode_userLockdown;;
	"*")	mode_default;;
esac


header "\nThings left to do:"
notify "Secure Root - Change root password and disable if allowed!"
notify "Update kernel"
notify "Update the APT Package Manager Source (Settings > Software and Updates > Download From)"
notify "Pam cracklib password requirements/logging"
notify "Discover rootkits/backdoors"
notify "Check file permissions"
notify "Check init scripts"
notify "Web browser updates and security"
notify "ADD USERS NOT IN THE LIST"
notify "Win - Good Luck! :D"

success "Script finished exiting."
exit 0

