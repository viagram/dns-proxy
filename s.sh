#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

function printnew(){
	typeset -l CHK
	WENZHI=''
	COLOUR=''
	HUANHANG=0
	for PARSTR in "${@}"; do
		CHK="${PARSTR}"
		if echo "${CHK}" | egrep -io "^\-[[:graph:]]*" >/dev/null 2>&1; then
			case "${CHK}" in
				-black) COLOUR="\033[30m";;
				-red) COLOUR="\033[31m";;
				-green) COLOUR="\033[32m";;
				-yellow) COLOUR="\033[33m";;
				-blue) COLOUR="\033[34m";;
				-purple) COLOUR="\033[35m";;
				-cyan) COLOUR="\033[36m";;
				-white) COLOUR="\033[37m";;
				-a) HUANHANG=1;;
				*) COLOUR="\033[37m";;
			esac
		else
			WENZHI+="${PARSTR}"
		fi
	done
	if [[ ${HUANHANG} -eq 1 ]]; then
		printf "${COLOUR}%b%s\033[0m" "${WENZHI}"
	else
		printf "${COLOUR}%b%s\033[0m\n" "${WENZHI}"
	fi
}

[[ $EUID -ne 0 ]] && printnew -red "错误: 请使用root用户来执行脚本!" && exit 1

# Get public IP address
function get_ip(){
	if command -v ip >/dev/null 2>&1; then
		local ip_addr='ip addr'
	elif command -v ifconfig >/dev/null 2>&1; then
		local ip_addr='ifconfig'
	fi
	local wanip=$(${ip_addr} | egrep -o '((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
	if [[ -z ${wanip} ]]; then
		local wanip=$(curl -skL --connect-timeout 8 -m 12 https://dnsdian.com/?format=ip | egrep -io '((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])')
		if [[ -z ${wanip} ]]; then
			local wanip=$(curl -skL --connect-timeout 8 -m 12 https://ip.cn | egrep -io '((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])')
		fi
	fi
	[ ! -z ${wanip} ] && echo ${wanip} || echo
}

function Check_OS(){
	Text=$(cat /etc/*-release)
	if echo ${Text} | egrep -io "(centos[a-z ]*5|red[a-z ]*hat[a-z ]*5)" >/dev/null 2>&1; then echo centos5
	elif echo ${Text} | egrep -io "(centos[a-z ]*6|red[a-z ]*hat[a-z ]*6)" >/dev/null 2>&1; then echo centos6
	elif echo ${Text} | egrep -io "(centos[a-z ]*7|red[a-z ]*hat[a-z ]*7)" >/dev/null 2>&1; then echo centos7
	elif echo ${Text} | egrep -io "(centos[a-z ]*8|red[a-z ]*hat[a-z ]*8)" >/dev/null 2>&1; then echo centos8
	elif echo ${Text} | egrep -io "Fedora[a-z ]*[0-9]{1,2}" >/dev/null 2>&1; then echo fedora
	elif echo ${Text} | egrep -io "debian[a-z /]*[0-9]{1,2}" >/dev/null 2>&1; then echo debian
	elif echo ${Text} | egrep -io "ubuntu" >/dev/null 2>&1; then echo ubuntu
	fi
}

# Disable selinux
function disable_selinux(){
	if [[ -s /etc/selinux/config ]] && egrep -io 'SELINUX=enforcing' /etc/selinux/config; then
		sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
		setenforce 0
	fi
}

function doNet(){
	# 以前优化设置来自于网络, 具体用处嘛~~~我也不知道^_^.
	sysctl=/etc/sysctl.conf
	limits=/etc/security/limits.conf
	sed -i '/* soft nofile/d' $limits;echo '* soft nofile 1024000'>>$limits
	sed -i '/* hard nofile/d' $limits;echo '* hard nofile 1024000'>>$limits
	echo "ulimit -SHn 1024000">>/etc/profile
	ulimit -n 1024000
	sed -i '/net.ipv4.ip_forward/d' $sysctl;echo 'net.ipv4.ip_forward=1'>>$sysctl
	sed -i '/net.ipv4.conf.default.rp_filter/d' $sysctl;echo 'net.ipv4.conf.default.rp_filter=1'>>$sysctl
	sed -i '/net.ipv4.conf.default.accept_source_route/d' $sysctl;echo 'net.ipv4.conf.default.accept_source_route=0'>>$sysctl
	sed -i '/kernel.sysrq/d' $sysctl;echo 'kernel.sysrq=0'>>$sysctl
	sed -i '/kernel.core_uses_pid/d' $sysctl;echo 'kernel.core_uses_pid=1'>>$sysctl
	sed -i '/kernel.msgmnb/d' $sysctl;echo 'kernel.msgmnb=65536'>>$sysctl
	sed -i '/kernel.msgmax/d' $sysctl;echo 'kernel.msgmax=65536'>>$sysctl
	sed -i '/kernel.shmmax/d' $sysctl;echo 'kernel.shmmax=68719476736'>>$sysctl
	sed -i '/kernel.shmall/d' $sysctl;echo 'kernel.shmall=4294967296'>>$sysctl
	sed -i '/net.ipv4.tcp_timestamps/d' $sysctl;echo 'net.ipv4.tcp_timestamps=0'>>$sysctl
	sed -i '/net.ipv4.tcp_retrans_collapse/d' $sysctl;echo 'net.ipv4.tcp_retrans_collapse=0'>>$sysctl
	sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' $sysctl;echo 'net.ipv4.icmp_echo_ignore_broadcasts=1'>>$sysctl
	sed -i '/net.ipv4.conf.all.rp_filter/d' $sysctl;echo 'net.ipv4.conf.all.rp_filter=1'>>$sysctl
	sed -i '/fs.inotify.max_user_watches/d' $sysctl;echo 'fs.inotify.max_user_watches=65536'>>$sysctl
	sed -i '/net.ipv4.conf.default.promote_secondaries/d' $sysctl;echo 'net.ipv4.conf.default.promote_secondaries=1'>>$sysctl
	sed -i '/net.ipv4.conf.all.promote_secondaries/d' $sysctl;echo 'net.ipv4.conf.all.promote_secondaries=1'>>$sysctl
	sed -i '/kernel.hung_task_timeout_secs=0/d' $sysctl;echo 'kernel.hung_task_timeout_secs=0'>>$sysctl
	sed -i '/fs.file-max/d' $sysctl;echo 'fs.file-max=1024000'>>$sysctl
	sed -i '/net.core.wmem_max/d' $sysctl;echo 'net.core.wmem_max=67108864'>>$sysctl
	sed -i '/net.core.netdev_max_backlog/d' $sysctl;echo 'net.core.netdev_max_backlog=32768'>>$sysctl
	sed -i '/net.core.somaxconn/d' $sysctl;echo 'net.core.somaxconn=32768'>>$sysctl
	sed -i '/net.ipv4.tcp_syncookies/d' $sysctl;echo 'net.ipv4.tcp_syncookies=1'>>$sysctl
	sed -i '/net.ipv4.tcp_tw_reuse/d' $sysctl;echo 'net.ipv4.tcp_tw_reuse=1'>>$sysctl
	sed -i '/net.ipv4.tcp_fin_timeout/d' $sysctl;echo 'net.ipv4.tcp_fin_timeout=30'>>$sysctl
	sed -i '/net.ipv4.tcp_keepalive_time/d' $sysctl;echo 'net.ipv4.tcp_keepalive_time=1200'>>$sysctl
	sed -i '/net.ipv4.ip_local_port_range/d' $sysctl;echo 'net.ipv4.ip_local_port_range=1024 65500'>>$sysctl
	sed -i '/net.ipv4.tcp_max_syn_backlog/d' $sysctl;echo 'net.ipv4.tcp_max_syn_backlog=8192'>>$sysctl
	sed -i '/net.ipv4.tcp_max_tw_buckets/d' $sysctl;echo 'net.ipv4.tcp_max_tw_buckets=6000'>>$sysctl
	sed -i '/net.ipv4.tcp_fastopen/d' $sysctl;echo 'net.ipv4.tcp_fastopen=3'>>$sysctl
	sed -i '/net.ipv4.tcp_rmem/d' $sysctl;echo 'net.ipv4.tcp_rmem=4096'>>$sysctl
	sed -i '/net.ipv4.tcp_wmem/d' $sysctl;echo 'net.ipv4.tcp_wmem=4096'>>$sysctl
	sed -i '/net.ipv4.tcp_mtu_probing/d' $sysctl;echo 'net.ipv4.tcp_mtu_probing=1'>>$sysctl
	sysctl -p
	sleep 1
}

function downfile(){
	local downurl=${1}
	local filename=${2}
	[[ -f ${filename} ]] && rm -rf ${filename}
	printnew -green "正在下载: ${downurl}"
	if ! wget --no-check-certificate -q -t3 -T60 -O ${filename} -c ${downurl}; then
		printnew -red "下载失败."
		exit 1
	fi
}

function clear_tmp(){
	cd ${cur_dir}/..
	rm -rf ${cur_dir}
}

###################################################
echo ${1} | egrep -io '^(update|up)$' >/dev/null 2>&1 && update=true || update=false
if ${update}; then
	printnew -green -a "更新 dnsmasq 和 sniproxy"
else
	printnew -green -a "检测端口占用"
	for aport in 82 443 53; do
		netstat -a -n -p | grep LISTEN | grep -P "\d+\.\d+\.\d+\.\d+:${aport}\s+" > /dev/null && printnew "\r\c" && printnew -red "端口 ${aport} 被占用." && exit 1
	done
fi

fix_url='https://raw.githubusercontent.com/viagram/dns-proxy/master'
cur_dir=$(pwd)/Netflix_dns_dir_tmp/
[[ -d ${cur_dir} ]] && rm -rf ${cur_dir}
mkdir -p ${cur_dir}
cd ${cur_dir}

printnew "\r\c"
printnew -green "安装依赖组件包                                       "
if [[ "$(Check_OS)" == "centos7" || "$(Check_OS)" == "centos8" ]]; then
	[[ ! -f /etc/yum.repos.d/epel.repo ]] && yum install -y epel-release
	! command -v yum-config-manager >/dev/null 2>&1 && yum install -y yum-utils
	[[ x"$(yum-config-manager epel | grep -w enabled | awk '{print $3}')" != x"True" ]] && yum-config-manager --enable epel
	yum groupinstall -y "Development Tools"
	[[ -f /etc/yum.repos.d/elrepo.repo ]] && yum --enablerepo=elrepo-kernel -y install kernel-ml-devel kernel-ml-headers || yum install -y kernel-devel kernel-headers
	yum install -y jq git curl tar wget net-tools dnsmasq autoconf automake make gettext-devel libev-devel pcre-devel perl pkgconfig rpm-build udns-devel openssl-devel gcc bind-utils
elif [[ "$(Check_OS)" == "ubuntu" || "$(Check_OS)" == "debian" ]]; then
	apt-get -y install curl wget git tar dnsmasq net-tools make jq build-essential autotools-dev cdbs debhelper dh-autoreconf dpkg-dev gettext libev-dev libpcre3-dev libudns-dev pkg-config fakeroot devscripts gcc dnsutils
fi

: <<'dnsmasq_tgz'
printnew -green "获取最新dnsmasq版本信息..."
dnsmasq_home="http://www.thekelleys.org.uk/dnsmasq/"
dnsmasq_file=$(curl -skL ${dnsmasq_home} | egrep -io 'dnsmasq-[0-9]{1,2}.([0-9]{1,2}|[0-9a-zA-Z]{1,5}|[0-9]{1,2}.[0-9]{1,2}).tar.gz' | sort -ruV | sed -n 1p)
dnsmasq_url="${dnsmasq_home}${dnsmasq_file}"
dnsmasq_name=$(basename ${dnsmasq_url})
dnsmasq_dir=$(echo ${dnsmasq_name} | sed  's/.tar.gz//g')
downfile ${dnsmasq_url} ${dnsmasq_name}
printnew -green "解压${dnsmasq_name}"
if ! tar --overwrite -zxf ${dnsmasq_name}; then
	printnew -reg "解压${dnsmasq_name}."
	clear_tmp
	exit 1
fi
cd ${dnsmasq_dir}
dnsmasq_tgz

disable_selinux
doNet >/dev/null 2>&1

dnsmasq_dir=dnsmasq
printnew -green "获取最新dnsmasq源码"
[[ -e ${dnsmasq_dir} ]] && rm -rf ${dnsmasq_dir}
#  http://thekelleys.org.uk/git/dnsmasq.git
if ! git clone git://thekelleys.org.uk/dnsmasq.git ${dnsmasq_dir}; then
	printnew -red "获取失败."
	clear_tmp
	exit 1
fi
cd ${dnsmasq_dir}

printnew -green "编译${dnsmasq_dir}"
if make; then
	${update} && systemctl stop dnsmasq >/dev/null 2>&1
	\cp -f ${cur_dir}/${dnsmasq_dir}/src/dnsmasq /usr/sbin/dnsmasq
	chmod +x /usr/sbin/dnsmasq
	printnew -green "编译${dnsmasq_dir}成功."
	${update} && systemctl start dnsmasq >/dev/null 2>&1
else
	printnew -red "编译${dnsmasq_dir}失败."
	clear_tmp
	exit 1
fi

cd ${cur_dir}
[[ -e sniproxy ]] && rm -rf sniproxy
printnew -green "克隆sniproxy源码"
git clone https://github.com/dlundquist/sniproxy.git
cd sniproxy
if [[ "$(Check_OS)" == "centos7" || "$(Check_OS)" == "centos8" ]]; then
	rpm -qa | grep sniproxy >/dev/null 2>&1 && rpm -e sniproxy
	printnew -green "编译sniproxy的rpm包"
	sed -i '/debchange/d' setver.sh
	./autogen.sh && ./configure && make dist
	sed -i "s/\%configure CFLAGS\=\"-I\/usr\/include\/libev\"/\%configure CFLAGS\=\"-fPIC -I\/usr\/include\/libev\"/" redhat/sniproxy.spec
	rpmbuild --define "_sourcedir `pwd`" --define "_topdir ${cur_dir}/sniproxy/rpmbuild" --define "debug_package %{nil}" -ba redhat/sniproxy.spec
	yum -y install ${cur_dir}/sniproxy/rpmbuild/RPMS/x86_64/sniproxy-*.rpm
	\cp -f redhat/sniproxy.init /etc/init.d/sniproxy && chmod +x /etc/init.d/sniproxy
elif [[ "$(Check_OS)" == "ubuntu" || "$(Check_OS)" == "debian" ]]; then
	dpkg -s sniproxy >/dev/null 2>&1 && dpkg -r sniproxy
	printnew -green "编译sniproxy的deb包"
	./autogen.sh && dpkg-buildpackage
	dpkg -i --no-debsig ../sniproxy_*.deb
	\cp -f debian/init.d /etc/init.d/sniproxy && chmod +x /etc/init.d/sniproxy
	downfile ${fix_url}/sniproxy.default /etc/default/sniproxy
fi
[[ ! -f /usr/sbin/sniproxy ]] && printnew -red "安装Sniproxy出现问题." && exit 1
cd ${cur_dir}

downfile ${fix_url}/sniproxy.conf /etc/sniproxy.conf
downfile ${fix_url}/proxy-domains.txt ${cur_dir}/proxy-domains.txt
\cp -f ${cur_dir}/proxy-domains.txt ${cur_dir}/out-proxy-domains.txt
sed -i -e 's/\./\\\./g' -e 's/^/    \.\*/' -e 's/$/\$ \*/' ${cur_dir}/out-proxy-domains.txt
sed -i "/table {/r ${cur_dir}/out-proxy-domains.txt" /etc/sniproxy.conf
[[ ! -e /var/log/sniproxy ]] && mkdir /var/log/sniproxy

downfile ${fix_url}/dnsmasq.conf /etc/dnsmasq.d/custom_netflix.conf

PublicIP=$(get_ip)
for domain in $(cat ${cur_dir}/proxy-domains.txt); do
	printf "address=/${domain}/${PublicIP}\n"\
	| tee -a /etc/dnsmasq.d/custom_netflix.conf > /dev/null 2>&1
done
[ "$(grep -x -E "(conf-dir=/etc/dnsmasq.d|conf-dir=/etc/dnsmasq.d,.bak|conf-dir=/etc/dnsmasq.d/,\*.conf|conf-dir=/etc/dnsmasq.d,.rpmnew,.rpmsave,.rpmorig)" /etc/dnsmasq.conf)" ] || echo -e "\nconf-dir=/etc/dnsmasq.d" >> /etc/dnsmasq.conf

systemctl daemon-reload >/dev/null 2>&1
systemctl enable dnsmasq >/dev/null 2>&1
systemctl restart dnsmasq >/dev/null 2>&1
systemctl enable sniproxy >/dev/null 2>&1
systemctl restart sniproxy >/dev/null 2>&1

clear_tmp
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36"
region=$(curl --user-agent "${UA}" -4 -skL 'https://www.netflix.com/api/ftl/probe?monotonic=true&device=web&iter=0' | jq -r .ctx.region)
printnew
printnew -green "安装成功"
printnew -green -a "所属区域: "
printnew -yellow "${region}"
printnew -green "请执行下面命令修改DNS 即可以观看Netflix节目了。"
printnew -yellow "curl -skL ${fix_url}/c.sh | bash -s ${PublicIP}"
printnew

cat >/bin/dnsip<<'eof'
#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

function helper(){
	echo -e "\033[32m 添加ip:\033[0m"
	echo -e "   \033[33mdnsip add [ip address]\033[0m"
	echo -e "\033[32m 删除ip:\033[0m"
	echo -e "   \033[33mdnsip del [ip address]\033[0m"
	echo -e "\033[32m 查看所有规则:\033[0m"
	echo -e "   \033[33mdnsip all/list\033[0m"
}

if ! firewall-cmd --state > /dev/null 2>&1; then
	echo -e "\033[32m 初始化防火墙 \033[0m"
	systemctl start firewalld > /dev/null 2>&1
	systemctl enable firewalld > /dev/null 2>&1
	firewall-cmd --zone=public --add-port=1-52/tcp  --permanent > /dev/null 2>&1
	firewall-cmd --zone=public --add-port=1-52/udp  --permanent > /dev/null 2>&1
	firewall-cmd --zone=public --add-port=54-79/tcp  --permanent > /dev/null 2>&1
	firewall-cmd --zone=public --add-port=54-79/udp  --permanent > /dev/null 2>&1
	firewall-cmd --zone=public --add-port=81-442/tcp  --permanent > /dev/null 2>&1
	firewall-cmd --zone=public --add-port=81-442/udp  --permanent > /dev/null 2>&1
	firewall-cmd --zone=public --add-port=444-65535/tcp  --permanent > /dev/null 2>&1
	firewall-cmd --zone=public --add-port=444-65535/udp  --permanent > /dev/null 2>&1
	#ssh_port=$(cat /etc/ssh/sshd_config | egrep -i '(#|)Port[[:space:]]*[0-9]*$' | egrep -io '[0-9]*')
	#firewall-cmd --zone=public --add-port=${ssh_port}/tcp --permanent > /dev/null 2>&1
	#firewall-cmd --zone=public --add-port=${ssh_port}/udp --permanent > /dev/null 2>&1
	firewall-cmd --reload > /dev/null 2>&1
fi

if [[ x${1} == 'xlist' || x${1} == 'xLIST' || x${1} == 'xall' || x${1} == 'xALL' ]]; then
	echo -e "\033[32m 所有规则列表: \033[0m"
	firewall-cmd --list-all
	exit 0
fi

if [[ x${1} == 'xadd' || x${1} == 'xADD' ]]; then
	iplist=$(echo ${@} | egrep -o '((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\.")
	if [[ -n ${iplist} ]]; then
		for ipaddr in ${iplist}; do
			if ! firewall-cmd --list-rich-rules | egrep -io ${ipaddr} > /dev/null 2>&1; then
				echo -e "\033[32m 正在添加 \033[33m${ipaddr} \033[32m的规则 \033[0m"
				firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${ipaddr}/32 port protocol=tcp port=53 accept" > /dev/null 2>&1
				firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${ipaddr}/32 port protocol=udp port=53 accept" > /dev/null 2>&1
				firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${ipaddr}/32 port protocol=tcp port=80 accept" > /dev/null 2>&1
				firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${ipaddr}/32 port protocol=udp port=80 accept" > /dev/null 2>&1
				firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${ipaddr}/32 port protocol=tcp port=443 accept" > /dev/null 2>&1
				firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${ipaddr}/32 port protocol=udp port=443 accept" > /dev/null 2>&1
			fi
		done
			firewall-cmd --reload > /dev/null 2>&1
			#firewall-cmd --list-rich-rules
	else
		echo -e "\033[33m 请输入有效的IPf地址\033[0m"
		helper
	fi
elif [[ x${1} == 'xDEL' || x${1} == 'xdel' ]]; then
	iplist=$(echo ${@} | egrep -o '((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\.")
	if [[ -n ${iplist} ]]; then
		for ipaddr in ${iplist}; do
			if firewall-cmd --list-rich-rules | egrep -io ${ipaddr} > /dev/null 2>&1; then
				echo -e "\033[32m 正在删除 \033[33m${ipaddr} \033[32m的规则 \033[0m"
				firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=${ipaddr}/32 port protocol=tcp port=53 accept" > /dev/null 2>&1
				firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=${ipaddr}/32 port protocol=udp port=53 accept" > /dev/null 2>&1
				firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=${ipaddr}/32 port protocol=tcp port=80 accept" > /dev/null 2>&1
				firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=${ipaddr}/32 port protocol=udp port=80 accept" > /dev/null 2>&1
				firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=${ipaddr}/32 port protocol=tcp port=443 accept" > /dev/null 2>&1
				firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=${ipaddr}/32 port protocol=udp port=443 accept" > /dev/null 2>&1
			fi
		done
			firewall-cmd --reload > /dev/null 2>&1
			#firewall-cmd --list-rich-rules
	else
		echo -e "\033[33m 请输入有效的IPf地址\033[0m"
		helper
	fi
else
	helper
fi
eof
chmod +x /bin/dnsip
dnsip > /dev/null 2>&1
