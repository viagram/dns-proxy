#!/usr/bin/env bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

function Check_OS(){
    Text=$(cat /etc/*-release)
    if echo ${Text} | egrep -io "(centos[a-z ]*5|red[a-z ]*hat[a-z ]*5)" >/dev/null 2>&1; then echo centos5
    elif echo ${Text} | egrep -io "(centos[a-z ]*6|red[a-z ]*hat[a-z ]*6)" >/dev/null 2>&1; then echo centos6
    elif echo ${Text} | egrep -io "(centos[a-z ]*7|red[a-z ]*hat[a-z ]*7)" >/dev/null 2>&1; then echo centos7
    elif echo ${Text} | egrep -io "(centos[a-z ]*8|red[a-z ]*hat[a-z ]*8)" >/dev/null 2>&1; then echo centos8
    elif echo ${Text} | egrep -io "(Rocky[a-z ]*8|red[a-z ]*hat[a-z ]*8)" >/dev/null 2>&1; then echo rockylinux8
    elif echo ${Text} | egrep -io "Fedora[a-z ]*[0-9]{1,2}" >/dev/null 2>&1; then echo fedora
    elif echo ${Text} | egrep -io "debian[a-z /]*[0-9]{1,2}" >/dev/null 2>&1; then echo debian
    elif echo ${Text} | egrep -io "ubuntu" >/dev/null 2>&1; then echo ubuntu
   fi
}


function install(){
    zsph="/usr/bin/dnsctl"
    myph="$(dirname $(readlink -f $0))/$(basename $0)"
    [[ ${myph} != ${zsph} ]] && {
        echo -e "\033[32m 安装路径: ${zsph}\033[0m"
        mv -rf ${myph} ${zsph}
        chmod +x ${zsph}
    }
}

##########################################################################################
echo -e "\033[32m 开始工作\033[0m"
install
[[ "$(Check_OS)" == "centos6" || "$(Check_OS)" == "centos7" ]] && upbash=yum
[[ "$(Check_OS)" == "centos8" || "$(Check_OS)" == "fedora" ]] && upbash=dnf
[[ "$(Check_OS)" == "ubuntu" || "$(Check_OS)" == "debian" ]] && upbash=apt-get
! command -v jq >/dev/null 2>&1 && echo -en "\033[32m 安装jq包: \033[0m" && ${upbash} install -y jq >/dev/null 2>&1 && echo -e "\033[32m 成功\033[0m"

if [[ -n ${1} ]]; then
    echo -en "\033[32m 获取 DNS: \033[0m"
    dns=$(curl -skL https://dnsdian.com/api/dns.php -d "dns=${1}")
    [[ -z ${dns} ]] && echo -e "\033[31m 失败.\033[0m" && exit 1
    echo -e "\033[33m ${dns}\033[0m"
else
    echo -e "\033[32m 恢复 DNS: \033[33m8.8.8.8\033[0m"
    echo -e "\033[32m 恢复 DNS: \033[33m1.1.1.1\033[0m"
    dns='8.8.8.8\nnameserver 1.1.1.1'
fi

echo -en "\033[32m 设置 DNS: \033[0m"
[[ ! -d /etc/dhcp/dhclient-enter-hooks.d/ ]] && mkdir -p /etc/dhcp/dhclient-enter-hooks.d/
echo '#!/bin/sh
make_resolv_conf(){
    :
}' > /etc/dhcp/dhclient-enter-hooks.d/nodnsupdate
chmod +x /etc/dhcp/dhclient-enter-hooks.d/nodnsupdate
chattr -i /etc/resolv.conf >/dev/null 2>&1
rm -f /etc/resolv.conf
echo -e "nameserver ${dns}" >/etc/resolv.conf
chattr +i /etc/resolv.conf >/dev/null 2>&1
systemctl restart network >/dev/null 2>&1
systemctl restart networking >/dev/null 2>&1
echo -e "\033[32m 成功.\033[0m"
echo -en "\033[32m 检测状态: \033[0m"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36"
chk=$(curl --user-agent "${UA}" -4 -skL 'https://www.netflix.com/api/ftl/probe?monotonic=true&device=web&iter=0' | jq -r .ctx.ip)
[[ -z ${chk} ]] && chk=$(ping -4 -c1 netflix.com | egrep -i 'ping' | egrep -o '((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | sed -n 1p)
[[ x"${dns}" == x"${chk}" ]] && echo -e "\033[32m 正常.\033[0m" ||echo -e "\033[31m 异常.\033[0m"
