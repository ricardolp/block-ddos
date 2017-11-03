#!/usr/bin/perl
# attackers 2, with ipv6 support.
# output connection information from netstat
# 
use strict;

sub run {
        my @netstat = `netstat -pant`;

        my $portcheck = $ARGV[0];
        if ( $portcheck =~ /^[0-9]+$/ ) {
                my %ports;
                my %ips;
                foreach (@netstat) {
                        my ($port, $ip);
                        if ( /^tcp\s+\d\s+\d\s+[0-9\.|0-9A-Za-z\.:]+:${portcheck}\s+([0-9\.|0-9A-Za-z\.:]+):/ ) {
                                chomp;
                                $ip = $1;
                                if ( $ip !~ /^::$/ ) {
                                        $ips{$ip}++;
                                }
                        }
                }
                my $count;
                print "[+] Highest connections on port $portcheck\n";
                foreach my $number ( sort {$ips{$b} <=> $ips{$a}} keys %ips ) {
                        if ( $count <= 10 ) {
                                if ($number) {
                                        print "\t$ips{$number} $number\n";
                                        $count++;
                                }
                        }
                }
                my $total;
                foreach my $key ( keys %ips ) {
                        if ($key) {
                                $total += $ips{$key};
                        }
                }
                print "\n[+] TOTAL: $total\n";
        } else {
                my %ports;
                my %ips;
                foreach (@netstat) {
                        my ($port, $ip);
                        if ( /^tcp\s+\d\s+\d\s+[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:([0-9]+)\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):[0-9]+\s+/ ) {
                                chomp;
                                $port = $1;
                                $ip = $2;
                        } elsif ( /^tcp\s+\d\s+\d\s+[0-9\.|0-9A-Za-z\.:]+:([0-9]+)\s+([0-9\.|0-9A-Za-z\.:]+):[0-9]+\s+/ ) {
                                chomp;
                                $port = $1;
                                $ip = $2;
                        }
                        $ports{$port}++;
 $ips{$ip}++;
                }

                my $count;
                print "[+] Número de Conexões por IP:\n";
                foreach my $number ( sort {$ips{$b} <=> $ips{$a}} keys %ips ) {
                        if ( $count <= 10 ) {
                                if ($number) {

                                        print "\mk $ips{$number} jk $number\n";
                                        $count++;
                                }
                        }
                }



                        }
                }




run();


#!/bin/bash
SHELL=/bin/sh
PATH=/sbin:/usr/sbin:/usr/bin:/bin

rm /home/pega-ddos.txt -f
let linhas=`block-ddos.sh |wc -l`-1
block-ddos.sh|tail -$linhas|sed 's/%//'|sed 's/G//g'|
while read  Tam  mk   jk
do
        echo  $jk $mk
        if [ "$mk" -gt "250" ]   
        then    
       echo " $jk " >> /home/pega-ddos.txt
       sed 's/[^0-9.]//g' /home/pega-ddos.txt > /home/pega-ddos2.txt
MMM="`cat /home/pega-ddos2.txt`  "
netstat -anp  | grep $MMM |  sort | uniq -c | sort -n > /home/result2.txt
RESUL2=" `cat  /home/result2.txt` "
MOSTRA=" `cat /home/pega-ddos2.txt` "
echo -e "  O Ip $MOSTRA Tem $mk  Conexões E Está Conectado Nas  Portas Abaixo \n \n O IP $MOSTRA Foi Bloqueado Por Questões De Segurança \n  \n$RESUL2\n" >> /home/result-ddos.txt
sed  -i 's/\(\w.*\)\.\(\w.*\)\.\(\w.*\)\.\(\w.*\)/\1.\2.\3.0\/24/' /home/pega-ddos2.txt
for ACCT in  `cat /home/pega-ddos2.txt` ; do  iptables -I INPUT -s $ACCT -j DROP  ; done && echo "ips bloqueados com sucesso" && for ACCT in  `cat /home/meus-ips.txt` ; do iptables -D INPUT -s $ACCT -j DROP ; done && echo "ips Desbloqueados com sucesso"
echo -e   |  cat /home/result-ddos.txt  | mail -s " IPS TENTANDO ATACAR COM DDOS " coloque seu email aqui && echo -n > /home/result2.txt && echo -n > /home/result-ddos.txt && echo -n > /home/pega-ddos2.txt
fi
done

script bonus para regras  DDos

echo " Adicionando Regras Iptables para proteção "
###### Protege contra synflood
iptables -A FORWARD -p tcp --syn -m limit --limit 1/s -j ACCEPT
iptables -A FORWARD -p tcp --syn -j DROP
iptables -A INPUT -m state --state INVALID -j DROP
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

###### Protecao contra ICMP Broadcasting
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
###### Prote.. Contra IP Spoofing
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter

###### Protecao diversas contra portscanners, ping of death, ataques DoS, pacotes danificados e etc.
iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -i eth1 -p icmp --icmp-type echo-reply -m limit --limit 1/s -j DROP
iptables -A FORWARD -p tcp -m limit --limit 1/s -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
iptables -A FORWARD --protocol tcp --tcp-flags ALL SYN,ACK -j DROP
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -N VALID_CHECK
iptables -A VALID_CHECK -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -A VALID_CHECK -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -A VALID_CHECK -p tcp --tcp-flags ALL ALL -j DROP
iptables -A VALID_CHECK -p tcp --tcp-flags ALL FIN -j DROP
iptables -A VALID_CHECK -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A VALID_CHECK -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A VALID_CHECK -p tcp --tcp-flags ALL NONE -j DROP

echo ""
echo " Regras Anti DDOS Adicionadas com sucesso"