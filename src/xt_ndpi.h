/* 
 * xt_ndpi.h
 * Copyright (C) 2010-2012 G. Elian Gidoni
 *               2012 Ed Wildgoose
 *               2014 Humberto Jucá <betolj@gmail.com>
 * 
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the PACE technology by ipoque GmbH
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _LINUX_NETFILTER_XT_NDPI_H
#define _LINUX_NETFILTER_XT_NDPI_H 1

#include <linux/netfilter.h>
#include "ndpi_main.h"

#ifndef NDPI_BITMASK_IS_ZERO
#define NDPI_BITMASK_IS_ZERO(a) NDPI_BITMASK_IS_EMPTY(a)
#endif

struct xt_ndpi_mtinfo {
        NDPI_PROTOCOL_BITMASK flags;
};

/* /usr/src/nDPI/src/include/ndpi_protocol_ids.h
 - protocols summ per line: 9, 23, 29, 37, 52, 63, 75, 90, 104, 114, 126, 135, 144, 156, 170, 185, 197, 208, 214
*/
#ifndef NDPI_PROTOCOL_LONG_STRING
#define NDPI_PROTOCOL_LONG_STRING "UNKNOWN" ,"FTP_CONTROL" ,"MAIL_POP" ,"MAIL_SMTP" ,"MAIL_IMAP" ,"DNS" ,"IPP" ,"HTTP" ,"MDNS" ,\
	"NTP" ,"NETBIOS" ,"NFS" ,"SSDP" ,"BGP" ,"SNMP" ,"XDMCP" ,"SMBV1" ,"SYSLOG" ,"DHCP" ,"POSTGRES" ,"MYSQL" ,"MS_OUTLOOK" ,"VK" ,\
	"MAIL_POPS" ,"TAILSCALE" ,"YANDEX" ,"NTOP" ,"COAP" ,"VMWARE" ,"MAIL_SMTPS" ,"DTLS" ,"UBNTAC2" ,"KONTIKI" ,"YANDEX_MAIL" ,"YANDEX_MUSIC" ,\
	"GNUTELLA" ,"EDONKEY" ,"BITTORRENT" ,"SKYPE_TEAMS_CALL" ,"SIGNAL" ,"MEMCACHED" ,"SMBV23" ,"MINING" ,"NEST_LOG_SINK" ,"MODBUS" ,"WHATSAPP_CALL" ,\
	"DATASAVER" ,"XBOX" ,"QQ" ,"TIKTOK" ,"RTSP" ,"MAIL_IMAPS" ,"ICECAST" ,"CPHA" ,"PPSTREAM" ,"ZATTOO" ,"YANDEX_MARKET" ,"YANDEX_DISK" ,"DISCORD" ,\
	"TVUPLAYER" ,"MONGODB" ,"PLURALSIGHT" ,"YANDEX_CLOUD" ,"OCSP" ,"VXLAN" ,"IRC" ,"MERAKI_CLOUD" ,"JABBER" ,"NATS" ,"AMONG_US" ,"YAHOO" ,"DISNEYPLUS" ,\
	"GOOGLE_PLUS" ,"IP_VRRP" ,"STEAM" ,"HALFLIFE2" ,"WORLDOFWARCRAFT" ,"TELNET" ,"STUN" ,"IPSEC" ,"IP_GRE" ,"IP_ICMP" ,"IP_IGMP" ,"IP_EGP" ,"IP_SCTP" ,\
	"IP_OSPF" ,"IP_IP_IN_IP" ,"RTP" ,"RDP" ,"VNC" ,"TUMBLR" ,"TLS" ,"SSH" ,"USENET" ,"MGCP" ,"IAX" ,"TFTP" ,"AFP" ,"YANDEX_METRIKA" ,"YANDEX_DIRECT" ,"SIP" ,\
	"TRUPHONE" ,"IP_ICMPV6" ,"DHCPV6" ,"ARMAGETRON" ,"CROSSFIRE" ,"DOFUS" ,"ADS_ANALYTICS_TRA" ,"ADULT_CONTENT" ,"GUILDWARS" ,"AMAZON_ALEXA" ,"KERBEROS" ,"LDAP" ,\
	"MAPLESTORY" ,"MSSQL_TDS" ,"PPTP" ,"WARCRAFT3" ,"WORLD_OF_KUNG_FU" ,"SLACK" ,"FACEBOOK" ,"TWITTER" ,"DROPBOX" ,"GMAIL" ,"GOOGLE_MAPS" ,"YOUTUBE" ,"SKYPE_TEAMS" ,\
	"GOOGLE" ,"RPC" ,"NETFLOW" ,"SFLOW" ,"HTTP_CONNECT" ,"HTTP_PROXY" ,"CITRIX" ,"NETFLIX" ,"LASTFM" ,"WAZE" ,"YOUTUBE_UPLOAD" ,"HULU" ,"CHECKMK" ,"AJP" ,"APPLE" ,"WEBEX" ,\
	"WHATSAPP" ,"APPLE_ICLOUD" ,"VIBER" ,"APPLE_ITUNES" ,"RADIUS" ,"WINDOWS_UPDATE" ,"TEAMVIEWER" ,"TUENTI" ,"LOTUS_NOTES" ,"SAP" ,"GTP" ,"WSD" ,"LLMNR" ,"TOCA_BOCA" ,\
	"SPOTIFY" ,"MESSENGER" ,"H323" ,"OPENVPN" ,"NOE" ,"CISCOVPN" ,"TEAMSPEAK" ,"TOR" ,"SKINNY" ,"RTCP" ,"RSYNC" ,"ORACLE" ,"CORBA" ,"UBUNTUONE" ,"WHOIS_DAS" ,"SD_RTN" ,\
	"SOCKS" ,"NINTENDO" ,"RTMP" ,"FTP_DATA" ,"WIKIPEDIA" ,"ZMQ" ,"AMAZON" ,"EBAY" ,"CNN" ,"MEGACO" ,"REDIS" ,"PINTEREST" ,"VHUA" ,"TELEGRAM" ,"VEVO" ,"PANDORA" ,\
	"QUIC" ,"ZOOM" ,"EAQ" ,"OOKLA" ,"AMQP" ,"KAKAOTALK" ,"KAKAOTALK_VOICE" ,"TWITCH" ,"DOH_DOT" ,"WECHAT" ,"MPEGTS" ,"SNAPCHAT" ,"SINA" ,"HANGOUT_DUO" ,"IFLIX" ,\
	"GITHUB" ,"BJNP" ,"REDDIT" ,"WIREGUARD" ,"SMPP" ,"DNSCRYPT" ,"TINC" ,"DEEZER" ,"INSTAGRAM" ,"MICROSOFT" ,"STARCRAFT" ,"TEREDO" ,"HOTSPOT_SHIELD" ,"IMO" ,"GOOGLE_DRIVE" ,\
	"OCS" ,"MICROSOFT_365" ,"CLOUDFLARE" ,"MS_ONE_DRIVE" ,"MQTT" ,"RX" ,"APPLESTORE" ,"OPENDNS" ,"GIT" ,"DRDA" ,"PLAYSTORE" ,"SOMEIP" ,"FIX" ,"PLAYSTATION" ,"PASTEBIN" ,\
	"LINKEDIN" ,"SOUNDCLOUD" ,"CSGO" ,"LISP" ,"DIAMETER" ,"APPLE_PUSH" ,"GOOGLE_SERVICES" ,"AMAZON_VIDEO" ,"GOOGLE_DOCS" ,"WHATSAPP_FILES" ,"TARGUS_GETDATA" ,"DNP3" ,"IEC60870" ,\
	"BLOOMBERG" ,"CAPWAP" ,"ZABBIX" ,"S7COMM" ,"MSTEAMS" ,"WEBSOCKET" ,"ANYDESK" ,"SOAP" ,"APPLE_SIRI" ,"SNAPCHAT_CALL" ,"HPVIRTGRP" ,"GENSHIN_IMPACT" ,"ACTIVISION" ,"FORTICLIENT" ,\
	"Z3950" ,"LIKEE" ,"GITLAB" ,"AVAST_SECUREDNS" ,"CASSANDRA" ,"AMAZON_AWS" ,"SALESFORCE" ,"VIMEO" ,"FACEBOOK_VOIP" ,"SIGNAL_VOIP" ,"FUZE" ,"GTP_U" ,"GTP_C" ,"GTP_PRIME" ,"ALIBABA" ,\
	"CRASHLYSTICS" ,"MICROSOFT_AZURE" ,"ICLOUD_PRIVATE_RELAY" ,"ETHERNET_IP" ,"BADOO" ,"ACCUWEATHER" ,"GOOGLE_CLASSROOM" ,"HSRP" ,"CYBERSECURITY" ,"GOOGLE_CLOUD" ,"TENCENT" ,"RAKNET" ,\
	"XIAOMI" ,"EDGECAST" ,"CACHEFLY" ,"SOFTETHER" ,"MPEGDASH" ,"DAZN" ,"GOTO" ,"RSH" ,"1KXUN" ,"IP_PGM" ,"IP_PIM" ,"COLLECTD" ,"TUNNELBEAR" ,"CLOUDFLARE_WARP" ,"I3D" ,"RIOTGAMES" ,\
	"PSIPHON" ,"ULTRASURF" ,"THREEMA" ,"ALICLOUD" ,"AVAST" ,"TIVOCONNECT" ,"KISMET" ,"FASTCGI" ,"FTPS" ,"NATPMP" ,"SYNCTHING" ,"CRYNET" ,"LINE" ,"LINE_CALL" ,"APPLETVPLUS" ,"DIRECTV" ,\
	"HBO" ,"VUDU" ,"SHOWTIME" ,"DAILYMOTION" ,"LIVESTREAM" ,"TENCENTVIDEO" ,"IHEARTRADIO" ,"TIDAL" ,"TUNEIN" ,"SIRIUSXMRADIO" ,"MUNIN" ,"ELASTICSEARCH" ,"TUYA_LP" ,"TPLINK_SHP" ,\
	"SOURCE_ENGINE" ,"BACNET" ,"OICQ" ,"HOTS" ,"FACEBOOK_REEL_STORY" ,"SRTP" ,"GAMBLING" ,"EPICGAMES" ,"GEFORCENOW" ,"NVIDIA" ,"BITCOIN" ,"PROTONVPN" ,"APACHE_THRIFT" ,"ROBLOX", "DPI-CHECK"
	
#endif

#ifndef NDPI_PROTOCOL_SHORT_STRING
#define NDPI_PROTOCOL_SHORT_STRING "unkown" ,"ftp_control" ,"mail_pop" ,"mail_smtp" ,"mail_imap" ,"dns" ,"ipp" ,"http" ,"mdns" ,\
	"ntp" ,"netbios" ,"nfs" ,"ssdp" ,"bgp" ,"snmp" ,"xdmcp" ,"smbv1" ,"syslog" ,"dhcp" ,"postgres" ,"mysql" ,"ms_outlook" ,"vk" ,\
	"mail_pops" ,"tailscale" ,"yandex" ,"ntop" ,"coap" ,"vmware" ,"mail_smtps" ,"dtls" ,"ubntac2" ,"kontiki" ,"yandex_mail" ,"yandex_music" ,\
	"gnutella" ,"edonkey" ,"bittorrent" ,"skype_teams_call" ,"signal" ,"memcached" ,"smbv23" ,"mining" ,"nest_log_sink" ,"modbus" ,"whatsapp_call" ,\
	"datasaver" ,"xbox" ,"qq" ,"tiktok" ,"rtsp" ,"mail_imaps" ,"icecast" ,"cpha" ,"ppstream" ,"zattoo" ,"yandex_market" ,"yandex_disk" ,"discord" ,\
	"tvuplayer" ,"mongodb" ,"pluralsight" ,"yandex_cloud" ,"ocsp" ,"vxlan" ,"irc" ,"meraki_cloud" ,"jabber" ,"nats" ,"among_us" ,"yahoo" ,"disneyplus" ,\
	"google_plus" ,"ip_vrrp" ,"steam" ,"halflife2" ,"worldofwarcraft" ,"telnet" ,"stun" ,"ipsec" ,"ip_gre" ,"ip_icmp" ,"ip_igmp" ,"ip_egp" ,"ip_sctp" ,\
	"ip_ospf" ,"ip_ip_in_ip" ,"rtp" ,"rdp" ,"vnc" ,"tumblr" ,"tls" ,"ssh" ,"usenet" ,"mgcp" ,"iax" ,"tftp" ,"afp" ,"yandex_metrika" ,"yandex_direct" ,"sip" ,\
	"truphone" ,"ip_icmpv6" ,"dhcpv6" ,"armagetron" ,"crossfire" ,"dofus" ,"ads_analytics_tra" ,"adult_content" ,"guildwars" ,"amazon_alexa" ,"kerberos" ,"ldap" ,\
	"maplestory" ,"mssql_tds" ,"pptp" ,"warcraft3" ,"world_of_kung_fu" ,"slack" ,"facebook" ,"twitter" ,"dropbox" ,"gmail" ,"google_maps" ,"youtube" ,"skype_teams" ,\
	"google" ,"rpc" ,"netflow" ,"sflow" ,"http_connect" ,"http_proxy" ,"citrix" ,"netflix" ,"lastfm" ,"waze" ,"youtube_upload" ,"hulu" ,"checkmk" ,"ajp" ,"apple" ,"webex" ,\
	"whatsapp" ,"apple_icloud" ,"viber" ,"apple_itunes" ,"radius" ,"windows_update" ,"teamviewer" ,"tuenti" ,"lotus_notes" ,"sap" ,"gtp" ,"wsd" ,"llmnr" ,"toca_boca" ,\
	"spotify" ,"messenger" ,"h323" ,"openvpn" ,"noe" ,"ciscovpn" ,"teamspeak" ,"tor" ,"skinny" ,"rtcp" ,"rsync" ,"oracle" ,"corba" ,"ubuntuone" ,"whois_das" ,"sd_rtn" ,\
	"socks" ,"nintendo" ,"rtmp" ,"ftp_data" ,"wikipedia" ,"zmq" ,"amazon" ,"ebay" ,"cnn" ,"megaco" ,"redis" ,"pinterest" ,"vhua" ,"telegram" ,"vevo" ,"pandora" ,\
	"quic" ,"zoom" ,"eaq" ,"ookla" ,"amqp" ,"kakaotalk" ,"kakaotalk_voice" ,"twitch" ,"doh_dot" ,"wechat" ,"mpegts" ,"snapchat" ,"sina" ,"hangout_duo" ,"iflix" ,\
	"github" ,"bjnp" ,"reddit" ,"wireguard" ,"smpp" ,"dnscrypt" ,"tinc" ,"deezer" ,"instagram" ,"microsoft" ,"starcraft" ,"teredo" ,"hotspot_shield" ,"imo" ,"google_drive" ,\
	"ocs" ,"microsoft_365" ,"cloudflare" ,"ms_one_drive" ,"mqtt" ,"rx" ,"applestore" ,"opendns" ,"git" ,"drda" ,"playstore" ,"someip" ,"fix" ,"playstation" ,"pastebin" ,\
	"linkedin" ,"soundcloud" ,"csgo" ,"lisp" ,"diameter" ,"apple_push" ,"google_services" ,"amazon_video" ,"google_docs" ,"whatsapp_files" ,"targus_getdata" ,"dnp3" ,"iec60870" ,\
	"bloomberg" ,"capwap" ,"zabbix" ,"s7comm" ,"msteams" ,"websocket" ,"anydesk" ,"soap" ,"apple_siri" ,"snapchat_call" ,"hpvirtgrp" ,"genshin_impact" ,"activision" ,"forticlient" ,\
	"z3950" ,"likee" ,"gitlab" ,"avast_securedns" ,"cassandra" ,"amazon_aws" ,"salesforce" ,"vimeo" ,"facebook_voip" ,"signal_voip" ,"fuze" ,"gtp_u" ,"gtp_c" ,"gtp_prime" ,"alibaba" ,\
	"crashlystics" ,"microsoft_azure" ,"icloud_private_relay" ,"ethernet_ip" ,"badoo" ,"accuweather" ,"google_classroom" ,"hsrp" ,"cybersecurity" ,"google_cloud" ,"tencent" ,"raknet" ,\
	"xiaomi" ,"edgecast" ,"cachefly" ,"softether" ,"mpegdash" ,"dazn" ,"goto" ,"rsh" ,"1kxun" ,"ip_pgm" ,"ip_pim" ,"collectd" ,"tunnelbear" ,"cloudflare_warp" ,"i3d" ,"riotgames" ,\
	"psiphon" ,"ultrasurf" ,"threema" ,"alicloud" ,"avast" ,"tivoconnect" ,"kismet" ,"fastcgi" ,"ftps" ,"natpmp" ,"syncthing" ,"crynet" ,"line" ,"line_call" ,"appletvplus" ,"directv" ,\
	"hbo" ,"vudu" ,"showtime" ,"dailymotion" ,"livestream" ,"tencentvideo" ,"iheartradio" ,"tidal" ,"tunein" ,"siriusxmradio" ,"munin" ,"elasticsearch" ,"tuya_lp" ,"tplink_shp" ,\
	"source_engine" ,"bacnet" ,"oicq" ,"hots" ,"facebook_reel_story" ,"srtp" ,"gambling" ,"epicgames" ,"geforcenow" ,"nvidia" ,"bitcoin" ,"protonvpn" ,"apache_thrift" ,"roblox", "dpi-check"
#endif

#ifndef NDPI_LAST_NFPROTO
#define NDPI_LAST_NFPROTO NDPI_LAST_IMPLEMENTED_PROTOCOL + 1
#endif

#endif /* _LINUX_NETFILTER_XT_NDPI_H */
