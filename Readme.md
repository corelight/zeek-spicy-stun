# STUN

Session Traversal Utilities for NAT (STUN)

This is a Zeek protocol analyzer that detects STUN based on Spicy.
You must install [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)
to use this package.

This package will create two logs:

- stun.log - This log has every STUN message.
- stun_nat.log - This log has NAT detections from mapped addresses.

Additional logic has been added to the original logic found here:

- <https://github.com/r-franke/spicy_stun> (BSD License for original code and PCAP here.)
- <https://github.com/r-franke/spicy_stun/issues/1> (Permission to move this work over to spicy-analyzers here.)

More info about STUN:

- <https://datatracker.ietf.org/doc/html/rfc5389>
- <https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml>
- <https://datatracker.ietf.org/doc/html/rfc8489>

## Example

```
$ zeek -Cr stun-ice-testcall.pcap packages

$ head -n 20 stun.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	stun
#open	2021-11-23-19-48-14
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	is_orig	trans_id	method	class	attr_types	attr_vals
#types	time	string	addr	port	addr	port	enum	bool	string	string	string	vector[string]	vector[string]
1377211115.029606	CHhAvVGS1DHFjwGM9	192.168.43.155	60020	74.125.141.127	19302	udp	T	SOpCii5Jfc1z	BINDING	REQUEST	(empty)	(empty)
1377211115.073291	CHhAvVGS1DHFjwGM9	192.168.43.155	60020	74.125.141.127	19302	udp	F	SOpCii5Jfc1z	BINDING	RESPONSE_SUCCESS	MAPPED_ADDRESS	70.199.128.46:4604
1377211125.073812	CHhAvVGS1DHFjwGM9	192.168.43.155	60020	74.125.141.127	19302	udp	T	KIkrzjV7Aan8	BINDING	REQUEST	(empty)	(empty)
1377211125.173831	CHhAvVGS1DHFjwGM9	192.168.43.155	60020	74.125.141.127	19302	udp	T	KIkrzjV7Aan8	BINDING	REQUEST	(empty)	(empty)
1377211125.183611	CHhAvVGS1DHFjwGM9	192.168.43.155	60020	74.125.141.127	19302	udp	F	KIkrzjV7Aan8	BINDING	RESPONSE_SUCCESS	MAPPED_ADDRESS	70.199.128.46:4604
1377211125.210098	CHhAvVGS1DHFjwGM9	192.168.43.155	60020	74.125.141.127	19302	udp	F	KIkrzjV7Aan8	BINDING	RESPONSE_SUCCESS	MAPPED_ADDRESS	70.199.128.46:4604
1377211128.184058	ClEkJM2Vm5giqnMf4h	192.168.43.155	59977	155.212.214.188	23130	udp	T	5YSnBqpVwa9O	BINDING	REQUEST	USERNAME,ICE_CONTROLLING,USE_CANDIDATE,PRIORITY,MESSAGE_INTEGRITY,FINGERPRINT	pLyZHR:GwL3AHBovubLvCqn,\x18\x8b\x10Li{\xf6[,(empty),1845501695,`+\xc7\xfc\x0d\x10c\xaa\xc58\x1c\xcb\x96\xa9s\x08s\x9a\x96\x0c,3512920677
1377211128.184433	C4J4Th3PJpwUYZZ6gc	192.168.43.155	59977	155.212.214.188	23131	udp	T	mPEXdyYbuuQm	BINDING	REQUEST	USERNAME,ICE_CONTROLLING,USE_CANDIDATE,PRIORITY,MESSAGE_INTEGRITY,FINGERPRINT	pLyZHR:GwL3AHBovubLvCqn,\x18\x8b\x10Li{\xf6[,(empty),1845501695,\xed<\x90\xdaN+2\xd5\xd3\xe4\x8b&\xdc\xcd\xddv\xbakc\xe9,3908864856
1377211128.232201	CtPZjS20MLrsMUOJi2	192.168.43.155	60020	155.212.214.188	23130	udp	T	akReei85OatV	BINDING	REQUEST	USERNAME,ICE_CONTROLLING,USE_CANDIDATE,PRIORITY,MESSAGE_INTEGRITY,FINGERPRINT	pLyZHR:GwL3AHBovubLvCqn,\x18\x8b\x10Li{\xf6[,(empty),1845501695,x\xb7\x14\xa9\x9fi\xf9+\xcc;\\\xe0\x0f\xee\x911\x02\xb9\x83a,2846465274
1377211128.232522	CUM0KZ3MLUfNB0cl11	192.168.43.155	60020	155.212.214.188	23131	udp	T	K32zssmQHem3	BINDING	REQUEST	USERNAME,ICE_CONTROLLING,USE_CANDIDATE,PRIORITY,MESSAGE_INTEGRITY,FINGERPRINT	pLyZHR:GwL3AHBovubLvCqn,\x18\x8b\x10Li{\xf6[,(empty),1845501695,\xdb\xae\x92\x92\xba\xb9\xaao\xf7\x95\x98\xde\x2c\xd4\x9a\xdae\xc9\x2c\x08,1949326560
1377211128.280083	ClEkJM2Vm5giqnMf4h	192.168.43.155	59977	155.212.214.188	23130	udp	T	VPPyM5LqxI7r	BINDING	REQUEST	USERNAME,ICE_CONTROLLING,USE_CANDIDATE,PRIORITY,MESSAGE_INTEGRITY,FINGERPRINT	pLyZHR:GwL3AHBovubLvCqn,\x18\x8b\x10Li{\xf6[,(empty),1845501695, \x01\x0e\x94\xea\x90\x07F\xa1\x18\x87\x85\x10{q5\x9c\x92)},2756207482
1377211128.280402	C4J4Th3PJpwUYZZ6gc	192.168.43.155	59977	155.212.214.188	23131	udp	T	jDsAa/4ATcQN	BINDING	REQUEST	USERNAME,ICE_CONTROLLING,USE_CANDIDATE,PRIORITY,MESSAGE_INTEGRITY,FINGERPRINT	pLyZHR:GwL3AHBovubLvCqn,\x18\x8b\x10Li{\xf6[,(empty),1845501695,\xf8\x98-!\x0bG\xa6\x85\xcc \xcf^\x0b`\xe6\xcd::\xae5,3444520530

$ head -n 20 stun_nat.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	stun_nat
#open	2021-11-23-19-48-14
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	is_orig	wan_addrs	wan_ports	lan_addrs
#types	time	string	addr	port	addr	port	enum	bool	vector[addr]	vector[count]	vector[addr]
1377211115.073291	CHhAvVGS1DHFjwGM9	192.168.43.155	60020	74.125.141.127	19302	udp	F	70.199.128.46	4604	192.168.43.155
1377211125.183611	CHhAvVGS1DHFjwGM9	192.168.43.155	60020	74.125.141.127	19302	udp	F	70.199.128.46	4604	192.168.43.155
1377211125.210098	CHhAvVGS1DHFjwGM9	192.168.43.155	60020	74.125.141.127	19302	udp	F	70.199.128.46	4604	192.168.43.155
1377211128.309676	ClEkJM2Vm5giqnMf4h	192.168.43.155	59977	155.212.214.188	23130	udp	F	70.199.128.46	4587	192.168.43.155
1377211128.309677	C4J4Th3PJpwUYZZ6gc	192.168.43.155	59977	155.212.214.188	23131	udp	F	70.199.128.46	4587	192.168.43.155
1377211128.358745	CUM0KZ3MLUfNB0cl11	192.168.43.155	60020	155.212.214.188	23131	udp	F	70.199.128.46	4604	192.168.43.155
1377211128.359514	CtPZjS20MLrsMUOJi2	192.168.43.155	60020	155.212.214.188	23130	udp	F	70.199.128.46	4604	192.168.43.155
1377211128.394673	ClEkJM2Vm5giqnMf4h	192.168.43.155	59977	155.212.214.188	23130	udp	F	70.199.128.46	4587	192.168.43.155
1377211128.405706	C4J4Th3PJpwUYZZ6gc	192.168.43.155	59977	155.212.214.188	23131	udp	F	70.199.128.46	4587	192.168.43.155
1377211128.458800	C4J4Th3PJpwUYZZ6gc	192.168.43.155	59977	155.212.214.188	23131	udp	F	70.199.128.46	4587	192.168.43.155
1377211128.459477	ClEkJM2Vm5giqnMf4h	192.168.43.155	59977	155.212.214.188	23130	udp	F	70.199.128.46	4587	192.168.43.155
1377211128.940537	ClEkJM2Vm5giqnMf4h	192.168.43.155	59977	155.212.214.188	23130	udp	F	70.199.128.46	4587	192.168.43.155

$ cat conn.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2021-11-23-19-48-14
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
1377211115.029606	CHhAvVGS1DHFjwGM9	192.168.43.155	60020	74.125.141.127	19302	udp	spicy_stun	20.187972	80	128	SF	-	-	0	Dd	4	192	4	240	-
1377211128.184058	ClEkJM2Vm5giqnMf4h	192.168.43.155	59977	155.212.214.188	23130	udp	spicy_stun	7.955804	2136	1972	SF	-	-	0	Dd	22	2752	22	2588	-
1377211128.232201	CtPZjS20MLrsMUOJi2	192.168.43.155	60020	155.212.214.188	23130	udp	spicy_stun	0.274303	288	288	SF	-	-	0	Dd	4	400	3	372	-
1377211128.184433	C4J4Th3PJpwUYZZ6gc	192.168.43.155	59977	155.212.214.188	23131	udp	spicy_stun	7.955427	2088	1872	SF	-	-	0	Dd	21	2676	21	2460	-
1377211128.232522	CUM0KZ3MLUfNB0cl11	192.168.43.155	60020	155.212.214.188	23131	udp	spicy_stun	0.242014	288	288	SF	-	-	0	Dd	4	400	3	372	-
#close	2021-11-23-19-48-14
```

Testing Pcaps:

- [stun-ice-testcall.pcap](https://github.com/r-franke/spicy_stun/blob/master/test_data/stun-ice-testcall.pcap)
- stun-attribute-length-ffff.pcap (self-made)
- stun-malformed-error.pcap (self-made)
