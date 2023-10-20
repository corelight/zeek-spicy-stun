module STUN;

export {
	const methodtype = {
		[0x01] = "BINDING",
		[0x03] = "ALLOCATE",
		[0x04] = "REFRESH",
		[0x06] = "SEND",
		[0x07] = "DATA",
		[0x08] = "CREATEPERMISSION",
		[0x09] = "CHANNELBIND",
		[0x0A] = "CONNECT",
		[0x0B] = "CONNECTIONBIND",
		[0x0C] = "CONNECTIONATTEMPT",
		[0x080] = "GOOG-PING",
	} &default=function(n: count): string
		{
		return fmt("unknown-methodtype-%d", n);
		};

	const classtype = {
		[0x00] = "REQUEST",
		[0x01] = "INDICATION",
		[0x02] = "RESPONSE_SUCCESS",
		[0x03] = "RESPONSE_ERROR",
	} &default=function(n: count): string
		{
		return fmt("unknown-classtype-%d", n);
		};

	const attrtype = {
		[0x0001] = "MAPPED_ADDRESS",
		[0x0006] = "USERNAME",
		[0x0008] = "MESSAGE_INTEGRITY",
		[0x0009] = "ERROR_CODE",
		[0x000A] = "UNKNOWN_ATTRIBUTES",
		[0x000C] = "CHANNEL_NUMBER",
		[0x000D] = "LIFETIME",
		[0x0012] = "XOR_PEER_ADDRESS",
		[0x0013] = "DATA",
		[0x0014] = "REALM",
		[0x0015] = "NONCE",
		[0x0016] = "XOR_RELAYED_ADDRESS",
		[0x0017] = "REQUESTED_ADDRESS_FAMILY",
		[0x0018] = "EVEN_PORT",
		[0x0019] = "REQUESTED_TRANSPORT",
		[0x001A] = "DONT_FRAGMENT",
		[0x001B] = "ACCESS_TOKEN",
		[0x001C] = "MESSAGE_INTEGRITY_SHA256",
		[0x001D] = "PASSWORD_ALGORITHM",
		[0x001E] = "USERHASH",
		[0x0020] = "XOR_MAPPED_ADDRESS",
		[0x0022] = "RESERVATION_TOKEN",
		[0x0024] = "PRIORITY",
		[0x0025] = "USE_CANDIDATE",
		[0x0026] = "PADDING",
		[0x0027] = "RESPONSE_PORT",
		[0x002A] = "CONNECTION_ID",
		[0x8000] = "ADDITIONAL_ADDRESS_FAMILY",
		[0x8001] = "ADDRESS_ERROR_CODE",
		[0x8002] = "PASSWORD_ALGORITHMS",
		[0x8003] = "ALTERNATE_DOMAIN",
		[0x8004] = "ICMP",
		[0x8022] = "SOFTWARE",
		[0x8023] = "ALTERNATE_SERVER",
		[0x8025] = "TRANSACTION_TRANSMIT_COUNTER",
		[0x8027] = "CACHE_TIMEOUT",
		[0x8028] = "FINGERPRINT",
		[0x8029] = "ICE_CONTROLLED",
		[0x802A] = "ICE_CONTROLLING",
		[0x802B] = "RESPONSE_ORIGIN",
		[0x802C] = "OTHER_ADDRESS",
		[0x802D] = "ECN_CHECK",
		[0x802E] = "THIRD_PARTY_AUTHORIZATION",
		[0x8030] = "MOBILITY_TICKET",
		[0xC000] = "CISCO_STUN_FLOWDATA",
		[0xC001] = "ENF_FLOW_DESCRIPTION",
		[0xC002] = "ENF_NETWORK_STATUS",
		[0xC057] = "GOOG_NETWORK_INFO",
		[0xC058] = "GOOG_LAST_ICE_CHECK_RECEIVED",
		[0xC059] = "GOOG_MISC_INFO",
		[0xC05A] = "GOOG_OBSOLETE_1",
		[0xC05B] = "GOOG_CONNECTION_ID",
		[0xC05C] = "GOOG_DELTA",
		[0xC05D] = "GOOG_DELTA_ACK",
		[0xC060] = "GOOG_MESSAGE_INTEGRITY_32",
	} &default=function(n: count): string
		{
		return fmt("unknown-attrtype-%d", n);
		};
}
