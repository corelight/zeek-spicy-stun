# @TEST-EXEC: zeek -Cr ${TRACES}/stun-malformed-error.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
#
# @TEST-DOC: Test that truncated errors do not cause integer overflow errors

@load analyzer
