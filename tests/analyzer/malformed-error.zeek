# @TEST-EXEC: zeek -Cr ${TRACES}/stun-malformed-error.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: grep -o "requires failed" weird.log > weird.log.cut
# @TEST-EXEC: btest-diff weird.log.cut
#
# @TEST-DOC: Test that truncated errors do not cause integer overflow errors

@load analyzer
