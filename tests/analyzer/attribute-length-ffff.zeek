# @TEST-EXEC: $ZEEK -Cr ${TRACES}/stun-attribute-length-ffff.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
#
# @TEST-DOC: Test that attributes of length 0xffff do not cause integer overflow errors

@load analyzer
