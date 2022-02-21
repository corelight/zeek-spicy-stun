# @TEST-EXEC: zeek -Cr ${TRACES}/stun-attribute-length-ffff.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: zeek-cut -c uid name addl < weird.log > weird.log.cut
# @TEST-EXEC: btest-diff weird.log.cut
#
# @TEST-DOC: Test that attributes of length 0xffff do not cause integer overflow errors

@load analyzer
