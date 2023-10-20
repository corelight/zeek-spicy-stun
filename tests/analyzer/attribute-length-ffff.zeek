# @TEST-EXEC: $ZEEK -Cr ${TRACES}/stun-attribute-length-ffff.pcap %INPUT
#
# Zeek 6 and newer populate the local_orig and local_resp columns by default,
# while earlier ones only do so after manual configuration. Filter out these
# columns to allow robust baseline comparison:
# @TEST-EXEC: cat conn.log | zeek-cut -m -n local_orig local_resp >conn.log.filtered
#
# @TEST-EXEC: btest-diff conn.log.filtered
#
# @TEST-DOC: Test that attributes of length 0xffff do not cause integer overflow errors

@load analyzer
