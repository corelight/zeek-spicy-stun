# @TEST-DOC: Check for performance regression
#
# @TEST-EXEC: btest-bg-run test $ZEEK -Cr ${TRACES}/stun-many.pcap %INPUT
# @TEST-EXEC: btest-bg-wait 60

@load analyzer
