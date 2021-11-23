spicy_add_analyzer(
    NAME STUN
    PACKAGE_NAME STUN
    SOURCES analyzer.spicy analyzer.evt zeek_analyzer.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig)
