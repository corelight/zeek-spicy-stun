signature STUN {
  ip-proto == udp
  payload /^.{4}\x21\x12\xa4\x42/
  enable "spicy_STUN"
}

signature STUN_TCP {
  ip-proto == tcp
  payload /^.{4}\x21\x12\xa4\x42/
  enable "spicy_STUN_TCP"
}
