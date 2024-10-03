let
  ymstnt = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBFMbDkjW4Bei6BIQRNzoAyed+1klLFjumE6Og6GhMsz";
  gep = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID3olHivyTuztxmwefBJ5EtsaG2Kff7kDGVUacrFMIFQ";

  raspi-doboz = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK3vrYOUtZIZhwoYihWYUzglxs7w8GGq647OX9vNcPRP";

  keys = [ ymstnt gep raspi-doboz ];
in
{
  "moe.age".publicKeys = keys;
  "mysql.age".publicKeys = keys;
  "transmission.json.age".publicKeys = keys;
  "runner1.age".publicKeys = keys;
  "miniflux.age".publicKeys = keys;
  "openai-token-gep.age".publicKeys = keys;
  "gotosocial.age".publicKeys = keys;
  "borgmatic-raspi.age".publicKeys = keys;
  "authelia-jwt.age".publicKeys = keys;
  "authelia-sekf.age".publicKeys = keys;
  "authelia-ssf.age".publicKeys = keys;
  "authelia-hmac.age".publicKeys = keys;
  "authelia-ipvk.age".publicKeys = keys;
  "lldap-jwt.age".publicKeys = keys;
  "lldap-user-pass.age".publicKeys = keys;
  "lldap-private-key.age".publicKeys = keys;
}
