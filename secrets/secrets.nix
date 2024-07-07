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
  "ddclient.age".publicKeys = keys;
  "authelia-jwt.age".publicKeys = keys;
  "authelia-storage.age".publicKeys = keys;
}
