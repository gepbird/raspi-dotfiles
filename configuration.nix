{ lib, config, pkgs, agenix, ... }:

{
  imports = [
    ./home/gep.nix
    ./home/ymstnt.nix
  ];

  swapDevices = [{
    device = "/var/lib/swapfile";
    size = 2 * 1024;
  }];

  console.keyMap = "hu";

  networking = {
    hostName = "raspi-doboz";
    networkmanager.enable = true;
  };

  services.fail2ban.enable = true;

  time.timeZone = "Europe/Budapest";

  services.tailscale = {
    enable = true;
  };

  systemd.tmpfiles.rules = [
    # Type Path                           Mode User   Group   Age Argument
    " d    /var/media                     0755 ymstnt shared"
    " d    /var/media/music               0755 ymstnt shared"
    " d    /var/media/torrents            0755 ymstnt shared"
    " d    /var/media/torrents/Movies     0755 ymstnt shared"
    " d    /var/media/torrents/Shows      0755 ymstnt shared"
    " d    /var/media/torrents/Anime      0755 ymstnt shared"
    " d    /var/media/media-server        0755 ymstnt shared"
    " d    /var/media/media-server/Movies 0755 ymstnt shared"
    " d    /var/media/media-server/Shows  0755 ymstnt shared"
    " d    /var/media/media-server/Anime  0755 ymstnt shared"
    " d    /var/moe                       0750 moe    shared"
    " d    /var/www/ymstnt.com            2770 nginx  shared"
    " d    /var/www/ymstnt.com-generated  0775 shared shared"
    # required by gepDrive due to sending requests to localhost
    " L    /var/www/localhost            -    -      -      -    /var/www/ymstnt.com"
  ];

  age.secrets = {
    moe.file = ./secrets/moe.age;
    mysql.file = ./secrets/mysql.age;
    transmission.file = ./secrets/transmission.json.age;
    runner1.file = ./secrets/runner1.age;
    miniflux.file = ./secrets/miniflux.age;
    gotosocial.file = ./secrets/gotosocial.age;
    ddclient.file = ./secrets/ddclient.age;
  };

  services.avahi.enable = true;

  services.minidlna = {
    enable = true;
    openFirewall = true;
    settings = {
      friendly_name = "ymstnt-media";
      media_dir = [
        "V,/var/media/media-server"
        "V,/var/media/torrents"
      ];
      log_level = "error";
      inotify = "yes";
    };
  };

  services.transmission = {
    user = "ymstnt";
    group = "shared";
    enable = true;
    openRPCPort = true;
    openPeerPorts = true;
    settings = {
      download-dir = "/var/media/torrents";
      incomplete-dir-enabled = false;
      rpc-enabled = true;
      rpc-host-whitelist-enabled = false;
      rpc-whitelist-enabled = true;
      rpc-authentication-required = true;
      rpc-username = "ymstnt";
      rpc-whitelist = "127.0.0.1,192.168.*.*,100.*.*.*";
      rpc-bind-address = "0.0.0.0";
      umask = 18;
      ratio-limit = 1;
      ratio-limit-enabled = true;
    };
    credentialsFile = config.age.secrets.transmission.path;
  };

  services.n8n = {
    enable = true;
    openFirewall = true;
    webhookUrl = "https://n8n.ymstnt.com/";
    settings = {
      generic = {
        timezone = config.time.timeZone;
      };
    };
  };

  services.github-runners = {
    website = {
      enable = true;
      replace = true;
      user = "shared";
      url = "https://github.com/ymstnt/ymstnt.com";
      tokenFile = config.age.secrets.runner1.path;
      extraPackages = with pkgs; [
        bun
        nodejs_20
      ];
      nodeRuntimes = [ "node20" ];
      serviceOverrides = {
        ReadWritePaths = [ "/var/www/ymstnt.com-generated" ];
      };
    };
  };

  services.phpfpm.pools.shared = {
    user = "shared";
    settings = {
      pm = "dynamic";
      "listen.owner" = config.services.nginx.user;
      "pm.max_children" = 32;
      "pm.max_requests" = 500;
      "pm.start_servers" = 2;
      "pm.min_spare_servers" = 2;
      "pm.max_spare_servers" = 5;
      "security.limit_extensions" = ".php .html";
    };
    phpOptions = ''
      upload_max_filesize = 50G
      post_max_size = 50G
    '';
    phpEnv."PATH" = lib.makeBinPath [ pkgs.php ];
  };


  services.nginx = {
    enable = true;
    group = "shared";
    appendConfig = ''
      error_log /var/log/nginx/error.log debug;
    '';
    virtualHosts =
      let
        ymstnt-com = {
          root = "/var/www";
          extraConfig = ''
            error_page 404 /ymstnt.com-generated/404.html;
            client_max_body_size 50G;
            fastcgi_read_timeout 24h;
          '';
          locations = {
            "~ ^([^.\?]*[^/])$".extraConfig = ''
              if (-d $document_root/ymstnt.com-generated$uri) {
                rewrite ^([^.]*[^/])$ $1/ permanent;
              }
              if (-d $document_root/ymstnt.com$uri) {
                rewrite ^([^.]*[^/])$ $1/ permanent;
              }
              try_files _ @entry;
            '';
            "/".extraConfig = ''
              try_files _ @entry;
            '';
            "@entry".extraConfig = ''
              try_files /ymstnt.com-generated$uri /ymstnt.com-generated$uri/index.html @ymstnt.com-rewrite;
            '';
            "@ymstnt.com-rewrite".extraConfig = ''
              if (-f $document_root/ymstnt.com$uri) {
                rewrite ^(.*)$ /ymstnt.com$1 last;
              }
              if (-f $document_root/ymstnt.com$uri/index.html) {
                rewrite ^(.*)$ /ymstnt.com$1/index.html last;
              }
              if (-f $document_root/ymstnt.com$uri/index.php) {
                rewrite ^(.*)$ /ymstnt.com$1/index.php last;
              }
            '';
            "/ymstnt.com/".extraConfig = ''
              alias /var/www/ymstnt.com/;
              location ~ \.(php|html)$ {
                alias /var/www;
                fastcgi_pass unix:${config.services.phpfpm.pools.shared.socket};
              }
            '';
            "/.well-known/webfinger".extraConfig = ''
              rewrite ^.*$ https://social.ymstnt.com/.well-known/webfinger permanent;
            '';
            "/.well-known/host-meta".extraConfig = ''
              rewrite ^.*$ https://social.ymstnt.com/.well-known/host-meta permanent;
            '';
            "/.well-known/nodeinfo".extraConfig = ''
              rewrite ^.*$ https://social.ymstnt.com/.well-known/nodeinfo permanent;
            '';
            "^~ /miniflux/" = {
              proxyPass = "http://localhost:${config.services.miniflux.config.PORT}/miniflux/";
              recommendedProxySettings = true;
            };
            "^~ /navidrome/" = {
              proxyPass = "http://127.0.0.1:${toString config.services.navidrome.settings.Port}";
              recommendedProxySettings = true;
            };
          };
        };
      in
      {
        "ymstnt.com" = ymstnt-com // {
          enableACME = true;
          forceSSL = true;
        };
        # gepDrive needs to send requests to current host, and can't send it to ymstnt.com due to hairpinning
        "localhost" = ymstnt-com;
        "n8n.ymstnt.com" = {
          enableACME = true;
          forceSSL = true;
          locations = {
            "/" = {
              proxyPass = "http://127.0.0.1:${toString config.services.n8n.settings.port}";
              proxyWebsockets = true;
              recommendedProxySettings = true;

              extraConfig = ''
                chunked_transfer_encoding off;
                proxy_buffering off;
                proxy_cache off;
              '';
            };
            "~ ^/(webhook|webhook-test)" = {
              proxyPass = "http://127.0.0.1:${toString config.services.n8n.settings.port}";

              extraConfig = ''
                chunked_transfer_encoding off;
                proxy_buffering off;
                proxy_cache off;
              '';
            };
            "~ ^/rest/oauth2-credential/callback" = {
              proxyPass = "http://127.0.0.1:${toString config.services.n8n.settings.port}";

              extraConfig = ''
                chunked_transfer_encoding off;
                proxy_buffering off;
                proxy_cache off;
              '';
            };
          };
        };
        "social.ymstnt.com" = {
          enableACME = true;
          forceSSL = true;
          locations = {
            "/" = {
              proxyPass = "http://127.0.0.1:${toString config.services.gotosocial.settings.port}";

              extraConfig = ''
                proxy_set_header Host $host;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection "upgrade";
                proxy_set_header X-Forwarded-For $remote_addr;
                proxy_set_header X-Forwarded-Proto $scheme;
                client_max_body_size 40M;
              '';
            };
          };
        };
      };
  };

  services.miniflux = {
    enable = true;
    adminCredentialsFile = config.age.secrets.miniflux.path;
    config = {
      PORT = "3327";
      BASE_URL = "http://localhost/miniflux/";
    };
  };

  services.navidrome = {
    enable = true;
    openFirewall = true;
    settings = {
      BaseUrl = "/navidrome";
      MusicFolder = "/var/media/music";
    };
  };

  services.gotosocial = {
    enable = true;
    settings = {
      bind-address = "127.0.0.1";
      port = 3333;
      host = "social.ymstnt.com";
      account-domain = "ymstnt.com";
      db-type = "sqlite";
      db-address = "/var/lib/gotosocial/database.sqlite";
      protocol = "https";
      storage-local-base-path = "/var/lib/gotosocial/storage";
    };
    environmentFile = config.age.secrets.gotosocial.path;
  };

  security.acme = {
    acceptTerms = true;
    defaults.email = "ymstnt@mailbox.org";
  };

  networking.firewall.allowedTCPPorts = [ 80 443 ];

  services.mysql = {
    enable = true;
    package = pkgs.mariadb;
  };

  services.openssh = {
    enable = true;
    ports = [ 42727 ];
    settings = {
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
      PermitRootLogin = "no";
      X11Forwarding = true;
    };
  };

  services.ddclient = {
    enable = true;
    protocol = "porkbun";
    domains = [
      ".ymstnt.com"
      "social.ymstnt.com"
      "n8n.ymstnt.com"
      "dev.ymstnt.com"
    ];
    verbose = true;
    usev4 = "webv4,webv4=api.ipify.org/";
    usev6 = ""; # ddclient prioritizes v6 which is unavailable at voda, empty string to disable it
    extraConfig = builtins.readFile config.age.secrets.ddclient.path;
  };

  environment.shellInit = "umask 002";
  users.users = {
    shared = {
      isSystemUser = true;
      group = "shared";
    };
    minidlna = {
      extraGroups = [ "users" "shared" ];
    };
  };

  users.groups.shared = { };

  moe = {
    enable = true;
    group = "shared";
    openFirewall = true;
    settings = {
      backups-interval-minutes = 240;
      backups-to-keep = 100;
      status-port = 25571;
    };
    credentialsFile = config.age.secrets.moe.path;
  };

  environment.systemPackages = with pkgs; [
    git
    inotify-tools
    nh
    nix-inspect
    nvd
    nix-output-monitor
    gotosocial
    agenix.packages.${pkgs.system}.default
  ];

  # TODO: remove after issue is fixed https://github.com/NixOS/nixpkgs/issues/180175
  systemd.services.NetworkManager-wait-online.enable = false;

  nixpkgs.config.allowUnfree = true;
  nix.settings.experimental-features = [
    "nix-command"
  ];

  nix.settings.trusted-users = [ "gep" "ymstnt" ];

  home-manager.useGlobalPkgs = true;

  system.stateVersion = "23.05";
}
