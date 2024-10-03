{ lib, config, pkgs, agenix, ... }:

{
  imports = [
    ./home/gep.nix
    ./home/ymstnt.nix
  ];

  swapDevices = [{
    device = "/var/lib/swapfile";
    size = 6 * 1024;
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
    " d    /var/media/incomplete-torrents 0755 ymstnt shared"
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
  ];

  age.secrets = {
    moe.file = ./secrets/moe.age;
    mysql.file = ./secrets/mysql.age;
    transmission.file = ./secrets/transmission.json.age;
    runner1.file = ./secrets/runner1.age;
    miniflux.file = ./secrets/miniflux.age;
    gotosocial.file = ./secrets/gotosocial.age;
    borgmatic-raspi.file = ./secrets/borgmatic-raspi.age;
    authelia-jwt.file = ./secrets/authelia-jwt.age;
    authelia-sekf.file = ./secrets/authelia-sekf.age;
    authelia-ssf.file = ./secrets/authelia-ssf.age;
    authelia-hmac.file = ./secrets/authelia-hmac.age;
    authelia-ipvk.file = ./secrets/authelia-ipvk.age;
    lldap-jwt = {
      file = ./secrets/lldap-jwt.age;
      mode = "0440";
      group = "lldap";
    };
    lldap-private-key = {
      file = ./secrets/lldap-private-key.age;
      mode = "0440";
      group = "lldap";
    };
    lldap-user-pass = { 
      file = ./secrets/lldap-user-pass.age;
      mode = "0440";
      group = "lldap";
    };
  };

  services.avahi.enable = true;

  services.plex = {
    enable = true;
    openFirewall = true;
    user = "ymstnt";
    group = "shared";
  };

  services.transmission = {
    user = "ymstnt";
    group = "shared";
    enable = true;
    openRPCPort = true;
    openPeerPorts = true;
    settings = {
      download-dir = "/var/media/torrents";
      incomplete-dir = "/var/media/incomplete-torrents";
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

  services.github-runners = {
    website = {
      enable = true;
      replace = true;
      user = "shared";
      url = "https://github.com/ymstnt/ymstnt.com";
      tokenFile = config.age.secrets.runner1.path;
      extraPackages = with pkgs; [
        nodejs_20
      ];
      nodeRuntimes = [ "node20" ];
      serviceOverrides = {
        ReadWritePaths = [ "/var/www/ymstnt.com-generated" ];
      };
    };
  };

  services.ntfy-sh = {
    enable = true;
    group = "shared";
    settings = {
      base-url = "https://ntfy.ymstnt.com";
      behind-proxy = true;
      web-root = "disable";
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
    virtualHosts = {
      "ymstnt.com" = {
        enableACME = true;
        forceSSL = true;
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
          "/\.git".extraConfig = ''
            deny all;
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
      "ntfy.ymstnt.com" = {
        enableACME = true;
        forceSSL = true;
        locations = {
          "/" = {
            proxyPass = "http://${toString config.services.ntfy-sh.settings.listen-http}";
            recommendedProxySettings = true;
            proxyWebsockets = true;
          };
        };
      };
      "notes.ymstnt.com" = {
        enableACME = true;
        forceSSL = true;
        locations = {
          "/" = {
            proxyPass = "http://${toString config.services.silverbullet.listenAddress}:${toString config.services.silverbullet.listenPort}";
            recommendedProxySettings = true;
            proxyWebsockets = true;
          };
        };
      };
    };
  };

  services.authelia.instances.main = {
    enable = true;
    secrets = {
      jwtSecretFile = config.age.secrets.authelia-jwt.path;
      storageEncryptionKeyFile = config.age.secrets.authelia-sekf.path;
      sessionSecretFile = config.age.secrets.authelia-ssf.path;
      oidcHmacSecretFile = config.age.secrets.authelia-hmac.path;
      oidcIssuerPrivateKeyFile = config.age.secrets.authelia-ipvk.path;
    };
    settings = {
      theme = "auto";
      default_2fa_method = "totp";
      server = {
        host = "localhost";
        port = 9092;
      };
      log.level = "info";
      regulation = {
        max_retries = 3;
        find_time = 120;
        ban_time = 300;
      };
      totp.issuer = "authelia.com";
    };
  };

  services.lldap = {
    enable = true;
    settings = {
      http_url = "https://ldap.ymstnt.com";
      ldap_base_dn = "dc=ymstnt,dc=com";
      key_file = config.age.secrets.lldap-private-key.path;
    };
    environment = {
      LLDAP_JWT_SECRET_FILE = config.age.secrets.lldap-jwt.path;
      LLDAP_LDAP_USER_PASS_FILE = config.age.secrets.lldap-user-pass.path;
    };
  };

  systemd.services.lldap.serviceConfig.SupplementaryGroups = [ "lldap-secrets" ];

  services.miniflux = {
    enable = true;
    adminCredentialsFile = config.age.secrets.miniflux.path;
    config = {
      PORT = "3327";
      BASE_URL = "http://localhost/miniflux/";
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

  services.silverbullet = {
    enable = true;
    group = "shared";
    user = "shared";
    openFirewall = true;
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

  services.postgresql = {
    enable = true;
    authentication = ''
      #type database  DBuser  auth-method
      local all       all     trust
    '';
  };

  systemd.services.borgmatic = {
    path = with pkgs; [
      postgresql
      sqlite
    ];
  };
  services.borgmatic = {
    enable = true;
    configurations = {
      "raspi" = {
        repositories = [
          {
            label = "borgmatic";
            path = "ssh://khrfjql1@khrfjql1.repo.borgbase.com/./repo";
          }
        ];
        postgresql_databases = [
          {
            name = "miniflux";
            username = "postgres";
            password = "";
          }
        ];
        sqlite_databases = [
          {
            name = "moe";
            path = "/var/moe/storage.db";
          }
          {
            name = "gotosocial";
            path = "/var/lib/gotosocial/database.sqlite";
          }
        ];
        exclude_patterns = [
          "*cache*"
          "*Cache*"
          "*.tmp"
          "*.log"
        ];
        exclude_if_present = [
          ".nobackup"
        ];
        encryption_passcommand = "${pkgs.coreutils}/bin/cat ${config.age.secrets.borgmatic-raspi.path}";
        ssh_command = "${pkgs.openssh}/bin/ssh -i /etc/ssh/borg";
        relocated_repo_access_is_ok = true;
        compression = "auto,zstd";
        archive_name_format = "{hostname}-{now:%Y-%m-%d-%H%M%S}";
        retries = 5;
        retry_wait = 30;
        keep_hourly = 1;
        keep_daily = 7;
        keep_weekly = 4;
        keep_monthly = 6;
        checks = [
          {
            name = "repository";
            frequency = "weekly";
            only_run_on = [
              "Sunday"
            ];
          }
          {
            name = "archives";
            frequency = "weekly";
            only_run_on = [
              "Sunday"
            ];
          }
        ];
      };
    };
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

  environment.shellInit = "umask 002";
  users.users = {
    shared = {
      isSystemUser = true;
      group = "shared";
    };
    borgmatic = {
      isSystemUser = true;
      group = "shared";
    };
  };

  users.groups.shared = { };

  moe = {
    enable = true;
    group = "shared";
    openFirewall = true;
    settings = {
      status-port = 25571;
    };
    credentialsFile = config.age.secrets.moe.path;
  };

  environment.systemPackages = with pkgs; [
    git
    gotosocial
    inotify-tools
    ncdu
    nh
    nix-inspect
    nix-output-monitor
    nvd
    agenix.packages.${pkgs.system}.default
  ];

  # TODO: remove after issue is fixed https://github.com/NixOS/nixpkgs/issues/180175
  systemd.services.tailscaled.after = ["NetworkManager-wait-online.service"];

  nixpkgs.config.allowUnfree = true;
  nix.settings.experimental-features = [
    "nix-command"
  ];

  nix.settings.trusted-users = [ "gep" "ymstnt" ];

  home-manager.useGlobalPkgs = true;

  system.stateVersion = "23.05";
}
