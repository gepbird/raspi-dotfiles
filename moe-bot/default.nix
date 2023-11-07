{ config, pkgs, lib, ... }:

with lib;
with types;
let
  cfg = config.services.moe-bot;
in
{
  options.services.moe-bot = {
    enable = mkEnableOption "Enable the Moe-Bot service";
    package = mkOption {
      type = package;
      default = (pkgs.callPackage ./package.nix { });
    };
    group = mkOption {
      type = str;
      description = ''
        The group for moe-bot user that the systemd service will run under.
      '';
    };
    token = mkOption {
      type = str;
      description = ''
        Your Discord bot's access token.
        Anyone with possession of this token can act on your bot's behalf.
      '';
    };
    owners = mkOption {
      type = str;
      description = ''
        Comma separated list of User IDs who have full access to the bot. Overrides modranks.
      '';
    };
    backups-interval-minutes = mkOption {
      type = int;
      default = 60;
      description = ''
        Minutes between automatic database backups.
      '';
    };
    backups-to-keep = mkOption {
      type = int;
      default = 50;
      description = ''
        Delete old backups after the number of backups exceeds this.
      '';
    };
  };

  config = mkIf cfg.enable {
    users.users.moe-bot = {
      isSystemUser = true;
      home = "/var/moe-bot";
      createHome = true;
      group = cfg.group;
    };

    systemd.services.moe-bot = {
      description = "Moe-Bot";
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/MoeBot";
        WorkingDirectory = "/var/moe-bot";
        User = "moe-bot";
        Environment =
          let
            token = "TOKEN=${cfg.token}";
            owners = "OWNERS=${cfg.owners}";
            backups-interval-minutes = "BACKUP_INTERVAL_MINUTES=${toString cfg.backups-interval-minutes}";
            backups-to-keep = "BACKUPS_TO_KEEP=${toString cfg.backups-to-keep}";
          in
          "${token} ${owners} ${backups-interval-minutes} ${backups-to-keep}";
      };
    };
  };
}

