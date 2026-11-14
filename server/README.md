# Fran sync server

The server Fran syncs with when you add a "Fran sync server" cloud. It stores encrypted records and nothing else. Passwords, keys, names and contents are encrypted on your computers before they're sent, so the server and whoever runs it can't read them.

It runs on Linux, as a Docker image or a Nix package. Other systems aren't supported.

## What you need

- Docker with Compose, or NixOS.
- A domain with https in front of the server. Fran only uses plain http when you type `http://` yourself, and warns that it's for testing only. Use a reverse proxy (Caddy, nginx, Traefik), or give the server a certificate itself with `TLS_CERT` and `TLS_KEY`.

## Set up with Docker

1. Make a server key in a `.env` file next to the compose file, and keep that file:

   ```sh
   echo "SERVER_KEY=$(openssl rand -hex 32)" > .env
   ```

2. The key is any 64 hex characters, so any random source works. Without openssl: `head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'`. On a platform that takes environment variables in a form, paste one in there instead.

3. Start it. Pick one:

   ```sh
   docker compose -f compose.sqlite.yml up -d   # one container, the database is a file
   docker compose -f compose.mysql.yml up -d    # with MySQL, also needs MYSQL_PASSWORD in .env
   ```

4. Point your reverse proxy at `127.0.0.1:8787`. The WebSocket at `/v1/events` has to be passed through too. With Caddy this is the whole config:

   ```
   sync.example.com {
       reverse_proxy 127.0.0.1:8787
   }
   ```

5. Claim it. Until someone owns the server, it prints a setup code in its log each time it starts:

   ```sh
   docker compose -f compose.sqlite.yml logs fran-sync | grep "setup code"
   ```

   In Fran, open Sync, add a cloud, enter the server's address, choose "Create account" and put the setup code where it asks for an invite. That account becomes the owner, even with sign-up closed. Someone who already has an account there can claim it from the Server part of the cloud's panel instead. Do this right after the first start: anyone who can read the log can claim it until then.

6. Let others in from the Server tab: make invites, set storage limits, and see who's signed in where. The command line below does the same for the basics.

To build the image yourself, run this from the repo root:

```sh
docker build --file server/Dockerfile --tag fran-sync-server .
```

## Set up on NixOS

The flake has the package (`fran-sync-server`) and a module:

```nix
{
  imports = [fran.nixosModules.fran-sync];

  services.fran-sync = {
    enable = true;
    # A file with one line, SERVER_KEY=<the key>, readable by root only.
    environmentFile = "/run/secrets/fran-sync.env";
    environment = {
      BIND = "127.0.0.1:8787";
      SIGNUP = "closed";
      TRUST_PROXY = "true";
    };
  };
}
```

It runs as the `fran-sync` user from `/var/lib/fran-sync`, so the database is `/var/lib/fran-sync/fran-sync.db` unless `DATABASE_URL` says otherwise. Run the admin commands as that user, from that folder and with the same settings:

```sh
sudo systemd-run --pty --wait --uid=fran-sync \
  -p EnvironmentFile=/run/secrets/fran-sync.env -p WorkingDirectory=/var/lib/fran-sync \
  "$(command -v fran-sync-server)" users create you@example.com
```

## Settings

Set them as environment variables, or in a `server.toml` in the working directory with the same names in lower case (`FRAN_SYNC_CONFIG` names another file). The environment wins.

`SIGNUP`, `RECORD_BYTES`, `ACCOUNT_BYTES`, `BATCH_RECORDS` and `SERVER_BYTES` are only where the server starts. The owner or an admin can change them from Fran, which saves them in the database, and a value saved there wins over the one set here. Nothing else can be changed from the app.

| Name | Default | What it does |
| --- | --- | --- |
| `SERVER_KEY` | none, required | 64 hex characters, from `openssl rand -hex 32` or `fran-sync-server key`. Protects the two-step sign-in secrets and is part of every account's password salt. |
| `DATABASE_URL` | `sqlite:fran-sync.db`, in the working directory (`/data` in the image) | `sqlite:<path>` or `mysql://user:password@host:port/database`. MariaDB works with the same URL. With the image's SQLite default, mount a volume at `/data` or the database goes with the container. With MySQL nothing is written there. |
| `BIND` | `127.0.0.1:8787` (`0.0.0.0:8787` in the image) | Address and port to listen on. |
| `SIGNUP` | `closed` | `closed`: only emails given to `users create`. `invite`: anyone with a code from `users invite`. `open`: anyone. |
| `TLS_CERT`, `TLS_KEY` | not set | PEM files. With both set the server does https itself. |
| `TRUST_PROXY` | `false` | `true` counts sign-in attempts per address from `X-Forwarded-For`. Only turn it on behind a proxy that sets that header. |
| `PUBLIC_URL` | not set | The address clients use. Checked to be https, not used for anything else yet. |
| `RECORD_BYTES` | `262144` | Largest single record (256 KiB). |
| `ACCOUNT_BYTES` | `52428800` | Storage per account (50 MiB). |
| `BATCH_RECORDS` | `5000` | Most records in one push. |
| `SERVER_BYTES` | `0` | Storage for every account together, 0 for no limit. A push that grows past it is refused, deletes still work. |
| `LOGIN_WINDOW_SECS` | `900` | The window the three limits below count in. |
| `LOGIN_ATTEMPTS_PER_ACCOUNT` | `10` | Failed sign-ins per account in the window. |
| `LOGIN_ATTEMPTS_PER_IP` | `30` | Failed sign-ins per address in the window. |
| `SIGNUPS_PER_IP` | `10` | New accounts per address in the window. |

## Admin commands

Run them where the server's settings are, so inside the container with Docker (`docker compose exec fran-sync fran-sync-server ...`).

```
fran-sync-server key                   print a new SERVER_KEY
fran-sync-server users list            list the accounts
fran-sync-server users create <email>  make room for one account, works with SIGNUP=closed too
fran-sync-server users invite          make an invite anyone can use once (SIGNUP=invite)
fran-sync-server users delete <email>  delete an account and everything it stored
fran-sync-server users role <email> <user|admin|owner>
                                       owner hands the server over, the old owner becomes an admin
fran-sync-server --version
```

`users role` is also the way back in when the owner's account is lost: make another account the owner.

The server can't create an account by itself or reset a password. The keys are made in Fran from the password, and the server never sees them. Someone who forgot their password needs their recovery key.

## Backups

Back up two things: the database and `SERVER_KEY`.

- SQLite: the database is `/data/fran-sync.db` in the `fran-sync-data` volume, with `-wal` and `-shm` files next to it while the server runs. Stop the server and copy the file, or copy all three together:

  ```sh
  docker compose -f compose.sqlite.yml stop
  docker run --rm -v fran-sync-data:/data -v "$PWD":/backup debian:bookworm-slim cp /data/fran-sync.db /backup/
  docker compose -f compose.sqlite.yml start
  ```

  Compose puts the project name in front of the volume's name, so check it with `docker volume ls`.

- MySQL: `docker compose -f compose.mysql.yml exec db sh -c 'mysqldump -u fran -p"$MYSQL_PASSWORD" --single-transaction fran_sync' > fran-sync.sql`

A backup holds ciphertext only. It's no use to anyone without an account's password or recovery key.

If the server key is lost or changed, accounts with two-step sign-in can't sign in any more, and new accounts get a different salt. The synced data itself isn't affected. Every computer also keeps its own full copy, so losing the server never loses data: set up a new server and sync to it.

## Upgrades

```sh
docker compose -f compose.sqlite.yml pull
docker compose -f compose.sqlite.yml up -d
```

The server updates its own tables when it starts. Take a backup first, since a newer database can't be opened by an older server. The image tags are the server's version (`0.1.0`), which is separate from Fran's, and `latest`. Fran and the server have to speak the same protocol version, and each tells you to update the other when they don't.

## What the server knows

- Each account's email, when it was made and how much it stores.
- Each device's name and system, and when it last synced.
- Per record: a random-looking id, a revision number, its size and when it changed.

It doesn't log request bodies, tokens or keys.
