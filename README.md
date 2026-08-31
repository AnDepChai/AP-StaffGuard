# AP-StaffGuard

AP-StaffGuard is a security-first Paper plugin for protecting registered Minecraft OWNER/STAFF accounts with trusted-IP checks, Discord-based verification, account lifecycle controls, audit logging and fail-closed authorization.

> **Security note:** This repository contains source code and safe configuration templates. Never commit real Discord bot tokens, OAuth secrets, `server-secret.value`, RCON passwords, SSH keys or other credentials.

## What the plugin does

The normal protected-account flow is:

```text
Minecraft login
    ↓
Protected account lookup
    ↓
Account status / security state checks
    ↓
Client IP resolution
    ↓
Trusted IP check
    ├── Trusted → ALLOW
    └── Untrusted → Verification flow
                         ↓
                   Discord approval
                         ↓
                  Atomic approval
                         ↓
                  Trust new IP
                         ↓
                       ALLOW
```

The plugin is intended to **fail closed** when required security components cannot safely make an authorization decision.

## Requirements

- Java 21 runtime/build target.
- Paper-compatible Minecraft server.
- SQLite is used as the local database backend.
- Discord verification can be enabled when a Discord bot and verification channel are configured.

The current `plugin.yml` declares API version `1.21`.

## Installation

1. Build the plugin with Maven or use the JAR produced by GitHub Actions.
2. Copy `AP-StaffGuard-1.1.3.jar` to the server `plugins/` directory.
3. Start the server once so the plugin creates its configuration/data files.
4. Edit `plugins/AP-StaffGuard/config.yml`.
5. Restart the server after changing security or Discord configuration.

Do not delete the AP-StaffGuard database when updating the plugin unless you intentionally want to remove the stored protected accounts, trusted-IP state and verification state.

## First configuration

### Persistent 256-bit server secret

Generate a cryptographically random 32-byte secret on Linux:

```bash
openssl rand -hex 32
```

This produces 64 hexadecimal characters representing 256 bits.

Put it in:

```yaml
server-secret:
  value: "YOUR_64_HEX_CHARACTER_SECRET"
```

Keep the same value across restarts and updates. Do not put it in Git.

### Security section

Default security settings include:

```yaml
security:
  enabled: true
  temporary-ban-duration: "5m"
  verification-timeout: "2m"
  max-trusted-ips-per-account: 10
  max-verification-requests-per-10-minutes: 3
  max-verification-requests-per-ip-per-10-minutes: 5
  max-pending-sessions: 100
  max-discord-interactions-per-minute: 30
  max-discord-accounts-per-user: 2
  token-bytes: 32
```

Do not raise security limits casually. They are part of the abuse/rate-limit model.

### Discord

Set:

```yaml
discord:
  enabled: true
  channel-id: "DISCORD_TEXT_CHANNEL_ID"
  bot-token: "DISCORD_BOT_TOKEN"
  owner-user-ids:
    - "DISCORD_OWNER_USER_ID"
  staff-user-ids:
    - ""
  send-dm: true
  allow-self-approval: false
```

`owner-user-ids` are Discord users that can approve verification requests for protected accounts.

`staff-user-ids` are Discord staff identities. With `allow-self-approval: true`, a staff user may approve only a request whose linked Minecraft account has that same Discord user ID. Staff users do not gain Owner-level approval of other accounts.

With:

```yaml
allow-self-approval: false
```

Staff users cannot self-approve. Owners remain authorized according to the Owner authorization policy.

## Proxy / address handling

The plugin deliberately does not blindly trust forwarded client addresses.

Default:

```yaml
proxy:
  mode: "NONE"
  require-trusted-proxy: true
```

If the Minecraft server is actually behind a trusted proxy, configure the proxy integration and trusted proxy addresses to match the real deployment. Do **not** disable proxy validation merely to make an IP check pass on a hosting provider.

Hosting platforms that use NAT without exposing proxy/forwarding controls may need a deployment-specific address strategy. In that case, verify what address Paper actually exposes before changing security policy.

## Registering a protected account

Owner-only example:

```text
/staffguard add AnPahn owner 123456789012345678
```

Aliases:

```text
/sg add AnPahn owner 123456789012345678
```

The command requires the player to be online so the plugin can use the exact current UUID.

If the account already exists, the command shows the existing role/Discord binding and requires explicit confirmation before overwriting it:

```text
/staffguard add AnPahn owner 123456789012345678 --confirm
```

`--confirm` means **confirm the account update**. It does not mean Discord approval and it does not automatically trust a new IP.

## Trusting the current IP manually

Owner-only:

```text
/staffguard verify AnPahn
```

This resolves the target's current client address and manually trusts it for the protected account.

For explicit IP management:

```text
/staffguard trust AnPahn 203.0.113.10
/staffguard untrust AnPahn 203.0.113.10
```

Only IPv4/IPv6 literals are accepted here; hostnames are intentionally rejected.

## Verification flow for a new IP

Typical workflow:

```text
Trusted Wi-Fi IP
      ↓
    login ✅
      ↓
Switch to 4G / another network
      ↓
 New IP is not trusted
      ↓
StaffGuard creates verification session
      ↓
Discord verification / approval
      ↓
Authorized approver approves
      ↓
New IP becomes trusted
      ↓
Login again ✅
```

If verification is rejected, expired or unavailable, the protected login remains denied.

## Account lifecycle commands

### Admin-readable commands

```text
/staffguard help
/staffguard info <player|uuid>
/staffguard logs <player|uuid>
```

### Owner commands

```text
/staffguard add <player> <owner|staff> <discordId> [--confirm]
/staffguard remove <player|uuid>
/staffguard trust <player|uuid> <ip>
/staffguard untrust <player|uuid> <ip>
/staffguard reset <player|uuid>
/staffguard verify <player>
/staffguard revoke <verificationId>
/staffguard lock <player|uuid>
/staffguard account-unlock <player|uuid>
/staffguard account-revoke <player|uuid>
/staffguard lockdown
/staffguard unlock
/staffguard reload
```

Alias:

```text
/sg
```

`reload` is intentionally limited: security and Discord configuration changes should be followed by a real server/plugin restart rather than a hot reload.

## Permission nodes

```text
staffguard.admin
staffguard.owner
```

The command implementation also treats console as Owner-authorized.

## Security behaviour

### Account status

Protected accounts have lifecycle states such as `ACTIVE`, `LOCKED`, `REVOKED` and `REMOVED`. Security-sensitive state transitions invalidate related trusted/temporary security state as appropriate.

### Database

SQLite access is serialized through the plugin's database executor. The verification state machine uses atomic state transitions so concurrent approval/rejection attempts cannot process the same pending session twice.

### Audit

Security-sensitive commands and operations can be recorded in the command/security audit pipeline. Sensitive values must remain redacted.

### Fail closed

Examples that should deny a protected login rather than silently allow it:

- security backend is not ready;
- required account/security state cannot be safely loaded;
- managed security block is active;
- client IP cannot be resolved safely;
- verification cannot be created safely;
- an unexpected security exception occurs.

The player-facing message is intentionally less detailed than the console log so secrets and internal state are not disclosed to players.

## Console diagnostics

On a correct startup, the console should make it clear which major subsystems are ready, including the security backend and (when enabled) Discord verification.

When configuration is invalid, the plugin should identify the specific configuration problem rather than only reporting a generic "security unavailable" message.

When a login is denied, the console should record a structured reason such as:

```text
[AUTH][DENY][SECURITY_STATE]
[AUTH][DENY][IP_RESOLUTION]
[AUTH][DENY][DATABASE_TIMEOUT]
[AUTH][DENY][VERIFICATION_CREATE]
[AUTH][DENY][DISCORD_UNAVAILABLE]
```

Never paste real bot tokens, server secrets, RCON passwords or other credentials into issue reports.

## Discord logging

The plugin uses JDA for Discord verification. JDA interactions that may require database/business logic are acknowledged before long-running work so the interaction does not expire before a response is sent.

The project avoids relying on JDA's fallback logger when a proper SLF4J runtime provider is available.

## Development

Clone the repository:

```bash
git clone git@github.com:AnDepChai/AP-StaffGuard.git
cd AP-StaffGuard
```

Check the working tree:

```bash
git status
git log -1 --oneline
```

Run tests/build:

```bash
mvn clean test
mvn clean package
```

Built artifacts are normally placed in:

```text
target/
```

## Git workflow used for this project

Normal code update:

```bash
git status
git add .
git commit -m "fix: describe the change"
git pull --rebase origin main
git push
```

Create a release tag only after CI is green:

```bash
git tag v1.1.3
git push origin v1.1.3
```

If the repository workflow creates Releases from version tags, the tag push triggers the release build.

## Repository tree

The detailed source tree is maintained in [`PROJECT-TREE.txt`](PROJECT-TREE.txt).

## Security reporting

Do not publish exploitable details together with live secrets or credentials. For a private security report, include the plugin version, exact reproduction steps, relevant sanitized logs and the affected source class/method.

## License

Review the repository's declared license before redistributing the plugin or its bundled dependencies.
