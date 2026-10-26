# secrets

A Go package that finds the secrets a program is given -- an API key, an OAuth
application's client secret -- wherever its user keeps them, and keeps the ones
a program is handed itself, such as a login's token, in the safest place the
system offers.

fitactivity reads a Strava API application's credentials and keeps the login's
token with it; fitdash reads its map service key with it; course and fitdash
let their users set and list their secrets through
[cobrakit](https://github.com/wisborg/cobrakit)'s `secrets` command.

## Where secrets are looked for

A secret is known by a service and an item, `strava/client_secret`, and looked
for in a `Chain` of sources in turn. A program typically gives it:

1. **The environment**, `Env`: `$STRAVA_CLIENT_SECRET`.
2. **The system's keychain**, `Keychain`: the macOS Keychain, the Windows
   Credential Manager, or a Secret Service -- GNOME Keyring, KWallet -- on
   Linux. A secret is the item `client_secret` of the service
   `wisborg/strava` there.
3. **A file the user wrote**, `MappingFile`: a YAML or JSON mapping with the
   secret at a path of keys (`strava.client_secret`), or a file holding one
   secret as its whole text. It is only ever read.

A secret the program keeps itself goes where `Kept` says: the keychain where
one is used, a `File` of its own, for its owner alone, where not. One kept in
the file before the keychain was is moved into it the first time it is read.

## When the keychain is used

`$SECRETS_STORE` says:

| `SECRETS_STORE` | |
|---|---|
| unset | the keychain where the system has one that answers, files where not -- a server with no desktop session, an ssh login whose keychain is locked |
| `file` | never the keychain: files alone, read and kept |
| `keychain` | always the keychain, and an error where there is none |

On macOS the keychain is reached through `/usr/bin/security`, and a value is
handed to it on its standard input, never its command line, where any process
could read it. The Keychain then lets any program the user runs read the item
through the same tool without asking -- as any program of theirs can read a
file of theirs -- but it is kept encrypted, out of the files a backup or a
sync copies, and away from other users.

## What is never said

No error the package returns, and no description of where a secret is, holds a
secret's value. A file that is not a mapping is not reported with what the
parser made of it, since what it holds may be the secret; a mapping without
the secret is reported with the names it does have, which are not secrets.

## Tests

`MockKeychain` puts a keychain in memory in place of the system's for the rest
of the process, and every test here runs against one: none may reach the
user's own. A program's tests that make their own secrets set
`SECRETS_STORE=file`, or call `MockKeychain` too.

```
make gates      # gofmt, vet and test
make race
```

## License

Apache 2.0; see [LICENSE](LICENSE) and, for what it is built on,
[NOTICE](NOTICE).
