# MLS chat v2 device profiles

A profile is a separate local device. Configuration, account sessions, SQLCipher databases, content-encryption keys, MLS keys, and operating-system keychain entries are isolated from every other profile. Omitting `--profile` keeps the existing CLI installation and keychain names.

Use names containing 1–64 ASCII letters, numbers, hyphens, or underscores. On macOS, profile files live in `~/Library/Application Support/catmos-cli/profiles/NAME/`. Linux uses the corresponding configuration and data directories. `CATMOS_PROFILE` supplies a default when `--profile` is omitted.

Do not copy another profile's database or keys to enroll a device. Log in separately so each profile creates an independent device identity. App passwords are entered at the prompt, never as command-line arguments.

```sh
./target/debug/catmos --profile alice-phone login alice.example --app-password
./target/debug/catmos --profile alice-laptop login alice.example --app-password
./target/debug/catmos --profile bob-phone login bob.example --app-password
```

Finish secure-chat enrollment with `device register`. Registering a device and publishing the account's delivery-service declaration are both required before others can reach the account. Repeating explicit enrollment preserves an existing incoming-message consent policy and refuses to silently move an account to another delivery service.

```sh
./target/debug/catmos --profile alice-phone --no-startup-sync device register
./target/debug/catmos --profile alice-laptop --no-startup-sync device register
./target/debug/catmos --profile bob-phone --no-startup-sync device register
```

Normal CLI startup runs shared Rust synchronization, including device recovery and pending membership operations. For focused tests, `--no-startup-sync` skips whole-account recovery and block reconciliation. It still reads the conversation inventory; the chosen command can modify its target conversation. This option is available for CLI commands, not the interactive TUI.

Conversation commands accept a stable conversation UUID, a unique name, an alias, or an unambiguous ID prefix. Output uses the stable conversation UUID, which survives replacement of the underlying MLS group. Ambiguous names and prefixes fail instead of selecting an arbitrary chat.

```sh
./target/debug/catmos --profile alice-phone --no-startup-sync convo create Example --members did:plc:BOB
./target/debug/catmos --profile bob-phone --no-startup-sync convo accept CONVERSATION_UUID
./target/debug/catmos --profile alice-phone --no-startup-sync convo fulfill CONVERSATION_UUID
./target/debug/catmos --profile bob-phone --no-startup-sync convo join CONVERSATION_UUID
./target/debug/catmos --profile alice-phone --no-startup-sync send CONVERSATION_UUID 'Hello'
./target/debug/catmos --profile bob-phone --no-startup-sync messages CONVERSATION_UUID
```

On an additional device, `convo request-recovery CONVERSATION_UUID` requests a fresh device membership when necessary. Recovery that is waiting on another device returns an error rather than claiming the conversation is ready; an already active member can fulfill the request using `convo fulfill`. Then retry `convo join` on the new device. No old message history is promised to a newly admitted device.

`convo leave` uses the shared conversation lifecycle. Direct conversations close through the server even when the local MLS group is missing. A group leave can report that removal is pending; local state remains until another member commits the removal. Use `convo fulfill-leave CONVERSATION_UUID` on another active member's device to complete a pending group leave in a focused test. Failed leave requests remain errors. Message fetch failures are also reported directly rather than shown as an empty conversation.

Build and sign with `./build-cli.sh` on macOS to keep the stable development signature used by keychain access. Existing TUI setup and some ancillary CLI operations still use older adapters; this profile workflow validates the explicit conversation, device, and recovery commands rather than full client parity.
