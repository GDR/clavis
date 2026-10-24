# Personal/Bot routing and migration

Clavis uses `~/.ssh/clavis.sock` as its primary endpoint.
It handles Personal and Bot keys through the same protocol.
The socket chooses where a request goes; it does not identify the application.

## Keys and applications

Key type and operations are independent:

| Application classification | Personal key | Bot key |
| --- | --- | --- |
| Personal | Eligible | Eligible |
| Bot | Denied | Eligible |
| Block | Denied | Denied |
| Uncertain identity | Authenticated once | Authenticated once |

Eligibility also requires the requested operation to be enabled.
SSH and Signature switches do not change key type.
Changing key type preserves disabled operations.
Changing classification or key policy requires fresh authentication.
Existing approvals are invalidated when policy changes.

Clavis does not replace a key requested by the client with another key.
Configure the requested SSH identity or Git signing key explicitly.
An unknown identity is never silently treated as Personal because it has a terminal ancestor.
Uncertain callers cannot create remembered classification or cached approvals.
They must authenticate each request.

## SSH configuration without a launcher

Use the primary socket directly in the appropriate SSH config:

```sshconfig
Host github.com
    IdentityAgent ~/.ssh/clavis.sock
    IdentitiesOnly yes
    IdentityFile ~/.ssh/clavis/project.pub
```

The identity file contains the public key, not an exported private key.
Its public key must match the intended Clavis key.
A separate bot configuration can use the same endpoint:

```sh
ssh -F ~/.ssh/config_bot git@github.com
```

Using another config file does not itself prove that a request came from a bot.
Clavis still evaluates the verified caller and key policy.
For Git, select SSH signing and the intended public signing key in repository configuration.
A Nix shell or direnv can select configuration, but its environment is routing information.
It is not a source of Personal authority.

## Compatibility endpoint

`~/.ssh/clavis-agent.sock` remains a restricted compatibility endpoint.
It rejects Personal keys even for Personal-classified applications.
New Bot profiles can use enabled SSH or Signature operations there.
Legacy agent records retain their existing session and operation restrictions.
The compatibility endpoint rejects control requests, forwarding, and failed session bindings.
New configurations should use `clavis.sock`.

## Pause and resume

The kill switch revokes approvals and persistently pauses new requests.
Both endpoints reject enumeration and signing while paused.
Resuming requires fresh authentication and never restores revoked approvals.
Revocation cannot close an SSH connection that has already authenticated.

These policies do not provide strong isolation from hostile processes running as the same user.
Application labels, environment variables, and socket paths are not a sandbox boundary.

## Revocation during a request

A request captures both the current application-registry revision and a key-policy generation.
Clavis checks them again before returning a signature.
Changing a key's policy invalidates its previous generation on both listeners.
Changing Personal to Bot and then back to Personal does not revive the original request.
Disabling an operation and enabling it again also does not revive an old approval.
The application must submit a fresh request and satisfy the current policy.

A key rename retains the same fingerprint and private material.
Revocation still invalidates requests that began under the old label.
The old public-index entry does not need to remain present for that invalidation.

Generations are local to the running daemon.
They are shared between primary and compatibility sockets.
A daemon restart ends pending requests and cached grants; old generations cannot be reused.
Application classifications and kill-switch state remain persistent across restarts.

Only the trusted control path can revoke a key's generation.
An untrusted signing client cannot manipulate generations through a control opcode.
