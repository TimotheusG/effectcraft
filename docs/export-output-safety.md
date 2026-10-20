# Export output lifetime

Disk exports encode into job-owned staging on the destination filesystem. Existing
outputs are untouched until all encoding succeeds. A cancelled, failed, or abandoned
job removes its staging, never a final output selected by its filename. Browser
sinks retain per-file delivery, and render logs retain their separate behavior.

Publication replaces one complete file at a time. A sequence is **not** an atomic
transaction: if publication of a later frame fails, previously published complete
frames remain. Staging needs enough free space for the new export alongside the
old export. This provides error/cancellation safety, not a power-loss durability
guarantee or automatic recovery of staging left by a terminated process.

## Access policy

Before receiving media, staging is restricted to its owner. An empty, separate
probe checks that the intended output policy can be reproduced. That probe never
receives media, so a reader retaining its handle cannot later read export bytes.
New outputs use ordinary creation permissions, including umask and directory
inheritance. Existing outputs retain owner, group, mode/access controls supported
by the platform adapter; errors preserve the old output instead of weakening access.

- Windows creates staging with a protected, empty DACL, then grants its owner
  access before reopening for encoding. Staging stays beside the destination so
  publication can restore inherited as well as protected DACLs. The adapter checks
  owner, group, DACL, integrity/resource access metadata and readonly state.
- Linux preserves numeric ownership, permission bits, and security/system xattrs,
  including POSIX access ACLs. A setgid directory cannot silently change the owner
  group of an existing output. No libacl dependency is added on Linux.
- macOS uses an empty private staging directory with its inherited ACL cleared
  before creating the media file, because ACL grants can override ordinary mode
  bits. Native ACL entries are restored along with ownership and mode.
- FreeBSD uses the native ACL adapter and an owner-only POSIX staging-directory
  ACL. Filesystem policies the adapter cannot reproduce are rejected; unsupported
  ACL/filesystem combinations must not silently fall back to chmod alone.

Privilege-bearing files (setuid/setgid/sticky file modes or Linux file capabilities)
are not export replacement targets. This change preserves access policy, not all
arbitrary filesystem metadata such as user tags or alternate data streams.

## Links and concurrent changes

Leaf symbolic links are resolved with a bound of 40 links. Relative and dangling
links target their referenced filename; the link itself is retained. Directory
links are resolved by the filesystem. Files with multiple hard links are rejected
because replacing their inode would silently disconnect the other aliases.

The destination identity, length, modification time, access policy, resolved target,
and parent access policy are checked again before publication. Changed destinations
cause an error. Jobs in one process serialize their final validation/replacement.
New destinations are published with a no-clobber hard link, so an intervening creator
cannot be overwritten. This requires a filesystem that supports hard links.

External writers must cooperate. Portable rename does not provide compare-and-swap
against a file version, so there remains a race between the final check and replacing
an existing destination. This is not protection against arbitrary concurrent changes
by another process with authority to modify the output directory or its security
policy. Use separate output paths for independent processes.

## Tests

The native tests cover the staging lifecycle, competing jobs, policy changes,
failed publication, hard-link rejection, symlink targets, and platform ACL behavior.
Linux includes a named-user ACL and a differing-group setgid case when run as root.
The export integration tests cancel after writing begins and compare successful
movie/sequence output against sink bytes. The filesystem workflow runs these on
Windows, Linux and macOS. Local cross-compilation alone is not runtime validation.
