# Linux daemon lessons

- On the tested Ubuntu 26.04 kernel, `IFLA_IFALIAS` supplied with WireGuard
  `RTM_NEWLINK` is ignored. Set and verify the owner alias with a separate
  `RTM_SETLINK`; keep an unresolved write-ahead journal entry if a crash occurs
  before ownership can be proven.
- Netlink rule dumps may represent a table above 255 with
  `RT_TABLE_COMPAT` and an absent suppression as
  `SuppressPrefixLen(u32::MAX)`. Normalize those equivalent values when
  checking ownership before deletion; retain `stale` journal entries when
  identity or cleanup cannot be proven.
