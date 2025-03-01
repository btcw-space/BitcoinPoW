26.4.7 Release Notes (BTCW)
==================

Bitcoin PoW Core version 26.4.7 is now available from:

  <https://github.com/bitcoin-pow/BitcoinPoW/releases>

This release includes new bug fixes.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/bitcoin-pow/BitcoinPoW/issues>

To receive security and update notifications, please subscribe to:

  <https://bitcoincore.org/en/list/announcements/join/>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes in some cases), then run the
installer (on Windows) or just copy over `/Applications/Bitcoin-pow-Qt` (on macOS)
or `bitcoin-powd`/`bitcoin-pow-qt` (on Linux).

Upgrading directly from a version of Bitcoin Core that has reached its EOL is
possible, but it might take some time if the data directory needs to be migrated. Old
wallet versions of Bitcoin Core are generally supported.

Compatibility
==============

Bitcoin Core is supported and extensively tested on operating systems
using the Linux kernel, macOS 11.0+, and Windows 7 and newer.  Bitcoin
Core should also work on most other Unix-like systems but is not as
frequently tested on them.  It is not recommended to use Bitcoin Core on
unsupported systems.

Notable changes
===============
When miners sent their entire balance to another wallet and the mining wallet balance became ZERO; the mining failed to get into stage2. 
This happened with the introduction of hiding dust txs in version 26.4.6. The following lines of code below would force a return 
from entering stage2 mining because the check would fail.

if (nCredit == 0 || nCredit > nBalance)
    return false;

The solution was to delete the above lines of code. We get the balance from the previous output and the validation code will check 
for sufficient balance anyway, no need for that check on the mining side.


Pull requests resolved in this release:
https://github.com/bitcoin-pow/BitcoinPoW/pull/73 - some reports of not getting out of stage1 on latest release


```

Credits
=======

Thanks to everyone who directly contributed to this release:

- FluffyFunction
- skylovelian

As well as to everyone that helped with translations on
[Transifex](https://www.transifex.com/bitcoin/bitcoin/).
