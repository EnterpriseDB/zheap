Zheap Part I: Undo Log Storage

This branch is maintained by a robot.  It is automatically filtered and
combined from the commit history in the zheap-tmunro branch at
at https://github.com/EnterpriseDB/zheap into a more presentable form.
It's a preview of the lowest level patch-set in the Zheap proposal.
It's work in progress.

There are five patches in this patch set:

* [0001-Add-undo-log-manager.patch](../../commit/417481eaf562a36808cc7dbdbffbdef0361eff4f)
* [0002-Provide-access-to-undo-log-data-via-the-buffer-manager.patch](../../commit/88ce7dcbf20f243649aea1bd0ca3f42c7e0cc129)
* [0003-Add-developer-documentation-for-the-undo-log-manager.patch](../../commit/0c741fec6ffa4e69436a7e38dabc85b388477297)
* [0004-Add-tests-for-the-undo-log-manager.patch](../../commit/5d44b81eab636cb7f002704ca685af8a2800024b)
* [0005-Add-user-facing-documentation-for-undo-logs.patch](../../commit/892e5202b1c45a3f2032d4bef671413268738348)

This branch is automatically tested by:

* Ubuntu build bot over at Travis CI:  [<img src="https://travis-ci.org/macdice/postgres.svg?branch=undo-log-storage"/>](https://travis-ci.org/macdice/postgres/branches)
* Windows build bot over at AppVeyor: [<img src="https://ci.appveyor.com/api/projects/status/github/macdice?branch=undo-log-storage&svg=true"/>](https://ci.appveyor.com/project/macdice/postgres/branch/undo-log-storage)

