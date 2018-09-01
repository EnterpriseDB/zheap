Zheap Part I: Undo Log Storage

This branch is maintained by a robot.  It is automatically filtered and
combined from the commit history in the zheap-tmunro branch at
at https://github.com/EnterpriseDB/zheap into a more presentable form.
It's a preview of the lowest level patch-set in the Zheap proposal.
It's work in progress.

There are five patches in this patch set:

* [0001-Add-undo-log-manager.patch](../../commit/49fc10c94f3f3a2390586607307fbae94e4543a3)
* [0002-Provide-access-to-undo-log-data-via-the-buffer-manager.patch](../../commit/2bb795bdb71ac9ec89590d540f5721586ddbbbc0)
* [0003-Add-developer-documentation-for-the-undo-log-manager.patch](../../commit/203041219d799fb9e50b74ead103c4fc4bc56d1a)
* [0004-Add-tests-for-the-undo-log-manager.patch](../../commit/c2ed984e45af57fc2a18cec743ae7b3f0ececb23)
* [0005-Add-user-facing-documentation-for-undo-logs.patch](../../commit/85133a3601878714d8278de41fae66bc314f76cb)

This branch is automatically tested by:

* Ubuntu build bot over at Travis CI:  [<img src="https://travis-ci.org/macdice/postgres.svg?branch=undo-log-storage-v2"/>](https://travis-ci.org/macdice/postgres/branches)
* Windows build bot over at AppVeyor: [<img src="https://ci.appveyor.com/api/projects/status/github/macdice/postgres?branch=undo-log-storage-v2&svg=true"/>](https://ci.appveyor.com/project/macdice/postgres/branch/undo-log-storage-v2)

