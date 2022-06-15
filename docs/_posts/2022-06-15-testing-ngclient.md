---
title: "Testing Tricky Edge Cases in a TUF Client"
author: Ivana Atanasova
---

Usually the TUF Specification creates an impression of simple and straightforward approach to address software update systems security gaps. In the next few paragraphs we'll try to convince you that the devil is in the details.

With the [v1.0.0 release](https://blogs.vmware.com/opensource/2022/02/22/python-tuf-reaches-version-1-0-0/) we can say that the current reference implementation is finally in a good place, although it wouldn’t be so trustworthy without all the awesome test functionality it provides. Therein lies some interesting surprises, for the conformance tests reflect use cases and tricky details that wouldn’t easily come to mind. TUF, in fact, is capable of managing some tricky business!

Before looking into them, let’s first introduce the test functionality itself.

## Some repository simulator magic

The test suite is heavily based on [RepositorySimulator](https://github.com/theupdateframework/python-tuf/blob/develop/tests/repository_simulator.py), which allows you to play with repository metadata by modifying it, signing and storing new roles versions, while serving older ones in the client test code. You can also simulate downloading new metadata from a remote without the need of file access or network connections, and modify expiry dates and time.

Even though `RepositorySimulator` hosts repos purely in memory, you can supply the `--dump` flag to write its contents to a temporary directory on the local filesystem with "/metadata/..." and "/targets/..." URL paths that host metadata and targets respectively in order to audit the metadata. The test suite provides you with the ability to see the "live" test repository state for debugging purposes.

Let’s cite a specific example with testing expired metadata to demonstrate the cool thing the `RepositorySimulator` provides, i.e. the capability to simulate real repository chains of updates as suggested by the spec, and not just modify individual metadata.

More specifically, we would like to simulate a workflow in which a [targets](https://theupdateframework.github.io/specification/latest/#targets) version is being increased and a [timestamp](https://theupdateframework.github.io/specification/latest/#timestamp) expiry date is being changed. We are going to elaborate below on how this can be used to test the `Updater` above all programmatically. Now, let's just focus on how to verify that the `RepositorySimulator` did what we expected.

Let's assume we did the following:
* Upgraded `targets` to v2
* Changed `timestamp` v2 expiry date

We can verify that the metadata looks as expected, without the need to implement file access.

First, we need to find the corresponding temporary directory:
```
$ python3 test_updater_top_level_update.py TestRefresh.test_expired_metadata --dump
Repository Simulator dumps in /var/folders/pr/b0xyysh907s7mvs3wxv7vvb80000gp/T/tmpzvr5xah_
```

Once we know it, we can verify that the metadata has 2 cached versions:

```
$ tree /var/folders/pr/b0xyysh907s7mvs3wxv7vvb80000gp/T/tmpzvr5xah_/test_expired_metadata
/var/folders/pr/b0xyysh907s7mvs3wxv7vvb80000gp/T/tmpzvr5xah_/test_expired_metadata
├── 1
│   ├── 1.root.json
│   ├── snapshot.json
│   ├── targets.json
│   └── timestamp.json
└── 2
    ├── 2.root.json
    ├── snapshot.json
    ├── targets.json
    └── timestamp.json
```

And now we can also see that after bumping the version and moving timestamp v2 expiry date two weeks forward from v1, the v2 corresponding timestamp metadata has recorded that expiry date correctly:

Timestamp v1:
<pre><code>$ cat /var/folders/pr/b0xyysh907s7mvs3wxv7vvb80000gp/T/tmpzvr5xah_/test_expired_metadata/1/timestamp.json 
{
 "signatures": [{...}],
 "signed": {
  "_type": "timestamp",
  <b>"expires": "2022-03-30T00:18:31Z"</b>,
  "meta": { "snapshot.json": {"version": 1}},
  "spec_version": "1.0.28",
  "version": 1
 }}
</code></pre>

Timestamp v2:

<pre><code>$ cat /var/folders/pr/b0xyysh907s7mvs3wxv7vvb80000gp/T/tmpzvr5xah_/test_expired_metadata/2/timestamp.json 
{
 "signatures": [{...}],
 "signed": {
  "_type": "timestamp",
  <b>"expires": "2022-04-13T00:18:31Z"</b>,
  "meta": { "snapshot.json": {"version": 2}},
  "spec_version": "1.0.28",
  "version": 2
 }}
</code></pre>

As you can see, the first date is 30 Mar and the second - 13 Apr, which is exactly 14 days later. This is a great way to observe what the tests really do and check if they do it successfully.

## When we talk about security, edge cases are the norm

Now, let’s take a closer look at two edge cases, using in this test the cool things the RepositorySimulator provides:

### Example with expired metadata:

Imagine that we have performed an update and stored metadata in a cache. And the locally stored timestamp/snapshot has expired. But we still need it to perform an update from remote by verifying the signatures and we need to use the expired timestamp.

We can play with versions and expiry to verify that this scenario not explicitly mentioned in the spec works correctly and safely. By using the simulator, we can do the following:
1. Set the timestamp expiry one week ahead (to day 7)
2. On the very first day (day 0) download, verify, and load metadata for the [top-level roles](https://theupdateframework.github.io/specification/latest/#roles-and-pki) following the TUF specification order. This is done by simply calling `updater.refresh()`.
3. Then we bump [snapshot](https://theupdateframework.github.io/specification/latest/#update-snapshot) and [targets](https://theupdateframework.github.io/specification/latest/#targets) versions to v2 in the repository on the same day (day 0)
4. Set v2 expiry dates three weeks ahead (to day 21)
5. Travel in time somewhere between day 7 and day 21
6. Perform a successful `refresh` (with `updater.refresh()` call) with the expired locally cached timestamp
7. Check that the final repository version of the snapshot and targets roles is v2.

This is a not so obvious use-case to keep in mind when thinking about updates. You can see how it looks in practice in the [reference implementation](https://github.com/theupdateframework/python-tuf/blob/develop/tests/test_updater_top_level_update.py#:~:text=test_expired_metadata).

### Example rollback protection check with expired metadata:

Now let’s see if a rollback attack protection can be performed when the local timestamp has expired. In this case we need at least two timestamp and snapshot versions, an expired older version of timestamp, and a verification that a rollback check is performed with the old version.

For a timestamp rollback, the case is pretty similar to the use of expired metadata. We can do the following:
1. Set timestamp v1 expiry one week ahead (to day 7)
2. Perform `updater.refresh()` on the very first day
3. Publish timestamp v2 in the repository with expiry three weeks ahead (to day 21)
4. Perform `updater.refresh()` somewhere between day 7 and day 21
5. Verify that rollback check uses the expired timestamp v1. (For reference, see the implementation [example](https://github.com/theupdateframework/python-tuf/blob/develop/tests/test_updater_top_level_update.py#:~:text=test_expired_timestamp_version_rollback)).

A similar approach can be used when testing both timestamp and snapshot rollback protection. We just need to guarantee that after the last snapshot update, the snapshot version is not the latest in order to verify a rollback check is performed both with expired timestamp and an older snapshot. Sounds complicated, but it’s pretty easy with the simulator and [this example](https://github.com/theupdateframework/python-tuf/blob/develop/tests/test_updater_top_level_update.py#:~:text=test_expired_timestamp_snapshot_rollback) illustrates it pretty well. 


## The devil is in the details

One of the great things about a reference implementation is that one can learn a lot about the TUF specification by looking at the tests, which are full of examples that would hardly come to mind when you read the abstract straightforward workflow explained in the spec. And those tests most likely do not cover everything… 

Do you have a comment about the TUF spec or the cited examples? An idea? Please share it with us!

