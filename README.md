iolimit
=======

The utility sends SIGSTOP and SIGCONT signals to control disk IO load on systems with disabled io scheduler (it may be useful for iSCSI initiators).

At the moment the utility just tries to permit about 1 "disk sleeping" (writting/reading) idle (@ionice -c 3@) process.

Side effect: the daemon can send CONT signal to process stopped by somebody else.
