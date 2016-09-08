```
            __
           /\ \__
 _ __   __ \ \ ,_\   ___   __  _
/\`'__/'__`\\ \ \/  / __`\/\ \/'\
\ \ \/\ \L\.\\ \ \_/\ \L\ \/>  </
 \ \_\ \__/.\_\ \__\ \____//\_/\_\
  \/_/\/__/\/_/\/__/\/___/ \//\/_/
                                   -- by sin and FRIGN
======================================================
```

What is it?
===========

ratox is a client implementation of the rather popular tox protocol[0].
Unlike other clients relying on GUIs as an interface to the user, ratox is
developed with the UNIX-philosophy in mind and allows complete
interaction through named pipes.

There's also a set of scripts[1] developed by various people that build on
top of the FIFO interface.


Getting started
===============

Get the latest version from the git-repository; build and install it.
Run ratox in an empty directory and it will create a set of files and
folders allowing you to control the client.


File structure
==============

A typical filesystem structure is shown below along with some comments
to help explain the semantics of the individual files.

```
.
|-- .ratox.data			# ratox save file
|
|-- 0A734CBA717CEB7883D....	# friend's ID excluding nospam + checksum
|   |-- call_in			# 'arecord -r 48000 -c 1 -f S16_LE > call_in' to initiate a call
|   |-- call_out		# 'aplay -r 48000 -c 1 -f S16_LE - < call_out' to answer a call
|   |-- call_state		# (none, pending, active)
|   |-- file_in			# 'cat foo > file_in' to send a file
|   |-- file_out		# 'cat file_out > bar' to receive a file
|   |-- file_pending		# contains filename if transfer pending, empty otherwise
|   |-- name			# friend's nickname
|   |-- online			# 1 if friend online, 0 otherwise
|   |-- remove			# 'echo 1 > remove' to remove a friend
|   |-- state			# friend's user state; could be any of {none,away,busy}
|   |-- status			# friend's status message
|   |-- text_in			# 'echo yo dude > text_in' to send a text to this friend
|   `-- text_out		# 'tail -f text_out' to dump to stdout any text received
|
|-- id				# 'cat id' to show your own ID, you can give this to your friends
|
|-- name			# changing your nick
|   |-- err			# nickname related errors
|   |-- in			# 'echo my-new-nick > in' to change your name
|   `-- out			# 'cat out' to show your name
|
|-- nospam			# changing your nospam
|   |-- err			# nospam related errors
|   |-- in			# 'echo AABBCCDD > in' to change your nospam
|   `-- out			# 'cat out' to show your nospam
|
|-- request			# send and accept friend requests
|   |-- err			# request related errors
|   |-- in			# 'echo LONGASSID yo dude add me > in' to send a friend request
|   `-- out			# 'echo 1 > out/LONGASSID' to accept the friend request
|
|-- state			# changing your user state
|   |-- err			# user status related errors
|   |-- in			# 'echo away > in' to change your user state; could be any of {none,away,busy}
|   `-- out			# 'cat out' to show your user state
|
`-- status			# changing your status message
    |-- err			# status message related errors
    |-- in			# 'cat I am bored to death > in' to change your status message
    `-- out			# 'cat out' to show your status message
```

Features
========
```
1 v 1 messaging: Yes
File transfer: Yes
Group chat: No
Audio: Yes
Video: No
DNS discovery: No
Chat logs: Yes
Proxy support: Yes
Offline message: Yes
Offline transfers: Yes
Contact aliases: No
Contact blocking: No
Save file encryption: Yes
Multilingual: No
Multiprofile: Yes
Typing notification: No
Audio notifications: No
Emoticons: No
Spell check: No
Desktop sharing: No
Inline images: No
File resuming: No
Read receipts: No
Message splitting: Yes
Changing nospam: Yes
toxi URI: No

NOTE: Some of these features are not intended to be developed
in ratox itself but rather in external scripts[1] that are built upon
ratox.
```

Examples
========

SSH over TOX for the practical paranoid
---------------------------------------

On the sender side (the client):
1) cd into the friend's directory (the server)
2) nc -lv 1234 > file_in < file_out

On the receiver side (the server):
1) cd into the friend's directory (the client)
2) cat < file_out | nc localhost 22 > file_in

Now on the client run the following:
ssh -o ProxyCommand="nc %h 1234" user@localhost

Screencasting using ffmpeg and mplayer
--------------------------------------

On the sender side:
ffmpeg -f x11grab -r 10 -s 1366x768 -i :0.0 -vcodec libx264 \
	-pix_fmt yuv420p -preset fast -tune zerolatency -b:v 500k \
	-f flv pipe: > file_in

On the receiver side:
mplayer -cache 1024 file_out

You may have to play about with the cache size.


Portability
===========

Builds and works on *BSD and Linux.  To build on OSX you need
to apply a patch[2].


Contact
=======

You can reach us through the freenode IRC network at #2f30 or
through tech@lists.2f30.org.

[0] https://tox.chat/
[1] http://git.2f30.org/ratox-nuggets/
[2] http://ratox.2f30.org/ratox-os_x.patch
