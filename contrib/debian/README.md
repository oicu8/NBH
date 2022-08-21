
Debian
====================
This directory contains files used to package ntrnbhd/ntrnbh-qt
for Debian-based Linux systems. If you compile ntrnbhd/ntrnbh-qt yourself, there are some useful files here.

## ntrnbh: URI support ##


ntrnbh-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install ntrnbh-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your ntrnbh-qt binary to `/usr/bin`
and the `../../share/pixmaps/ntrnbh128.png` to `/usr/share/pixmaps`

ntrnbh-qt.protocol (KDE)

