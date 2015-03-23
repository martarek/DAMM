#!/bin/bash
dbFile="$1"
plugin="$2"
linuxplugin="linux_$plugin"
linuxpluginfullname="linux${plugin}_Linux${plugin^}Set"
echo $linuxpluginfullname

sqlite3 $dbFile	"ALTER TABLE '$linuxplugin' RENAME TO $linuxpluginfullname";


