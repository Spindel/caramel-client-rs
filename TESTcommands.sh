#! /bin/bash

UUID=9d391ecc-37f5-4a0b-8c7d-7457ef659149
SERVER=ca.sommar.modio.se

LOGFILE=TESTcommands.log


echo "#### No caramel files" > $LOGFILE
rm -f *.crt *.csr *.key *.cacert ; cargo run $SERVER $UUID >>  $LOGFILE 2>&1

echo "#### All caramel files" >> $LOGFILE
cargo run $SERVER $UUID >>  $LOGFILE 2>&1

echo "#### Missing private key file" >> $LOGFILE
rm -f *.key ; cargo run $SERVER $UUID >>  $LOGFILE 2>&1

echo "#### Missing cacert file" >> $LOGFILE
rm -f *.cacert ; cargo run $SERVER $UUID >>  $LOGFILE 2>&1

echo "#### Missing crt file" >> $LOGFILE
rm -f *.crt ; cargo run $SERVER $UUID >>  $LOGFILE 2>&1

echo "#### Missing csr file" >> $LOGFILE
rm -f *.csr ; cargo run $SERVER $UUID >>  $LOGFILE 2>&1

echo "#### Missing csr file" >> $LOGFILE
rm -f *.csr ; cargo run $SERVER $UUID >>  $LOGFILE 2>&1