#!/bin/bash

if (( $EUID != 0 )); then
	echo "Please run as root"
	exit
fi

#SRC_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo -n 'Getting chain ID: '
CHAIN_ID=`sudo -u geth geth attach --exec 'Number(eth.chainId())'`
if [ $? -ne 0 ] || [ $CHAIN_ID = 'NaN' ]; then
	echo Failed!
	exit
fi
echo $CHAIN_ID

echo -n 'Determining chain name: '
case $CHAIN_ID in

	116111110106)
		CHAIN_NAME='tcoin-tnet'
		;;

	116111110107)
		CHAIN_NAME='tcoin-l2-tnet'
		;;

	116111110101)
		CHAIN_NAME='tcoin-mnet'
		;;

	116111110102)
		CHAIN_NAME='tcoin-l2-mnet'
		;;

	10298105116)
		CHAIN_NAME='fbchain-mnet'
		;;

	949394939493)
		CHAIN_NAME='testchain-tnet'
		;;

	10311497112101)
		CHAIN_NAME='grape-mnet'
		;;

	949394939494)
		CHAIN_NAME='testchain2-tnet'
		;;

	949394939496)
		CHAIN_NAME='testchain2-l2-tnet'
		;;

	949394939495)
		CHAIN_NAME='white_tnet'
		;;

	*)
		echo Failed!
		exit
esac
echo $CHAIN_NAME

echo -n 'Getting block number: '
BLOCK_NUM=`sudo -u geth geth attach --exec 'eth.blockNumber'`
if [ $? -ne 0 ] || [ $BLOCK_NUM = 'undefined' ]; then
	echo Failed!
	exit
fi
echo $BLOCK_NUM

echo -n 'Stopping geth service: '
systemctl stop geth
if [ $? -ne 0 ]; then
	echo Failed!
	exit
fi
echo OK

BACKUP_FILE="${CHAIN_NAME}-blockchain-${BLOCK_NUM}.backup"
BACKUP_TMP="/tmp/${BACKUP_FILE}"
echo "Exporting blockchain to ${BACKUP_TMP}..."
sudo -u geth geth export $BACKUP_TMP
if [ $? -ne 0 ]; then
	echo Failed!
	exit
fi

echo -n 'Starting geth service: '
systemctl start geth
if [ $? -ne 0 ]; then
	echo Failed!
	exit
fi
echo OK

BACKUP_DST="./${BACKUP_FILE}"
echo -n "Moving ${BACKUP_TMP} to ${BACKUP_DST}: "
mv $BACKUP_TMP $BACKUP_DST
if [ $? -ne 0 ]; then
	echo Failed!
	exit
fi
echo OK

LOGNAME=`logname`
echo -n "Changin file owner to ${LOGNAME}:${LOGNAME}: "
chown ${LOGNAME}:${LOGNAME} ${BACKUP_DST}
if [ $? -ne 0 ]; then
	echo Failed!
	exit
fi
echo OK
