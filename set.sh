oldname=$1
newname=$2
ifconfig $oldname down
ip link set $oldname name $newname
ifconfig $newname down
iwconfig $newname mode monitor
ifconfig $newname up
