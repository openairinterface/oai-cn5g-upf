# !/bin/sh

KEY1="192.168.60.5"
KEY2="192.168.128.5"

VALUE1="52:54:00:5d:1a:93"
VALUE2="52:54:00:a8:13:72"
ID=0
#---------------------------------------------------------------------------#
ip2dec2hex () {
    local a b c d __ret_val ip=$@
    IFS=. read -r a b c d <<< "$ip"
    __ret_val="$((a * 256 ** 3 + b * 256 ** 2 + c * 256 + d))"
    echo "obase=16; $__ret_val" | bc
}

#---------------------------------------------------------------------------#
iphex2str(){
    local __ret_val len
    local val=$@ str=" " zero="0"
    len=${#val}
    if [ $len -eq 8 ]
    then 
        __ret_val="${val:0:2}$str${val:2:2}$str${val:4:2}$str${val:6:2}"
    elif [ $len -eq 7 ]
    then
        __ret_val="$zero${val:0:1}$str${val:1:2}$str${val:3:2}$str${val:5:2}"
    else
        echo The value is not correct!
    fi
    echo $__ret_val
}

#---------------------------------------------------------------------------#
mac2hex() {
    local __ret_val val=$@
    __ret_val=${val//:/" "}
    echo $__ret_val
}

#---------------------------------------------------------------------------#
getMapId(){
    local id
    id=$(sudo bpftool map list | awk '{if($4 == "m_arp_table") print $1}'| cut -f1 -d":")
    echo $id
}

#---------------------------------------------------------------------------#
#---------------------------------------------------------------------------#
#---------------------------------------------------------------------------#
main(){
set -o errexit
set -o pipefail
#set -o nounset

# GET MAP ID:
ID=$( getMapId )  

# IP Conversion:
KEY1=$( iphex2str $(ip2dec2hex $KEY1) )
KEY2=$( iphex2str $(ip2dec2hex $KEY2) )


# MAC Conversion:
 VALUE1=$( mac2hex $VALUE1 )
 VALUE2=$( mac2hex $VALUE2 )

 echo "KEY1 = $KEY1"
 echo "KEY2 = $KEY2"
 echo "VALUE1 = $VALUE1"
 echo "VALUE2 = $VALUE2"

# Update mac map:
sudo bpftool map update id $ID key hex $KEY1 value hex $VALUE1
sudo bpftool map update id $ID key hex $KEY2 value hex $VALUE2

sudo bpftool map dump id $ID

exit 0
}

main