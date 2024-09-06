# !/bin/sh

N3_UPF_IP="192.168.101.2"
N6_UPF_IP="192.168.102.2"

N3_TREX_IP="192.168.101.3"
N6_TREX_IP="192.168.102.3"

N3_BRIDGE_MAC="52:54:00:e6:c5:a2"
N6_BRIDGE_MAC="52:54:00:a2:5c:ac"


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
# getMapId(){
#     local id
#     id=$(sudo bpftool map list | awk '{if($4 == "m_arp_table") print $1}'| cut -f1 -d":")
#     echo $id
# }



getMapId() {
    local ids=()
    
    # Use map command to get a list of map IDs and store them in the array
    while IFS= read -r id; do
        ids+=("$id")
    done < <(sudo bpftool map list | awk '{if($4 == "m_arp_table") print $1}' | cut -f1 -d":")
    
    # Return the array
    echo "${ids[@]}"
}

#---------------------------------------------------------------------------#
#---------------------------------------------------------------------------#
#---------------------------------------------------------------------------#
main(){
    set -o errexit
    set -o pipefail
    #set -o nounset

    # IP Conversions:
    N3_UPF_IP=$( iphex2str $(ip2dec2hex $N3_UPF_IP) )
    N6_UPF_IP=$( iphex2str $(ip2dec2hex $N6_UPF_IP) )

    N3_TREX_IP=$( iphex2str $(ip2dec2hex $N3_TREX_IP) )
    N6_TREX_IP=$( iphex2str $(ip2dec2hex $N6_TREX_IP) )

    # MAC Conversions:
    N3_BRIDGE_MAC=$( mac2hex $N3_BRIDGE_MAC )
    N6_BRIDGE_MAC=$( mac2hex $N6_BRIDGE_MAC )

    echo "N3_UPF_IP = $N3_UPF_IP"
    echo "N6_UPF_IP = $N6_UPF_IP"
    echo "N3_BRIDGE_MAC = $N3_BRIDGE_MAC"
    echo "N6_BRIDGE_MAC = $N6_BRIDGE_MAC"

    # Call the function to get an array of map IDs
    mapIds=($(getMapId))

    # Check if the array is not empty
    if [ "${#mapIds[@]}" -gt 0 ]; then
        echo "ARP Table Map IDs: ${mapIds[@]}"
        
        # Iterate through the array and use the values
        for id in "${mapIds[@]}"; do
            echo " - $id"
            
            # Update mac map:
            sudo bpftool map update id $id key hex $N3_UPF_IP value hex $N3_BRIDGE_MAC 00 00 $N3_TREX_IP
            sudo bpftool map update id $id key hex $N6_UPF_IP value hex $N6_BRIDGE_MAC 00 00 $N6_TREX_IP

            sudo bpftool map dump id $id

        done
    else
        echo "No map IDs found."
    fi

    exit 0
}

main