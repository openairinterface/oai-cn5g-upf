#!/bin/bash

transfer_files(){

    local rx_queues=$1
    scp $1 $2

    # Check if the scp was successful
    if [ $? -eq 0 ]; then
        echo "Files transferred successfully."
    else
        echo "Error transferring files."
    fi
}


remove_files(){
    rm -f $1/*
}

main() {
    set -o errexit
    set -o pipefail
    set -o nounset
    
    local -r dirname="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local -r filename="${dirname}/$(basename "${BASH_SOURCE[0]}")"
    local -r session_name="acm"

    source "${dirname}/../env.sh"
    
    TEST_DURATION=30    # Duration of each running test (seconds)
    TEST_ITERATIONS=1    # Number of repetitions (#)
    MAX_QUEUES=12  
    QUEUE_SIZE=1
    
    PKT_SMALLEST_SIZE=64
    PKT_BIGEST_SIZE=1460
    PKT_STEP=50

    # DESTINATION_DIR="cristal:/home/franck/workspace/results-acm-conext/${packet_size}Bytes/tx_rx_queue_${QUEUE_SIZE}"
    

    SCRIPTS="${DUT_UPF_WORKSPACE_STANDALONE}/tests/scripts"
    
    unset TMUX
    tmux kill-session -t acm 2>/dev/null || true

    for ((packet_size=PKT_SMALLEST_SIZE; packet_size<=PKT_BIGEST_SIZE; packet_size+=PKT_STEP)); do
        for queues_size in $(seq 1 $MAX_QUEUES); do
            QUEUE_SIZE=$queues_size
            SOURCE_DIR="${WORKSPACE}/results-acm-conext/gtp/${packet_size}Bytes/tx_rx_queue_${QUEUE_SIZE}"

            echo "Set RX Queues to $QUEUE_SIZE"
            sudo ethtool -L enp5s0f0 combined "$QUEUE_SIZE"
            sudo ethtool -L enp5s0f1 combined "$QUEUE_SIZE"
            tmux kill-session -t acm 2>/dev/null || true
            echo "Return DPDK used interfaces:"
            ssh trex "cd \"${TREX_SERVER_DIR}\" && ./dpdk_setup_ports.py -L"

            for i in $(seq 1 $TEST_ITERATIONS); do
                echo "Packet Size: $packet_size, RX Queue: $QUEUE_SIZE, Test: $i"
                echo "=========================================================="
                
                sleep 2

                # Run the test script in the background
                "${SCRIPTS}/acm_conext_start_tests_gtp.sh" "$SOURCE_DIR" "$i" "$QUEUE_SIZE" "$TEST_DURATION" "$packet_size" > output.log 2>&1 &
                
                sleep $((TEST_DURATION + 20))

                echo "KILL SESSION ..."
                tmux kill-session -t acm 2>/dev/null || true

                wait 
                
                # Ensure the tmux session is really killed
                if tmux has-session -t acm 2>/dev/null; then
                    echo "Tmux session still exists, killing again..."
                    tmux kill-session -t acm 2>/dev/null
                fi
                
                echo ""
                echo ""
            done
            # DESTINATION_DIR="cristal:/home/franck/workspace/results-acm-conext/${packet_size}Bytes/tx_rx_queue_${QUEUE_SIZE}"
            # transfer_files $SOURCE_DIR $DESTINATION_DIR
            # delete_files $SOURCE_DIR

        done
        
        if [ "$packet_size" -eq 64 ]; then
            packet_size=50 
        elif [ "$packet_size" -eq 1450 ]; then
            PKT_STEP=10 
        fi 
    done
}

main "$@"
