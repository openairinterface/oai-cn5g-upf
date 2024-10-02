#!/bin/bash

remove_files(){
    rm -f $1/*
}

main() {
    set -o errexit
    set -o pipefail
    set -o nounset
   
    local -r dirname="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local -r filename="${dirname}/$(basename "${BASH_SOURCE[0]}")"
    local -r session_name="upf_performance"

    source "${dirname}/../env.sh"
    
    TEST_DURATION=120     # Duration of each running test (seconds)
    TEST_ITERATIONS=1    # Number of repetitions (#)
    MAX_QUEUES=24
    
    PKT_SMALLEST_SIZE=64
    PKT_BIGEST_SIZE=64
    PKT_STEP=50

    # Flat saving directory for results
    RESULT_DIR="${UPF_WORKSPACE}/new-results"
    
    SCRIPTS="${DUT_UPF_WORKSPACE_STANDALONE}/tests/scripts"
    
    unset TMUX
    tmux kill-session -t upf_performance 2>/dev/null || true
    
    for ((packet_size=$PKT_SMALLEST_SIZE; packet_size<=$PKT_BIGEST_SIZE; packet_size+=$PKT_STEP)); do
        echo "Packet Size: $packet_size"
        for queues_size in $(seq $MAX_QUEUES -1 1); do
            QUEUE_SIZE=$queues_size
            
            echo "Set RX Queues to $QUEUE_SIZE"
            sudo ethtool -L enp1s0f0np0 combined "$QUEUE_SIZE"
            sudo ethtool -L enp1s0f1np1 combined "$QUEUE_SIZE"
            
            for i in $(seq 1 $TEST_ITERATIONS); do
                echo "Packet Size: $packet_size, RX Queue: $QUEUE_SIZE, Test: $i, Duration: $TEST_DURATION"
                echo "================================================="
                echo ""
                
                sleep 2

                # Create a unique filename based on packet_size, QUEUE_SIZE, iteration, and timestamp
                #TIMESTAMP=$(date +%Y%m%d_%H%M%S)
                #OUTPUT_PREFIX="${RESULT_DIR}/UDP___TestIteration_${i}___PacketSize_${packet_size}Bytes___QueueSize_${QUEUE_SIZE}___TimeStamp_${TIMESTAMP}"
                OUTPUT_PREFIX="${RESULT_DIR}/UDP___TestIteration_${i}___PacketSize_${packet_size}Bytes___QueueSize_${QUEUE_SIZE}"
                   
                # Pass the file paths to the child script
                "${SCRIPTS}/china_start_tests_udp.sh" "$OUTPUT_PREFIX" "$i" "$QUEUE_SIZE" "$TEST_DURATION" "$packet_size" > "${OUTPUT_PREFIX}_output.log" 2>&1
                # "${SCRIPTS}/china_start_tests_udp.sh" "$OUTPUT_PREFIX" "$i" "$QUEUE_SIZE" "$TEST_DURATION" "$packet_size" > "${OUTPUT_PREFIX}_output.log" 2>&1 &

                sleep $((TEST_DURATION + 20))

                echo "KILL SESSION ..."
                tmux kill-session -t upf_performance 2>/dev/null || true

                wait 
                
                # Ensure the tmux session is really killed
                if tmux has-session -t upf_performance 2>/dev/null; then
                    echo "Tmux session still exists, killing again..."
                    tmux kill-session -t upf_performance 2>/dev/null
                fi
                
                echo ""
                echo ""
            done
        done
        
        if [ "$packet_size" -eq 64 ]; then
            packet_size=50 
        elif [ "$packet_size" -eq 1450 ]; then
            PKT_STEP=10 
        fi 
    done
}

main "$@"
