#!/bin/bash

output_file=$1
interval=$2
iterations=$3

# Initialize the output file
echo "Top output every $interval seconds:" > "$output_file"

# Loop to collect top output at regular intervals
for ((i = 1; i <= iterations; i++))
do
  echo -e "\nIteration $i:" >> "$output_file"
  top -b -n 1 >> "$output_file"
  sleep $interval
done