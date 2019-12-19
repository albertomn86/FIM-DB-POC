#!/bin/bash

rm metriquillas.txt
echo "files,insertion_time,commit_time,total_time,size" >> metriquillas.txt
for i in {1,5,10,50,100,500,1000,5000,10000,50000,100000,500000,1000000}; do
    echo "Vamos por $i"
    ./fim_db $i >> metriquillas.txt
    sqlite3 fim.db "select * from entry_path" > /dev/null
    size=`ls -l --block-size=KiB fim.db | cut -d " " -f 5 | cut -d "K" -f 1`
    echo -en ",$size\n" >> metriquillas.txt
done;
