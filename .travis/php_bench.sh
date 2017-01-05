#!/bin/bash
function logit() {
    echo "[php_bench] $@" 1>&2
}

function bench(){
    php_path=$1
    php_version=$2
    php_bin="$php_path/bin/php"
    bench_file=$1"/Zend/bench.php"
    php_ext_dir=`$php_path/bin/php-config |grep "extension-dir"|awk '{print substr($2, 2, length($2)-2)}'`
    trace_file="$php_ext_dir/trace.so"
    if [ ${php_version:0:3} != "5.2" ]; then
        bench_without_trace=`$php_bin -n $bench_file|awk 'END{print $2}'`
        bench_with_trace=`$php_bin -n -d extension=$trace_file $bench_file|awk 'END{print $2}'`
        logit "bench php-$php_version without trace : $bench_without_trace, with trace : $bench_with_trace"
    else 
        logit "not support php-5.2" 
    fi
    exit 0
}

#main
if [ $# -lt 2 ]; then
    echo "usage: `basename $0` <php-path> <php-version>"
    exit 1
fi

#argument
php_path="$1"
if [ ! -d "$php_path" ]; then
    logit "error: invalid PHP path \"$php_path\""
    exit 1
fi
logit "php_path: $php_path"
php_version="$2"
logit "php_version: $php_version"

#bench
bench $php_path $php_version






