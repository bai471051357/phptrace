<?php

function request($url, $postdata = null, &$error = null, $ip = null, $extraopts = null)
{
    $headers = array();
    $parsed_url = parse_url($url);

    // 使用IP替换Host，手动添加Host头
    if ($ip) {
        $url = str_replace($parsed_url['host'], $ip, $url);
        $headers[] = 'Host: '.$parsed_url['host'];
    }

    // Options
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    // make github happy
    // https://developer.github.com/v3/#user-agent-required
    curl_setopt($ch, CURLOPT_USERAGENT, 'curl for github');

    curl_setopt($ch, CURLOPT_TIMEOUT, 15);

    if ($postdata) {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
    }
    if ($extraopts) {
        if (isset($extraopts['headers'])) {
            $headers = array_merge($headers, $extraopts['headers']);
            unset($extraopts['headers']);
        }
        curl_setopt_array($ch, $extraopts);
    }
    if ($headers) {
        print_r($headers);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }

    // Exec
    $res = curl_exec($ch);
    if (curl_errno($ch)) {
        $error = curl_error($ch);
    }
    curl_close($ch); 

    return $res;
}

function request_api($url)
{
    for ($tries = 3; $tries > 0; $tries--) {
        $raw = request($url);
        if ($raw !== false) {
            break;
        }
    }
    $data = json_decode($raw);
    return $data;
}

// Init record
$r = array(
    'stars' => 0,
    'forks' => array(),
);

// Get api urls
$apis = request_api('https://api.github.com');

// Get repo data
$url = str_replace(
    array('{owner}', '{repo}'),
    array('Qihoo360', 'phptrace'),
    $apis->repository_url
);
$repo = request_api($url);
$r['stars'] = $repo->stargazers_count;

// Get all forks
$forks = request_api($repo->forks_url.'?per_page=1000');
foreach ($forks as $fork) {
    if ($fork->pushed_at >= $fork->created_at) {
        $r['forks'][] = $fork->full_name;
    }
}
$r['forks'] = implode(',', $r['forks']);

// Save record
$line = sprintf(
    "%s\t%s\n",
    date('Ymd_His'),    // key
    json_encode($r)     // value
);
echo $line;
file_put_contents(__DIR__.'/github.record', $line, FILE_APPEND);
