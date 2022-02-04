<?php

$PRIVATE_KEY = 'my_site_secret';

function base64Encode($text)  {
    return str_replace(
        ['+', '/', '='],
        ['-', '_', ''],
        base64_encode($text)
    );
}

function generateToken($object, $time, $payload = []) {
    global $PRIVATE_KEY;
    // header data
    $header = [ 'alg' => 'HS256', 'type' => 'JWT' ];
    // payload data
    $payload['iat'] = time();
    $payload['exp'] = time() + $time;
    $payload['obj'] = $object;
    // create encoded header
    $header64 = base64Encode(json_encode($header));
    // create encoded payload
    $payload64 = base64Encode(json_encode($payload));
    // create signature
    $signature = hash_hmac(
        'sha256',
        $header64 . "." . $payload64,
        $PRIVATE_KEY,
        true
    );
    // encode signature
    $signature64 = base64Encode($signature);
    // return token
    return $header64 . '.' . $payload64 . '.' . $signature64;
}

function validateToken($token) {
    global $PRIVATE_KEY;
    // get token string and split
    if(strpos($token, "Bearer ") === 0) { $token = substr($token, 7); }
    $parts = explode('.', $token);
    // define three parts
    $header64 = $parts[0];
    $payload64 = $parts[1];
    $signature64 = $parts[2];
    // create signature again from received header and payload
    $check = hash_hmac(
        'sha256',
        $header64 . "." . $payload64,
        $PRIVATE_KEY,
        true
    );
    // check if token decodable
    if(base64Encode($check) !== $signature64) {
        return 'TOKEN_INVALID';
    }
    // get payload data if token decoded successfully
    $payload = json_decode(base64_decode($payload64));
    // check token values
    if(isset($payload -> iat) === false) {
        // no issued time
        return 'TOKEN_INVALID';
    } else if(isset($payload -> exp) === false) {
        // no expiration time
        return 'TOKEN_INVALID';
    } else if(isset($payload -> obj) === false) {
        // no data object
        return 'TOKEN_INVALID';
    } else if($payload -> iat > time() || $payload -> exp < time()) {
        // expired token
        return 'TOKEN_EXPIRED';
    } else {
        // return valid token
        return $payload -> obj;
    }
}

?>