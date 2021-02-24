<?php

namespace OAuth2\Encryption;

use Firebase\JWT\JWT;

/**
 * Bridge file to use the firebase/php-jwt package for JWT encoding and decoding.
 * @author Francis Chuang <francis.chuang@gmail.com>
 */
class FirebaseJwt implements EncryptionInterface
{
    public function encode($payload, $key, $alg = 'HS256', $keyId = null)
    {
        return JWT::encode($payload, $key, $alg, $keyId);
    }

    public function decode($jwt, $key = null, $allowedAlgorithms = null)
    {
        try {

            //Maintain BC: Do not verify if no algorithms are passed in.
            if (!$allowedAlgorithms) {
                $key = null;
            }

            return (array)JWT::decode($jwt, $key, $allowedAlgorithms);
        } catch (\Exception $e) {
            return false;
        }
    }

    public function urlSafeB64Encode($data)
    {
        return JWT::urlsafeB64Encode($data);
    }

    public function urlSafeB64Decode($b64)
    {
        return JWT::urlsafeB64Decode($b64);
    }
}
