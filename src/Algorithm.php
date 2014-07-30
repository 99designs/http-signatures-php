<?php

namespace HttpSignatures;

class Algorithm
{
    private function __construct()
    {
        // static class.
    }

    public static function create($name)
    {
        switch ($name) {
        case 'hmac-sha1':
            return new HmacAlgorithm('sha1');
            break;
        case 'hmac-sha256':
            return new HmacAlgorithm('sha256');
            break;
        default:
            throw new Exception("No algorithm named '$name'");
            break;
        }
    }
}
