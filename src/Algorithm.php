<?php

namespace HttpSignatures;

abstract class Algorithm
{
    /**
     * @param string $name
     *
     * @return HmacAlgorithm
     *
     * @throws Exception
     */
    public static function create($name)
    {
        switch ($name) {
        case 'hmac-sha1':
            return new HmacAlgorithm('sha1');
            break;
        case 'hmac-sha256':
            return new HmacAlgorithm('sha256');
            break;
        case 'rsa-sha256':
            return new RsaAlgorithm('sha256');
            break;
        case 'rsa-sha384':
            return new RsaAlgorithm('sha384');
            break;
        case 'rsa-sha512':
            return new RsaAlgorithm('sha512');
            break;
        default:
            throw new Exception("No algorithm named '$name'");
            break;
        }
    }
}
