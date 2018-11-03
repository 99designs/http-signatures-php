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
            case 'hmac-sha256':
                return new HmacAlgorithm('sha256');
            case 'rsa-sha256':
                return new RsaAlgorithm('sha256');
            default:
                throw new Exception("No algorithm named '$name'");
        }
    }
}
