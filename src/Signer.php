<?php

namespace HttpSignatures;

class Signer
{
    private $key;
    private $algorithm;
    private $headerList;

    public function __construct($key, $algorithm, $headerList)
    {
        $this->key = $key;
        $this->algorithm = $algorithm;
        $this->headerList = $headerList;
    }
}
