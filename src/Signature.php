<?php

namespace HttpSignatures;

class Signature
{
    private $message;
    private $key;
    private $algorithm;
    private $headerList;

    public function __construct($message, $key, $algorithm, $headerList)
    {
        $this->message = $message;
        $this->key = $key;
        $this->algorithm = $algorithm;
        $this->headerList = $headerList;
    }

    public function string()
    {
        return $this->algorithm->sign(
            $this->key->secret,
            $this->signingString()->string()
        );
    }

    private function signingString()
    {
        return new SigningString(
            $this->headerList,
            $this->message
        );
    }
}
