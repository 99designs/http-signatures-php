<?php

namespace HttpSignatures;

use HttpSignatures\Message\MessageInterface;

class Signature
{
    /** @var MessageInterface */
    private $message;

    /** @var Key */
    private $key;

    /** @var HmacAlgorithm */
    private $algorithm;

    /** @var HeaderList */
    private $headerList;

    public function __construct(MessageInterface $message, $key, $algorithm, $headerList)
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
