<?php

namespace HttpSignatures;

use Psr\Http\Message\MessageInterface;

class Signature
{
    /** @var Key */
    private $key;

    /** @var HmacAlgorithm */
    private $algorithm;

    /** @var SigningString */
    private $signingString;

    /**
     * @param MessageInterface $message
     * @param Key $key
     * @param HmacAlgorithm $algorithm
     * @param HeaderList $headerList
     */
    public function __construct($message, $key, $algorithm, $headerList)
    {
        $this->key = $key;
        $this->algorithm = $algorithm;
        $this->signingString = new SigningString($headerList, $message);
    }

    public function string()
    {
        return $this->algorithm->sign(
            $this->key->secret,
            $this->signingString->string()
        );
    }
}
