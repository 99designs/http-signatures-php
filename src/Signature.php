<?php

namespace HttpSignatures;

use Psr\Http\Message\RequestInterface;

class Signature
{
    /** @var Key */
    private $key;

    /** @var HmacAlgorithm */
    private $algorithm;

    /** @var SigningString */
    private $signingString;

    /**
     * @param RequestInterface $message
     * @param Key $key
     * @param AlgorithmInterface $algorithm
     * @param HeaderList $headerList
     */
    public function __construct($message, Key $key, AlgorithmInterface $algorithm, HeaderList $headerList)
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
