<?php

namespace HttpSignatures;

use Psr\Http\Message\RequestInterface;

class Signature
{
    /** @var Key */
    private $key;

    /** @var AlgorithmInterface */
    private $algorithm;

    /** @var SigningString */
    private $signingString;

    /**
     * @param RequestInterface   $message
     * @param Key                $key
     * @param AlgorithmInterface $algorithm
     * @param HeaderList         $headerList
     */
    public function __construct($message, Key $key, AlgorithmInterface $algorithm, HeaderList $headerList)
    {
        $this->key = $key;
        $this->algorithm = $algorithm;
        $this->signingString = new SigningString($headerList, $message);
    }

    public function string()
    {
        switch (get_class($this->algorithm)) {
          case 'HttpSignatures\HmacAlgorithm':
            return $this->algorithm->sign(
                $this->key->secret,
                $this->signingString->string()
            );
          case 'HttpSignatures\RsaAlgorithm':
            return $this->algorithm->sign(
                $this->key->privateKey,
                $this->signingString->string()
              );
          default:
            throw new Exception(
              "Algorithm class " .
               get_class($this->algorithm) . " unknown");
        }
    }
}
