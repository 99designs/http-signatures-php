<?php

namespace HttpSignatures;

class Signer
{
    /** @var Key */
    private $key;

    /** @var HmacAlgorithm */
    private $algorithm;

    /** @var HeaderList */
    private $headerList;

    /**
     * @param Key           $key
     * @param HmacAlgorithm $algorithm
     * @param HeaderList    $headerList
     */
    public function __construct($key, $algorithm, $headerList)
    {
        $this->key = $key;
        $this->algorithm = $algorithm;
        $this->headerList = $headerList;
    }

    /**
     * @param $message
     */
    public function sign($message)
    {
        $signatureParameters = $this->signatureParameters($message);
        $message->headers->set('Signature', $signatureParameters->string());
        $message->headers->set('Authorization', 'Signature '.$signatureParameters->string());
    }

    /**
     * @param $message
     *
     * @return SignatureParameters
     */
    private function signatureParameters($message)
    {
        return new SignatureParameters(
        $this->key,
        $this->algorithm,
        $this->headerList,
        $this->signature($message)
      );
    }

    /**
     * @param $message
     *
     * @return Signature
     */
    private function signature($message)
    {
        return new Signature(
            $message,
            $this->key,
            $this->algorithm,
            $this->headerList
        );
    }
}
