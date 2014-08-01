<?php

namespace HttpSignatures;

use HttpSignatures\Signature;

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

    public function sign($message)
    {
        $signatureParameters = $this->signatureParameters($message);
        $message->headers->set("Signature", (string)$signatureParameters);
        $message->headers->set("Authorization", "Signature " . (string)$signatureParameters);
    }

    private function signatureParameters($message)
    {
      return new SignatureParameters(
        $this->key,
        $this->algorithm,
        $this->headerList,
        $this->signature($message)
      );
    }

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
