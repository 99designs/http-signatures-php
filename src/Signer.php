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

    public function sign($message)
    {
        $signatureParameters = $this->signatureParameters($message);
        $message->headers->set("Signature", $signatureParameters->string());
        $message->headers->set("Authorization", "Signature " . $signatureParameters->string());
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
