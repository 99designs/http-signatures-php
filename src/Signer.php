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
        $message->headers->set("Signature", (string)$signatureParameters);
        $message->headers->set("Authorization", "Signature " . (string)$signatureParameters);
    }

    private function signatureParameters($message)
    {
      return new SignatureParameters(
        $this->key,
        $this->algorithm,
        $this->headerList,
        $this->signatureForMessage($message)
      );
    }

    private function signatureForMessage($message)
    {
        return $this->algorithm->sign(
            $this->key->secret,
            $this->signingStringForMessage($message)
        );
    }

    private function signingStringForMessage($message)
    {
        return (string)new SigningString($this->headerList, $message);
    }
}
