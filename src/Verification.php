<?php

namespace HttpSignatures;

use HttpSignatures\Algorithm;
use HttpSignatures\HeaderList;

class Verification
{
    private $message;
    private $keyStore;
    private $_parameters;

    public function __construct($message, $keyStore)
    {
        $this->message = $message;
        $this->keyStore = $keyStore;
    }

    public function isValid()
    {
        return $this->expectedSignatureBase64() === $this->providedSignatureBase64();
    }

    private function expectedSignatureBase64()
    {
        return base64_encode($this->expectedSignature()->string());
    }

    private function expectedSignature()
    {
        return new Signature(
            $this->message,
            $this->key(),
            $this->algorithm(),
            $this->headerList()
        );
    }

    private function providedSignatureBase64()
    {
        return $this->parameter('signature');
    }

    private function key()
    {
        return $this->keyStore->fetch($this->parameter('keyId'));
    }

    private function algorithm()
    {
        return Algorithm::create($this->parameter('algorithm'));
    }

    private function headerList()
    {
        return HeaderList::fromString($this->parameter('headers'));
    }

    private function parameter($name)
    {
        $parameters = $this->parameters();
        if (!isset($parameters[$name])) {
            throw new Exception("Signature parameters does not contain '$name'");
        }
        return $parameters[$name];
    }

    private function parameters()
    {
        if (!isset($this->_parameters)) {
            $parser = new SignatureParametersParser($this->fetchHeader('Signature'));
            $this->_parameters = $parser->parse();
        }
        return $this->_parameters;
    }

    private function fetchHeader($name)
    {
        $headers = $this->message->headers;
        if ($headers->has($name)) {
            return $headers->get($name);
        } else {
            throw new Exception("HTTP message has no '$name' header");
        }
    }
}
