<?php

namespace HttpSignatures;

class Context
{
    private $keys;
    private $algorithm;
    private $headers;
    private $signingKeyId;

    public function __construct($args)
    {
        $this->keyStore = new KeyStore($args['keys']);
        $this->algorithm = $args['algorithm'];
        $this->headers = $args['headers'];
        $this->signingKeyId = isset($args['signingKeyId']) ? $args['signingKeyId'] : null;
    }

    public function signer()
    {
        return new Signer(
            $this->signingKey(),
            null, // TODO: algorithm
            null // TODO: headerList
        );
    }

    private function signingKey()
    {
        if ($this->signingKeyId) {
            return $this->keyStore->fetch($this->signingKeyId);
        } else {
            return $this->keyStore->onlyKey();
        }
    }
}
