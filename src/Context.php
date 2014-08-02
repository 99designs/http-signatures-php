<?php

namespace HttpSignatures;

class Context
{
    private $algorithm;
    private $headers;
    private $keyStore;
    private $keys;
    private $signingKeyId;

    public function __construct($args)
    {
        $this->keys = $args['keys'];
        $this->algorithmName = $args['algorithm'];
        $this->headers = $args['headers'];
        $this->signingKeyId = isset($args['signingKeyId']) ? $args['signingKeyId'] : null;
    }

    public function signer()
    {
        return new Signer(
            $this->signingKey(),
            $this->algorithm(),
            $this->headerList()
        );
    }

    public function verifier()
    {
        return new Verifier($this->keyStore());
    }

    private function signingKey()
    {
        if ($this->signingKeyId) {
            return $this->keyStore()->fetch($this->signingKeyId);
        } else {
            return $this->keyStore()->onlyKey();
        }
    }

    private function algorithm()
    {
        return Algorithm::create($this->algorithmName);
    }

    private function headerList()
    {
        return new HeaderList($this->headers);
    }

    private function keyStore()
    {
        if (empty($this->keyStore)) {
            $this->keyStore = new KeyStore($this->keys);
        }

        return $this->keyStore;
    }
}
