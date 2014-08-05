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
        if (isset($args['keys']) && isset($args['keyStore'])) {
            throw new Exception(__CLASS__ . ' accepts keys or keyStore but not both');
        } elseif (isset($args['keys'])) {
            // array of keyId => keySecret
            $this->keys = $args['keys'];
        } elseif (isset($args['keyStore'])) {
            // KeyStore-compatible object
            $this->keyStore = $args['keyStore'];
        }

        // algorithm for signing; not necessary for verifying.
        if (isset($args['algorithm'])) {
            $this->algorithmName = $args['algorithm'];
        }

        // headers list for signing; not necessary for verifying.
        if (isset($args['headers'])) {
            $this->headers = $args['headers'];
        }

        // signingKeyId specifies the key used for signing messages.
        if (isset($args['signingKeyId'])) {
            $this->signingKeyId = $args['signingKeyId'];
        } elseif (isset($args['keys']) && count($args['keys']) === 1) {
            list($this->signingKeyId) = array_keys($args['keys']); // first key
        }
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
        if (isset($this->signingKeyId)) {
            return $this->keyStore()->fetch($this->signingKeyId);
        } else {
            throw new Exception('no implicit or specified signing key');
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
