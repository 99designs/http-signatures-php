<?php

namespace HttpSignatures;

class Verifier
{
    private $keyStore;

    public function __construct($keyStore)
    {
        $this->keyStore = $keyStore;
    }

    public function isValid($message)
    {
        $verification = new Verification($message, $this->keyStore);

        return $verification->isValid();
    }
}
