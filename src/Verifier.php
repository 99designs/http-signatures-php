<?php

namespace HttpSignatures;

class Verifier
{
    /**
     * @var KeyStoreInterface
     */
    private $keyStore;

    public function __construct(KeyStoreInterface $keyStore)
    {
        $this->keyStore = $keyStore;
    }

    public function isValid($message)
    {
        $verification = new Verification($message, $this->keyStore);

        return $verification->isValid();
    }
}
