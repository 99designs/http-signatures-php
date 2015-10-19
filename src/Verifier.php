<?php

namespace HttpSignatures;

use Psr\Http\Message\MessageInterface;

class Verifier
{
    /** @var KeyStoreInterface */
    private $keyStore;

    /**
     * @param KeyStoreInterface $keyStore
     */
    public function __construct(KeyStoreInterface $keyStore)
    {
        $this->keyStore = $keyStore;
    }

    /**
     * @param MessageInterface $message
     * @return bool
     */
    public function isValid($message)
    {
        $verification = new Verification($message, $this->keyStore);

        return $verification->isValid();
    }
}
