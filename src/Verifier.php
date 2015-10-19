<?php

namespace HttpSignatures;

use Symfony\Component\HttpFoundation\Request;

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
     * @param Request|SymfonyRequestMessage $message
     *
     * @return bool
     */
    public function isValid($message)
    {
        $verification = new Verification($message, $this->keyStore);

        return $verification->isValid();
    }
}
