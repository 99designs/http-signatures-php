<?php

namespace HttpSignatures;

use HttpSignatures\Message\MessageInterface;
use HttpSignatures\Message\SymfonyRequestMessage;
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
     * @param Request|MessageInterface $message
     *
     * @return bool
     */
    public function isValid($message)
    {
        if ($message instanceof \Symfony\Component\HttpFoundation\Request) {
            $message = new SymfonyRequestMessage($message);
        } else if (!($message instanceof MessageInterface)) {
            throw new \InvalidArgumentException("\$message should be instance of \\HttpSignatures\\Message\\MessageInterface, instace of " . get_class($message) . " given");
        }

        $verification = new Verification($message, $this->keyStore);

        return $verification->isValid();
    }
}
