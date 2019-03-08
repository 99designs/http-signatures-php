<?php

namespace HttpSignatures;

use Psr\Http\Message\RequestInterface;

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
     * @param RequestInterface $message
     *
     * @return bool
     */
    public function isSigned($message)
    {
        $verification = new Verification($message, $this->keyStore);

        return $verification->isSigned();
    }

    /**
     * @param RequestInterface $message
     *
     * @return bool
     */
    public function isAuthorized($message)
    {
        $verification = new Verification($message, $this->keyStore);

        return $verification->isAuthorized();
    }

    /**
     * @param RequestInterface $message
     *
     * @return bool
     */
    public function isValid($message)
    {
        trigger_error(
            'http-signatures-php: Verifier->isValid() is deprecated, use isSigned() or isAuthorized() to validate individual signature header',
             E_USER_DEPRECATED
        );
        $verification = new Verification($message, $this->keyStore);

        return  $verification->isAuthorized() && $verification->isSigned();
    }
}
