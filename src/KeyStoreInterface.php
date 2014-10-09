<?php

namespace HttpSignatures;

interface KeyStoreInterface
{
    /**
     * return the secret for the specified $keyId
     */
    public function fetch($keyId);
}
