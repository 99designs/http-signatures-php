<?php

namespace HttpSignatures;

class KeyStore implements KeyStoreInterface
{
    private $keys;

    public function __construct($keys)
    {
        $this->keys = array();
        foreach ($keys as $id => $secret) {
            $this->keys[$id] = new Key($id, $secret);
        }
    }

    public function fetch($keyId)
    {
        if (isset($this->keys[$keyId])) {
            return $this->keys[$keyId];
        } else {
            throw new KeyStoreException("Key '$keyId' not found");
        }
    }
}
