<?php

namespace HttpSignatures;

class KeyStore
{
    private $keys;

    public function __construct($keys)
    {
        $this->keys = array();
        foreach ($keys as $id => $secret) {
            $this->keys[$id] = new Key($id, $secret);
        }
    }

    public function fetch($id)
    {
        if (isset($this->keys[$id])) {
            return $this->keys[$id];
        } else {
            throw new KeyStoreException("Key '$id' not found");
        }
    }
}
