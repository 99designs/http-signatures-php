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
            throw new Exception("Key '$id' not found");
        }
    }

    public function onlyKey()
    {
        $count = count($this->keys);
        if ($count == 1) {
            return reset($this->keys); // first item
        } else {
            throw new Exception("expected 1 key, found $count");
        }
    }
}
