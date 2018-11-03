<?php

namespace HttpSignatures;

class KeyStore implements KeyStoreInterface
{
    /** @var Key[] */
    private $keys;

    /**
     * @param array $keys
     */
    public function __construct($keys)
    {
        $this->keys = [];
        foreach ($keys as $id => $key) {
            $this->keys[$id] = new Key($id, $key);
        }
    }

    /**
     * @param string $keyId
     *
     * @return Key
     *
     * @throws UnknownKeyException
     */
    public function fetch($keyId)
    {
        if (isset($this->keys[$keyId])) {
            return $this->keys[$keyId];
        } else {
            throw new UnknownKeyException("Key '$keyId' not found");
        }
    }
}
