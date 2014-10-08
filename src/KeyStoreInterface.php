<?php

namespace HttpSignatures;

interface KeyStoreInterface
{
    /**
     * return the secret for the specified key_id
     *
     * @param $id
     * @return string|null
     */
    public function fetch($id);
}
