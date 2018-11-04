<?php

namespace HttpSignatures;

interface AlgorithmInterface
{
    /**
     * @return string
     */
    public function name();

    /**
     * @param string $key
     * @param string $data
     *
     * @return string
     */
    public function sign($key, $data);

    /**
     * @param string $signature
     * @param string $key
     * @param string $data
     *
     * @return bool
     */
    public function verify($signature, $key, $data);
}
