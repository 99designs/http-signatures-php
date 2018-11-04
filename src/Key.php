<?php

namespace HttpSignatures;

class Key
{
    /** @var string */
    private $id;

    /** @var resource */
    private $publicKey;

    /** @var resource */
    private $privateKey;

    /**
     * @param string $id
     * @param string $item
     */
    public function __construct($id, $item)
    {
        $this->id = $id;

        if (!$this->initPemKeys($item)) {
            $this->privateKey = $item;
            $this->publicKey = $item;
        }
    }

    private function initPemKeys($item)
    {
        if ($privateKeyRes = openssl_pkey_get_private($item)) {
            if (!openssl_pkey_export($privateKeyRes, $this->privateKey)) {
                throw new Exception('Failed to export key: ' . openssl_error_string());
            }
            $this->publicKey = static::pemKeyFromOpenSSLResource($privateKeyRes);
        }

        if (!$this->publicKey) {
            if ($publicKeyRes = openssl_pkey_get_public($item)) {
                $this->publicKey = static::pemKeyFromOpenSSLResource($publicKeyRes);
            }
        }

        return (bool) $this->publicKey;
    }

    private function pemKeyFromOpenSSLResource($r)
    {
        $details = openssl_pkey_get_details($r);
        if (!$details) {
            throw new Exception('Failed to get key details: ' . openssl_error_string());
        }

        return $details['key'];
    }

    /**
     * Signing HTTP Messages 'keyId' field.
     *
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Get the Verifying Key - Public Key for Asymmetric/PKI, or shared secret for HMAC.
     *
     * @return string Shared Secret or PEM-format Public Key
     */
    public function getVerifyingKey()
    {
        return $this->publicKey;
    }

    /**
     * Get the Signing Key - Private Key for Asymmetric/PKI, or shared secret for HMAC.
     *
     * @return string Shared Secret or PEM-format Private Key
     */
    public function getSigningKey()
    {
        return $this->privateKey;
    }
}
