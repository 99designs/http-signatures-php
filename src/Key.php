<?php

namespace HttpSignatures;

class Key
{
    /** @var string */
    public $id;

    /** @var string */
    public $secret;

    /** @var string */
    public $certificate;

    /** @var string */
    public $privateKey;

    /** @var string */
    public $type;

    /**
     * @param string $id
     * @param string $secret
     */
    public function __construct($id, $item)
    {
        $this->id = $id;
        $certificate = Key::getX509Certificate($item);
        $privateKey = Key::getRSAPrivateKey($item);
        if (($certificate || $privateKey)) {
            $this->type = 'rsa';
            if ($privateKey) {
                $this->privateKey = $privateKey;
            };
            if ($certificate) {
                $this->certificate = openssl_x509_read($certificate);
            };
            if ($certificate && $privateKey) {
                // openssl_pkey_export($this->privateKey, $privateKey);
            // openssl_x509_export($this->certificate, $certificate);
            if (! openssl_x509_check_private_key(
                $this->certificate, $this->privateKey)
                ) {
                throw new KeyException("Supplied Certificate and Key are not related");
            }
            };
        } else {
            $this->type = 'secret';
            $this->secret = $item;
            $publicKey = null;
            $privateKey = null;
        };
    }

    private function getRSAPrivateKey($object)
    {
        $key = null;
        if (is_array($object)) {
            foreach ($object as $item) {
                $privateKey = Key::getRSAPrivateKey($item);
                if ($privateKey) {
                    return $privateKey;
                }
            };
        } else {
            try {
                $privateKey = openssl_get_privatekey($object);
            } catch (\Exception $e) {
                $privateKey = null;
            };
            if ($privateKey) {
                return $privateKey;
            }
        }
    }

    private function getX509Certificate($object)
    {
        $key = null;
        if (is_array($object)) {
            foreach ($object as $item) {
                $result = Key::getX509Certificate($item);
                if ($result) {
                    $key = $result;
                }
            };
            return $key;
        } else {
            try {
                $result = openssl_get_publickey($object);
            } catch (\Exception $e) {
                $result = null;
            };
            if ($result) {
                openssl_x509_export($object, $out);
                return $object;
            }
        }
    }
}
