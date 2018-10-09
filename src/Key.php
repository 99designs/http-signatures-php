<?php

namespace HttpSignatures;

class Key
{
    /** @var string */
    private $id;

    /** @var string */
    private $secret;

    /** @var resource */
    private $certificate;

    /** @var resource */
    private $publicKey;

    /** @var resource */
    private $privateKey;

    /** @var string */
    private $type;

    /**
     * @param string $id
     * @param string $secret
     */
    public function __construct($id, $item)
    {
        $this->id = $id;
        if (Key::hasX509Certificate($item) || Key::hasPublicKey($item)) {
            $publicKey = Key::getPublicKey($item);
        } else {
            $publicKey = null;
        }
        if (Key::hasPrivateKey($item)) {
            $privateKey = Key::getPrivateKey($item);
        } else {
            $privateKey = null;
        }
        if (($publicKey || $privateKey)) {
            $this->type = 'asymmetric';
            if ($publicKey && $privateKey) {
                $publicKeyPEM = openssl_pkey_get_details($publicKey)['key'];
                $privateKeyPublicPEM = openssl_pkey_get_details($privateKey)['key'];
                if ($privateKeyPublicPEM != $publicKeyPEM) {
                    throw new KeyException('Supplied Certificate and Key are not related');
                }
            }
            $this->privateKey = $privateKey;
            $this->publicKey = $publicKey;
            $this->secret = null;
        } else {
            $this->type = 'secret';
            $this->secret = $item;
            $this->publicKey = null;
            $this->privateKey = null;
        }
    }

    public static function getPrivateKey($object)
    {
        if (is_array($object)) {
            foreach ($object as $candidateKey) {
                $privateKey = Key::getPrivateKey($candidateKey);
                if ($privateKey) {
                    return $privateKey;
                }
            }
        } else {
            // OpenSSL libraries don't have detection methods, so try..catch
            try {
                $privateKey = openssl_get_privatekey($object);

                return $privateKey;
            } catch (\Exception $e) {
                return null;
            }
        }
    }

    public static function getPublicKey($object)
    {
        if (is_array($object)) {
            // If we implement key rotation in future, this should add to a collection
            foreach ($object as $candidateKey) {
                $publicKey = Key::getPublicKey($candidateKey);
                if ($publicKey) {
                    return $publicKey;
                }
            }
        } else {
            // OpenSSL libraries don't have detection methods, so try..catch
            try {
                $publicKey = openssl_get_publickey($object);

                return $publicKey;
            } catch (\Exception $e) {
                return null;
            }
        }
    }

    public function getId()
    {
        return $this->id;
    }

    public function getVerifyingKey()
    {
        switch ($this->type) {
        case 'asymmetric':
            if ($this->publicKey) {
                return openssl_pkey_get_details($this->publicKey)['key'];
            } else {
                return null;
            }
            break;
        case 'secret':
            return $this->secret;
        default:
            throw new KeyException("Unknown key type $this->type");
        }
    }

    public function getSigningKey()
    {
        switch ($this->type) {
        case 'asymmetric':
            if ($this->privateKey) {
                openssl_pkey_export($this->privateKey, $pem);

                return $pem;
            } else {
                return null;
            }
            break;
        case 'secret':
            return $this->secret;
        default:
            throw new KeyException("Unknown key type $this->type");
        }
    }

    public function getType()
    {
        return $this->type;
    }

    public static function hasX509Certificate($object)
    {
        if (is_array($object)) {
            foreach ($object as $candidateCertificate) {
                $result = Key::hasX509Certificate($candidateCertificate);
                if ($result) {
                    return $result;
                }
            }
        } else {
            // OpenSSL libraries don't have detection methods, so try..catch
            try {
                openssl_x509_export($object, $null);

                return true;
            } catch (\Exception $e) {
                return false;
            }
        }
    }

    public static function hasPublicKey($object)
    {
        if (is_array($object)) {
            foreach ($object as $candidatePublicKey) {
                $result = Key::hasPublicKey($candidatePublicKey);
                if ($result) {
                    return $result;
                }
            }
        } else {
            return false == !openssl_pkey_get_public($object);
        }
    }

    public static function hasPrivateKey($object)
    {
        if (is_array($object)) {
            foreach ($object as $candidatePrivateKey) {
                $result = Key::hasPrivateKey($candidatePrivateKey);
                if ($result) {
                    return $result;
                }
            }
        } else {
            return  false != openssl_pkey_get_private($object);
        }
    }
}
