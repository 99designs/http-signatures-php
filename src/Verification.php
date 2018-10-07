<?php

namespace HttpSignatures;

use Psr\Http\Message\RequestInterface;

class Verification
{
    /** @var RequestInterface */
    private $message;

    /** @var KeyStoreInterface */
    private $keyStore;

    /** @var array */
    private $_signatureParameters;

    /** @var array */
    private $_authorizationParameters;

    /**
     * @param RequestInterface  $message
     * @param KeyStoreInterface $keyStore
     */
    public function __construct($message, KeyStoreInterface $keyStore)
    {
        $this->message = $message;
        $this->keyStore = $keyStore;
    }

    /**
     * @return bool
     */
    public function isSigned()
    {
        return $this->message->hasHeader('Signature') && $this->signatureMatches();
    }

    /**
     * @return bool
     */
    public function isAuthorized()
    {
        return $this->message->hasHeader('Authorization') && $this->authorizationMatches();
    }

    /**
     * @return bool
     */
    private function signatureMatches()
    {
        try {
            $random = random_bytes(32);

            return
                hash_hmac('sha256', $this->expectedSignatureBase64(), $random, true) ===
                hash_hmac('sha256', $this->providedSignatureBase64(), $random, true)
            ;
        } catch (SignatureParseException $e) {
            return false;
        } catch (KeyStoreException $e) {
            return false;
        } catch (SignedHeaderNotPresentException $e) {
            return false;
        }
    }

    /**
     * @return bool
     */
    private function authorizationMatches()
    {
        try {
            $random = random_bytes(32);

            return
              hash_hmac('sha256', $this->expectedAuthorizationBase64(), $random, true) ===
              hash_hmac('sha256', $this->providedAuthorizationBase64(), $random, true);
        } catch (SignatureParseException $e) {
            return false;
        } catch (KeyStoreException $e) {
            return false;
        } catch (SignedHeaderNotPresentException $e) {
            return false;
        }
    }

    /**
     * @return string
     */
    private function expectedSignatureBase64()
    {
        return base64_encode($this->expectedSignature()->string());
    }

    /**
     * @return string
     */
    private function expectedAuthorizationBase64()
    {
        return base64_encode($this->expectedAuthorization()->string());
    }

    /**
     * @return Signature
     */
    private function expectedSignature()
    {
        return new Signature(
            $this->message,
            $this->signatureKeyId(),
            $this->signatureAlgorithm(),
            $this->signatureHeaderList()
        );
    }

    /**
     * @return Signature
     */
    private function expectedAuthorization()
    {
        return new Signature(
            $this->message,
            $this->authorizationKeyId(),
            $this->authorizationAlgorithm(),
            $this->authorizationHeaderList()
        );
    }

    /**
     * @return string
     *
     * @throws Exception
     */
    private function providedSignatureBase64()
    {
        return $this->signatureHeaderParameter('signature');
    }

    /**
     * @return string
     *
     * @throws Exception
     */
    private function providedAuthorizationBase64()
    {
        return $this->authorizationHeaderParameter('signature');
    }

    /**
     * @return Key
     *
     * @throws Exception
     */
    private function signatureKeyId()
    {
        return $this->keyStore->fetch($this->signatureHeaderParameter('keyId'));
    }

    /**
     * @return Key
     *
     * @throws Exception
     */
    private function authorizationKeyId()
    {
        return $this->keyStore->fetch($this->authorizationHeaderParameter('keyId'));
    }

    /**
     * @return Algorithm
     *
     * @throws Exception
     */
    private function signatureAlgorithm()
    {
        return Algorithm::create($this->signatureHeaderParameter('algorithm'));
    }

    /**
     * @return Algorithm
     *
     * @throws Exception
     */
    private function authorizationAlgorithm()
    {
        return Algorithm::create($this->authorizationHeaderParameter('algorithm'));
    }

    /**
     * @return HeaderList
     *
     * @throws Exception
     */
    private function signatureHeaderList()
    {
        return HeaderList::fromString($this->signatureHeaderParameter('headers'));
    }

    /**
     * @return HeaderList
     *
     * @throws Exception
     */
    private function authorizationHeaderList()
    {
        return HeaderList::fromString($this->authorizationHeaderParameter('headers'));
    }

    /**
     * @param string $name
     *
     * @return string
     *
     * @throws Exception
     */
    private function signatureHeaderParameter($name)
    {
        $signatureHeaderParameters = $this->signatureHeaderParameters();
        if (!isset($signatureHeaderParameters[$name])) {
            throw new Exception("Signature parameters does not contain '$name'");
        }

        return $signatureHeaderParameters[$name];
    }

    /**
     * @param string $name
     *
     * @return string
     *
     * @throws Exception
     */
    private function authorizationHeaderParameter($name)
    {
        $authorizationHeaderParameters = $this->authorizationHeaderParameters();
        if (!isset($authorizationHeaderParameters[$name])) {
            throw new Exception("Authorization parameters does not contain '$name'");
        }

        return $authorizationHeaderParameters[$name];
    }

    /**
     * @return array
     *
     * @throws Exception
     */
    private function signatureHeaderParameters()
    {
        if (!isset($this->_signatureParameters)) {
            $parser = new SignatureParametersParser($this->signatureHeaderValue('Signature'));
            $this->_signatureParameters = $parser->parse();
        }

        return $this->_signatureParameters;
    }

    /**
     * @return array
     *
     * @throws Exception
     */
    private function authorizationHeaderParameters()
    {
        if (!isset($this->_authorizationParameters)) {
            $parser = new SignatureParametersParser($this->signatureHeaderValue('Authorization'));
            $this->_authorizationParameters = $parser->parse();
        }

        return $this->_authorizationParameters;
    }

    /**
     * @return string
     */
    private function signatureHeaderValue($headerName)
    {
        $headerLine = $this->fetchHeader($headerName);
        switch ($headerName) {
            case 'Authorization':
                return substr($headerLine, strlen('Signature '));
                break;
            case 'Signature':
                return $headerLine;
                break;
        }
    }

    /**
     * @param $name
     *
     * @return string|null
     */
    private function fetchHeader($name)
    {
        // grab the most recently set header.
        $header = $this->message->getHeader($name);

        return end($header);
    }
}
