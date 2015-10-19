<?php

namespace HttpSignatures;

use Psr\Http\Message\MessageInterface;

class Verification
{
    /** @var MessageInterface */
    private $message;

    /** @var KeyStoreInterface */
    private $keyStore;

    /** @var array */
    private $_parameters;

    /**
     * @param MessageInterface $message
     * @param KeyStoreInterface $keyStore
     */
    public function __construct($message, $keyStore)
    {
        $this->message = $message;
        $this->keyStore = $keyStore;
    }

    /**
     * @return bool
     */
    public function isValid()
    {
        return $this->hasSignatureHeader() && $this->signatureMatches();
    }

    /**
     * @return bool
     */
    private function signatureMatches()
    {
        try {
            return $this->expectedSignatureBase64() === $this->providedSignatureBase64();
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
     * @return Signature
     */
    private function expectedSignature()
    {
        return new Signature(
            $this->message,
            $this->key(),
            $this->algorithm(),
            $this->headerList()
        );
    }

    /**
     * @return string
     * @throws Exception
     */
    private function providedSignatureBase64()
    {
        return $this->parameter('signature');
    }

    /**
     * @return Key
     * @throws Exception
     */
    private function key()
    {
        return $this->keyStore->fetch($this->parameter('keyId'));
    }

    /**
     * @return HmacAlgorithm
     * @throws Exception
     */
    private function algorithm()
    {
        return Algorithm::create($this->parameter('algorithm'));
    }

    /**
     * @return HeaderList
     * @throws Exception
     */
    private function headerList()
    {
        return HeaderList::fromString($this->parameter('headers'));
    }

    /**
     * @param string $name
     * @return string
     * @throws Exception
     */
    private function parameter($name)
    {
        $parameters = $this->parameters();
        if (!isset($parameters[$name])) {
            throw new Exception("Signature parameters does not contain '$name'");
        }

        return $parameters[$name];
    }

    /**
     * @return array
     * @throws Exception
     */
    private function parameters()
    {
        if (!isset($this->_parameters)) {
            $parser = new SignatureParametersParser($this->signatureHeader());
            $this->_parameters = $parser->parse();
        }

        return $this->_parameters;
    }

    /**
     * @return bool
     */
    private function hasSignatureHeader()
    {
        return $this->message->hasHeader('Signature') || $this->message->hasHeader('Authorization');
    }

    /**
     * @return string
     * @throws Exception
     */
    private function signatureHeader()
    {
        if ($signature = $this->fetchHeader('Signature')) {
            return $signature;
        } else if ($authorization = $this->fetchHeader('Authorization')) {
            return substr($authorization, strlen('Signature '));
        } else {
            throw new Exception("HTTP message has no Signature or Authorization header");
        }
    }

    /**
     * @param $name
     * @return string|null
     */
    private function fetchHeader($name)
    {
        return $this->message->getHeader($name);
    }
}
