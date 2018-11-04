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
    private $_parameters;

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
            $signedString = new SigningString($this->headerList(), $this->message);

            return $this->algorithm()->verify(
                $signedString->string(),
                $this->parameter('signature'),
                $this->key()->getVerifyingKey()
            );
        } catch (SignatureParseException $e) {
            return false;
        } catch (UnknownKeyException $e) {
            return false;
        } catch (SignedHeaderNotPresentException $e) {
            return false;
        }
    }

    /**
     * @return Key
     */
    private function key()
    {
        return $this->keyStore->fetch($this->parameter('keyId'));
    }

    /**
     * @return HmacAlgorithm
     */
    private function algorithm()
    {
        return Algorithm::create($this->parameter('algorithm'));
    }

    /**
     * @return HeaderList
     */
    private function headerList()
    {
        return HeaderList::fromString($this->parameter('headers'));
    }

    /**
     * @param string $name
     *
     * @return string
     *
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
     *
     * @throws Exception
     */
    private function signatureHeader()
    {
        if ($signature = $this->fetchHeader('Signature')) {
            return $signature;
        } elseif ($authorization = $this->fetchHeader('Authorization')) {
            return substr($authorization, strlen('Signature '));
        } else {
            throw new Exception('HTTP message has no Signature or Authorization header');
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
