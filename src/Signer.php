<?php

namespace HttpSignatures;

use Psr\Http\Message\RequestInterface;

class Signer
{
    const defaultHttpDigest       = 'sha256';
    const defaultHttpDigestPrefix = 'SHA-256';

    /** @var Key */
    private $key;

    /** @var HmacAlgorithm */
    private $algorithm;

    /** @var HeaderList */
    private $headerList;

    /**
     * @param Key           $key
     * @param HmacAlgorithm $algorithm
     * @param HeaderList    $headerList
     */
    public function __construct($key, $algorithm, $headerList)
    {
        $this->key = $key;
        $this->algorithm = $algorithm;
        $this->headerList = $headerList;
    }

    /**
     * @param RequestInterface $message
     * @return RequestInterface
     */
    public function sign($message, $withDigest = false)
    {
        if ($withDigest) {
            $message = $this->addDigest($message);
        };
        $signatureParameters = $this->signatureParameters($message);
        $message = $message->withAddedHeader("Signature", $signatureParameters->string());
        $message = $message->withAddedHeader("Authorization", "Signature " . $signatureParameters->string());
        return $message;
    }

    /**
     * @param RequestInterface $message
     * @return RequestInterface
     */
    private function addDigest($message)
    {
        if (!array_search('digest', $this->headerList->names)) {
            $this->headerList->names[] = 'digest';
        };
        while ($message->getHeader('Digest')) {
            $message = $message->withoutHeader('Digest');
        };
        $message = $message->withHeader(
        'Digest',
        self::defaultHttpDigestPrefix . '=' . base64_encode(
          hash(
            self::defaultHttpDigest, $message->getBody(), true
          )
        )
      );
        return $message;
    }

    /**
     * @param RequestInterface $message
     * @return SignatureParameters
     */
    private function signatureParameters($message)
    {
        return new SignatureParameters(
            $this->key,
            $this->algorithm,
            $this->headerList,
            $this->signature($message)
        );
    }

    /**
     * @param RequestInterface $message
     * @return Signature
     */
    private function signature($message)
    {
        return new Signature(
            $message,
            $this->key,
            $this->algorithm,
            $this->headerList
        );
    }
}
