<?php

namespace HttpSignatures;

use HttpSignatures\Message\MessageInterface;
use HttpSignatures\Message\SymfonyRequestMessage;

class Signer
{
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

    public function sign($message)
    {
        if ($message instanceof \Symfony\Component\HttpFoundation\Request) {
            $message = new SymfonyRequestMessage($message);
        } else if (!($message instanceof MessageInterface)) {
            throw new \InvalidArgumentException("\$message should be instance of \\HttpSignatures\\Message\\MessageInterface, instace of " . get_class($message) . " given");
        }

        $signatureParameters = $this->signatureParameters($message);
        $message->setHeader("Signature", $signatureParameters->string());
        $message->setHeader("Authorization", "Signature " . $signatureParameters->string());
    }

    private function signatureParameters(MessageInterface $message)
    {
        return new SignatureParameters(
            $this->key,
            $this->algorithm,
            $this->headerList,
            $this->signature($message)
        );
    }

    private function signature(MessageInterface $message)
    {
        return new Signature(
            $message,
            $this->key,
            $this->algorithm,
            $this->headerList
        );
    }
}
