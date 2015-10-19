<?php

namespace HttpSignatures;

use Symfony\Component\HttpFoundation\Request;

class Signature
{
    /** @var Request|SymfonyRequestMessage */
    private $message;

    /** @var Key */
    private $key;

    /** @var HmacAlgorithm */
    private $algorithm;

    /** @var HeaderList */
    private $headerList;

    /**
     * @param Request|SymfonyRequestMessage $message
     * @param Key                           $key
     * @param HmacAlgorithm                 $algorithm
     * @param HeaderList                    $headerList
     */
    public function __construct($message, $key, $algorithm, $headerList)
    {
        $this->message = $message;
        $this->key = $key;
        $this->algorithm = $algorithm;
        $this->headerList = $headerList;
    }

    public function string()
    {
        return $this->algorithm->sign(
            $this->key->secret,
            $this->signingString()->string()
        );
    }

    private function signingString()
    {
        return new SigningString(
            $this->headerList,
            $this->message
        );
    }
}
