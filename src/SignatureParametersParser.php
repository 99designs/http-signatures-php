<?php

namespace HttpSignatures;

use HttpSignatures\Exception;

class SignatureParametersParser
{
    private $input;

    public function __construct($input)
    {
        $this->input = $input;
    }

    public function parse()
    {
        return $this->pairsToAssociative(
            $this->arrayOfPairs()
        );
    }

    private function pairsToAssociative($pairs)
    {
        $result = array();
        foreach ($pairs as $pair) {
            $result[$pair[0]] = $pair[1];
        }
        return $result;
    }

    private function arrayOfPairs()
    {
        return array_map(
            array($this, 'pair'),
            $this->segments()
        );
    }

    private function segments()
    {
        return explode(',', $this->input);
    }

    private function pair($segment)
    {
        $segmentPattern = '/\A(keyId|algorithm|headers|signature)="(.*)"\z/';
        $matches = array();
        $result = preg_match($segmentPattern, $segment, $matches);
        if ($result !== 1) {
            throw new Exception("Signature parameters segment '$segment' invalid");
        }
        array_shift($matches);
        return $matches;
    }
}
