<?php

namespace HttpSignatures;

class SignatureParametersParser
{
    private $input;

    public function __construct($input)
    {
        $this->input = $input;
    }

    public function parse()
    {
        $result = $this->pairsToAssociative(
            $this->arrayOfPairs()
        );
        $this->validate($result);
        return $result;
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
            throw new SignatureParseException("Signature parameters segment '$segment' invalid");
        }
        array_shift($matches);

        return $matches;
    }

    private function validate($result)
    {
        $this->validateAllKeysArePresent($result);
    }

    private function validateAllKeysArePresent($result)
    {
        // Regexp in pair() ensures no unwanted keys exist.
        // Ensure that all wanted keys exist.
        $wanted = array('keyId', 'algorithm', 'headers', 'signature');
        $missing = array_diff($wanted, array_keys($result));
        if (!empty($missing)) {
            $csv = implode(', ', $missing);
            throw new SignatureParseException("Missing keys $csv");
        }
    }
}
