<?php

namespace HttpSignatures;

class BodyDigest
{
    public $hashName;
    public $digestHeaderPrefix;

    /**
     * @param string $name
     * @return BodyDigest
     * @throws Exception
     */
    public function __construct($hashAlgorithm = null)
    {
        switch (strtolower(str_replace("-", '', $hashAlgorithm))) {
        case 'sha':
        case 'sha1':
            $this->hashName = 'sha1';
            $this->digestHeaderPrefix = 'SHA';
            break;
        case 'sha256':
        case null:
        case '':
            $this->hashName = 'sha256';
            $this->digestHeaderPrefix = 'SHA-256';
            break;
        case 'sha512':
            $this->hashName = 'sha512';
            $this->digestHeaderPrefix = 'SHA-512';
            break;
        default:
            throw new DigestException("Digest algorithm parameter '$name' not understood");
            break;
        }
    }

    public function digestInHeaderList($headerList)
    {
        if (!array_search('digest', $headerList->names)) {
            $headerList->names[] = 'digest';
        };
        return $headerList;
    }

    public function setDigestHeader($message)
    {
        $message = $message->withoutHeader('Digest')
            ->withHeader(
                'Digest',
                $this->getDigestHeaderLinefromBody($message->getBody()));
        return $message;
    }

    public function getDigestHeaderLinefromBody($messageBody)
    {
        if (is_null($messageBody)) {
            $messageBody = '';
        };
        return $this->digestHeaderPrefix . '=' . base64_encode(hash($this->hashName, $messageBody, true));
    }

    public static function fromMessage($message)
    {
        if (! $digestLine = $message->getHeader('Digest')) {
            throw new DigestException("No Digest header in message");
        }
        try {
            return new BodyDigest(explode("=", $digestLine[0])[0]);
        } catch (DigestException $e) {
            throw $e;
        }
    }

    public function isValid($message)
    {
        return $message->hasHeader('Signature') &&
        ($message->getHeader('Digest')[0] ==
        $this->getDigestHeaderLinefromBody($message->getBody()));
    }
}
