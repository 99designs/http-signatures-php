<?php

namespace HttpSignatures;

class BodyDigest
{
    /** @var string */
    private $hashName;

    /** @var string */
    private $digestHeaderPrefix;

    /**
     * @param string $name
     *
     * @return BodyDigest
     *
     * @throws DigestException
     */
    public function __construct($hashAlgorithm = null)
    {
        // Normalise to openssl type for switch - remove dashes and lowercase
        switch (strtolower(str_replace('-', '', $hashAlgorithm))) {
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
            throw new DigestException("Digest algorithm parameter '$hashAlgorithm' not understood");
            break;
        }
    }

    public function putDigestInHeaderList($headerList)
    {
        if (!array_search('digest', $headerList->names)) {
            $headerList->names[] = 'digest';
        }

        return $headerList;
    }

    public function setDigestHeader($message)
    {
        $message = $message->withoutHeader('Digest')
            ->withHeader(
                'Digest',
                $this->getDigestHeaderLinefromBody($message->getBody())
            );

        return $message;
    }

    public function getDigestHeaderLinefromBody($messageBody)
    {
        if (is_null($messageBody)) {
            $messageBody = '';
        }

        return $this->digestHeaderPrefix.'='.base64_encode(hash($this->hashName, $messageBody, true));
    }

    public static function fromMessage($message)
    {
        if (!$digestLine = $message->getHeader('Digest')) {
            throw new DigestException('No Digest header in message');
        }
        $digestAlgorithm = self::getDigestAlgorithm($digestLine[0]);
        if ($digestAlgorithm) {
            return new BodyDigest($digestAlgorithm);
        } else {
            throw new DigestException('Digest header does not appear to be correctly formatted');
        }
    }

    private static function getDigestAlgorithm($digestLine)
    {
        try {
            return explode('=', $digestLine)[0];
        } catch (DigestException $e) {
            return false;
        }
    }

    public function isValid($message)
    {
        return
            $message->getHeader('Digest')[0] == $this->getDigestHeaderLinefromBody($message->getBody())
        ;
    }
}
