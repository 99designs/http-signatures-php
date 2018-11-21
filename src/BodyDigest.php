<?php

namespace HttpSignatures;

class BodyDigest
{
    /** @var string */
    const validHashes =
      'sha sha1 sha256 sha512';

    /** @var string */
    private $hashName;

    /** @var string */
    private $digestHeaderPrefix;

    /**
     * @param string $hashAlgorithm
     *
     * @return BodyDigest
     *
     * @throws DigestException
     */
    public function __construct($hashAlgorithm = null)
    {
        // Default to sha256 if no spec provided
        if (is_null($hashAlgorithm) || '' == $hashAlgorithm) {
            $hashAlgorithm = 'sha256';
        }

        // Normalise to openssl type for switch - remove dashes and lowercase
        $hashAlgorithm = strtolower(str_replace('-', '', $hashAlgorithm));
        if (!$this->isValidDigestSpec($hashAlgorithm)) {
            throw new DigestException("'$hashAlgorithm' is not a valid Digest algorithm specifier");
        }
        switch ($hashAlgorithm) {
            case 'sha':
            case 'sha1':
                $this->hashName = 'sha1';
                $this->digestHeaderPrefix = 'SHA';
                break;
            case 'sha256':
                $this->hashName = 'sha256';
                $this->digestHeaderPrefix = 'SHA-256';
                break;
            case 'sha512':
                $this->hashName = 'sha512';
                $this->digestHeaderPrefix = 'SHA-512';
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

    /**
     * @param RequestInterface $message
     *
     * @return BodyDigest
     *
     * @throws DigestException
     */
    public static function fromMessage($message)
    {
        $digestLine = $message->getHeader('Digest');
        if (!$digestLine) {
            throw new DigestException('No Digest header in message');
        }

        $digestAlgorithm = self::getDigestAlgorithm($digestLine[0]);

        return new BodyDigest($digestAlgorithm);
    }

    /**
     * @param string $digestLine
     *
     * @return string
     *
     * @throws DigestException
     */
    private static function getDigestAlgorithm($digestLine)
    {
        // simple test if properly delimited, but see below
        if (!strpos($digestLine, '=')) {
            throw new DigestException('Digest header does not appear to be correctly formatted');
        }

        // '=' is valid base64, so raw base64 may match
        $hashAlgorithm = explode('=', $digestLine)[0];
        if (!self::isValidDigestSpec($hashAlgorithm)) {
            throw new DigestException("'$hashAlgorithm' in Digest header is not a valid algorithm");
        }

        return $hashAlgorithm;
    }

    public function isValid($message)
    {
        $receivedDigest = $message->getHeader('Digest')[0];
        $expectedDigest = $this->getDigestHeaderLinefromBody($message->getBody());

        return hash_equals($receivedDigest, $expectedDigest);
    }

    /**
     * @param string $digestSpec
     *
     * @return bool
     */
    public static function isValidDigestSpec($digestSpec)
    {
        $digestSpec = strtolower(str_replace('-', '', $digestSpec));
        $validHashes = explode(' ', self::validHashes);

        return in_array($digestSpec, $validHashes);
    }
}
