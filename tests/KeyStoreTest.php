<?php

namespace HttpSignatures\tests;

use HttpSignatures\KeyStore;
use HttpSignatures\Tests\TestKeys;

class KeyStoreTest extends \PHPUnit_Framework_TestCase
{
    private $testRsaPrivateKeyPEM;
    private $testRsaPublicKeyPEM;
    private $testRsaCert;

    public function setUp()
    {
        $privateKey = openssl_pkey_get_private(TestKeys::rsaPrivateKey);
        openssl_pkey_export($privateKey, $this->testRsaPrivateKeyPEM);
        $publicKey = openssl_pkey_get_private(TestKeys::rsaPrivateKey);
        $publicKeyDetails = openssl_pkey_get_details($publicKey);
        $this->testRsaPublicKeyPEM = $publicKeyDetails['key'];
        $this->testRsaCert = TestKeys::rsaCert;
    }

    /**
     * @expectedException \HttpSignatures\Exception
     */
    public function testFetchFail()
    {
        $ks = new KeyStore(['id' => 'secret']);
        $key = $ks->fetch('nope');
    }

    public function testFetchHmacSuccess()
    {
        $ks = new KeyStore(['hmacsecret' => 'ThisIsASecretKey']);
        $key = $ks->fetch('hmacsecret');
        $this->assertEquals(
            ['hmacsecret', 'ThisIsASecretKey', 'ThisIsASecretKey'],
            [$key->getId(), $key->getVerifyingKey(), $key->getSigningKey()]
        );
    }

    public function testParseX509inObject()
    {
        $ks = new KeyStore(['rsaCert' => TestKeys::rsaCert]);
        $publicKey = $ks->fetch('rsaCert')->getVerifyingKey();
        $this->assertEquals(trim(TestKeys::rsaPublicKey), trim($publicKey));
    }

    public function testParseRsaPublicKeyinObject()
    {
        $ks = new KeyStore(['rsaPubKey' => TestKeys::rsaPublicKey]);
        $publicKey = $ks->fetch('rsaPubKey')->getVerifyingKey();
        $this->assertEquals(trim(TestKeys::rsaPublicKey), trim($publicKey));
    }

    public function testParsePrivateKeyinObject()
    {
        $ks = new KeyStore(['rsaPrivKey' => TestKeys::rsaPrivateKey]);
        $publicKey = $ks->fetch('rsaPrivKey')->getSigningKey();
        $this->assertEquals($this->testRsaPrivateKeyPEM, $publicKey);
    }

    public function testFetchRsaSigningKeySuccess()
    {
        $ks = new KeyStore(['rsakey' => TestKeys::rsaPrivateKey]);
        $key = $ks->fetch('rsakey');
        openssl_pkey_export($key->getSigningKey(), $keyStoreSigningKey);
        $this->assertEquals(
            ['rsakey', $this->testRsaPrivateKeyPEM, $this->testRsaPublicKeyPEM],
            [$key->getId(), $keyStoreSigningKey, $key->getVerifyingKey()]
        );
    }

    public function testFetchRsaVerifyingKeyFromCertificateSuccess()
    {
        $ks = new KeyStore(['rsacert' => TestKeys::rsaCert]);
        $key = $ks->fetch('rsacert');
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $this->assertEquals(
            ['rsacert', null, $this->testRsaPublicKeyPEM],
            [$key->getId(), $key->getSigningKey(), $keyStoreVerifyingKey]
        );
    }

    public function testFetchRsaVerifyingKeyFromPublicKeySuccess()
    {
        $ks = new KeyStore(['rsapubkey' => TestKeys::rsaPublicKey]);
        $key = $ks->fetch('rsapubkey');
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $this->assertEquals(
            ['rsapubkey', null, $this->testRsaPublicKeyPEM],
            [$key->getId(), $key->getSigningKey(), $keyStoreVerifyingKey]
        );
    }
}
