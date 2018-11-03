<?php

namespace HttpSignatures\tests;

use HttpSignatures\Key;
use HttpSignatures\KeyStore;
use HttpSignatures\Tests\TestKeys;

class KeyStoreTest extends \PHPUnit_Framework_TestCase
{
    public function setUpRsa()
    {
        $privateKey = openssl_pkey_get_private(TestKeys::rsaPrivateKey);
        $publicKey = openssl_pkey_get_private(TestKeys::rsaPrivateKey);
        $publicKeyDetails = openssl_pkey_get_details($publicKey);
        openssl_pkey_export($privateKey, $this->testRsaPrivateKeyPEM);

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
            ['hmacsecret', 'ThisIsASecretKey', 'ThisIsASecretKey', 'secret'],
            [$key->getId(), $key->getVerifyingKey(), $key->getSigningKey(), $key->getType()]
        );
    }

    public function testParseX509inObject()
    {
        $this->setUpRsa();
        $keySpec = ['rsaCert' => [TestKeys::rsaCert]];
        $this->assertTrue(Key::hasX509Certificate($keySpec));

        $ks = new KeyStore($keySpec);
        $publicKey = $ks->fetch('rsaCert')->getVerifyingKey();
        $this->assertEquals('asymmetric', $ks->fetch('rsaCert')->getType());
        $this->assertEquals(trim(TestKeys::rsaPublicKey), trim($publicKey));
    }

    public function testParseRsaPublicKeyinObject()
    {
        $this->setUpRsa();
        $keySpec = ['rsaPubKey' => [TestKeys::rsaPublicKey]];
        $this->assertTrue(Key::hasPublicKey($keySpec));

        $ks = new KeyStore($keySpec);
        $publicKey = $ks->fetch('rsaPubKey')->getVerifyingKey();
        $this->assertEquals('asymmetric', $ks->fetch('rsaPubKey')->getType());
        $this->assertEquals(trim(TestKeys::rsaPublicKey), trim($publicKey));
    }

    public function testParsePrivateKeyinObject()
    {
        $this->setUpRsa();
        $keySpec = ['rsaPrivKey' => [TestKeys::rsaPrivateKey]];
        $this->assertTrue(Key::hasPrivateKey($keySpec));

        $ks = new KeyStore($keySpec);
        $publicKey = $ks->fetch('rsaPrivKey')->getSigningKey();
        $this->assertEquals('asymmetric', $ks->fetch('rsaPrivKey')->getType());
        $this->assertEquals($this->testRsaPrivateKeyPEM, $publicKey);
    }

    public function testFetchRsaSigningKeySuccess()
    {
        $this->setUpRsa();
        $ks = new KeyStore(['rsakey' => TestKeys::rsaPrivateKey]);
        $key = $ks->fetch('rsakey');
        openssl_pkey_export($key->getSigningKey(), $keyStoreSigningKey);
        $this->assertEquals(['rsakey', $this->testRsaPrivateKeyPEM, null, 'asymmetric'], [
            $key->getId(), $keyStoreSigningKey, $key->getVerifyingKey(), $key->getType()]);
    }

    public function testFetchRsaVerifyingKeyFromCertificateSuccess()
    {
        $this->setUpRsa();
        $ks = new KeyStore(['rsacert' => TestKeys::rsaCert]);
        $key = $ks->fetch('rsacert');
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $this->assertEquals(
            ['rsacert', null, $this->testRsaPublicKeyPEM, 'asymmetric'],
            [$key->getId(), $key->getSigningKey(), $keyStoreVerifyingKey, $key->getType()]
        );
    }

    public function testFetchRsaVerifyingKeyFromPublicKeySuccess()
    {
        $this->setUpRsa();
        $ks = new KeyStore(['rsapubkey' => TestKeys::rsaPublicKey]);
        $key = $ks->fetch('rsapubkey');
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $this->assertEquals(
            ['rsapubkey', null, $this->testRsaPublicKeyPEM, 'asymmetric'],
            [$key->getId(), $key->getSigningKey(), $keyStoreVerifyingKey, $key->getType()]
        );
    }

    public function testFetchRsaBothSuccess()
    {
        $this->setUpRsa();
        $ks = new KeyStore(['rsaboth' => [TestKeys::rsaCert, TestKeys::rsaPrivateKey]]);
        $key = $ks->fetch('rsaboth');
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $keyStoreSigningKey = $key->getSigningKey();
        $this->assertEquals(
            ['rsaboth', $this->testRsaPrivateKeyPEM, $this->testRsaPublicKeyPEM, 'asymmetric'],
            [$key->getId(), $keyStoreSigningKey, $keyStoreVerifyingKey, $key->getType()]
        );
    }

    public function testFetchRsaBothSuccessSwitched()
    {
        $this->setUpRsa();
        $ks = new KeyStore(['rsabothswitch' => [TestKeys::rsaPrivateKey, TestKeys::rsaCert]]);
        $key = $ks->fetch('rsabothswitch');
        $keyStoreVerifyingKey = $key->getVerifyingKey();
        $keyStoreSigningKey = $key->getSigningKey();
        $this->assertEquals(
            ['rsabothswitch', $this->testRsaPrivateKeyPEM, $this->testRsaPublicKeyPEM, 'asymmetric'],
            [$key->getId(), $keyStoreSigningKey, $keyStoreVerifyingKey, $key->getType()]
        );
    }

    /**
     * @expectedException \HttpSignatures\Exception
     */
    public function testRsaMismatch()
    {
        $this->setUpRsa();
        $privateKey = openssl_pkey_new([
            'private_key_type' => 'OPENSSL_KEYTYPE_RSA',
            'private_key_bits' => 1024]
        );
        $ks = new Key('badpki', [TestKeys::rsaCert, $privateKey]);
    }
}
