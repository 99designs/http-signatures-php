<?php

namespace HttpSignatures\tests;

use HttpSignatures\KeyStore;
use HttpSignatures\Key;
use HttpSignatures\Tests\TestKeys;

class KeyStoreRsaTest extends \PHPUnit_Framework_TestCase
{
    /** @var string */
    var $testRsaPrivateKeyPEM;

    /** @var string */
    var $testRsaPublicKeyPEM;

    public function setUp() {

      openssl_pkey_export(
        openssl_pkey_get_private(TestKeys::rsaKey),
        $this->testRsaPrivateKeyPEM
      );
      $this->testRsaPublicKeyPEM = openssl_pkey_get_details(
        openssl_get_publickey(TestKeys::rsaCert)
        )['key'];
    }

    public function testFetchRsaSigningKeySuccess()
    {
        $ks = new KeyStore(['rsakey' => TestKeys::rsaKey]);
        $key = $ks->fetch('rsakey');
        openssl_pkey_export($key->getSigningKey(), $keyStoreSigningKey);
        $this->assertEquals([ 'rsakey', $this->testRsaPrivateKeyPEM, null, 'rsa'], [
          $key->getId(), $keyStoreSigningKey, $key->getVerifyingKey(), $key->getType()]);
    }

    public function testFetchRsaVerifyingKeySuccess()
    {
        $ks = new KeyStore(['rsacert' => TestKeys::rsaCert]);
        $key = $ks->fetch('rsacert');
        $keyStoreVerifyingKey = openssl_pkey_get_details($key->getVerifyingKey())['key'];
        $this->assertEquals([ 'rsacert', null, $this->testRsaPublicKeyPEM, 'rsa'], [
          $key->getId(), $key->getSigningKey(), $keyStoreVerifyingKey, $key->getType()]);
    }

    public function testFetchRsaBothSuccess()
    {
        $ks = new KeyStore(['rsaboth' => [TestKeys::rsaCert, TestKeys::rsaKey]]);
        $key = $ks->fetch('rsaboth');
        $keyStoreVerifyingKey = openssl_pkey_get_details($key->getVerifyingKey())['key'];
        openssl_pkey_export($key->getSigningKey(), $keyStoreSigningKey);
        $this->assertEquals([ 'rsaboth', $this->testRsaPrivateKeyPEM, $this->testRsaPublicKeyPEM, 'rsa'], [
          $key->getId(), $keyStoreSigningKey, $keyStoreVerifyingKey, $key->getType()]);
    }

    public function testFetchRsaBothSuccessSwitched()
    {
        $ks = new KeyStore(['rsabothswitch' => [TestKeys::rsaKey, TestKeys::rsaCert]]);
        $key = $ks->fetch('rsabothswitch');
        $keyStoreVerifyingKey = openssl_pkey_get_details($key->getVerifyingKey())['key'];
        openssl_pkey_export($key->getSigningKey(), $keyStoreSigningKey);
        $this->assertEquals([ 'rsabothswitch', $this->testRsaPrivateKeyPEM, $this->testRsaPublicKeyPEM, 'rsa'], [
          $key->getId(), $keyStoreSigningKey, $keyStoreVerifyingKey, $key->getType()]);
    }

    /**
     * @expectedException HttpSignatures\KeyException
     */
     public function testRsaMismatch()
    {
        $privateKey = openssl_pkey_new([
          'private_key_type' => 'OPENSSL_KEYTYPE_RSA',
          'private_key_bits' => 1024 ]
        );
        $ks = new Key('badpki', [TestKeys::rsaCert, $privateKey]);
    }
}
