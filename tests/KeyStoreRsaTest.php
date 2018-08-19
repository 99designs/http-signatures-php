<?php

namespace HttpSignatures\tests;

use HttpSignatures\KeyStore;
use HttpSignatures\Key;
use HttpSignatures\Tests\TestKeys;

class KeyStoreRsaTest extends \PHPUnit_Framework_TestCase
{
    public function testFetchRsaKeySuccess()
    {
        $ks = new KeyStore(['rsakey' => TestKeys::rsaKey]);
        $key = $ks->fetch('rsakey');
        $this->assertEquals('rsakey', $key->id);
        openssl_pkey_export(TestKeys::rsaKey, $privateKey);
        openssl_pkey_export(openssl_get_privatekey($key->privateKey), $inKey);
        $this->assertEquals([ 'rsakey', null, $privateKey, null, 'rsa'], [
          $key->id, $key->secret, $inKey, $key->certificate, $key->type]);
    }

    public function testFetchRsaCertificateSuccess()
    {
        $ks = new KeyStore(['rsacert' => TestKeys::rsaCert]);
        $key = $ks->fetch('rsacert');
        $this->assertEquals('rsacert', $key->id);
        openssl_x509_export(TestKeys::rsaCert, $certificate);
        openssl_x509_export($key->certificate, $inCert);
        $this->assertEquals([ 'rsacert', null, null, $certificate, 'rsa'], [
          $key->id, $key->secret, $key->privateKey, $inCert, $key->type]);
    }

    public function testFetchRsaBothSuccess()
    {
        $ks = new KeyStore(['rsaboth' => [TestKeys::rsaCert, TestKeys::rsaKey]]);
        $key = $ks->fetch('rsaboth');
        $this->assertEquals('rsaboth', $key->id);
        openssl_x509_export(TestKeys::rsaCert, $certificate);
        openssl_x509_export($key->certificate, $inCert);
        openssl_pkey_export(TestKeys::rsaKey, $privateKey);
        openssl_pkey_export($key->privateKey, $inKey);
        $this->assertEquals([ 'rsaboth', null, $privateKey, $certificate, 'rsa'], [
          $key->id, $key->secret, $inKey, $inCert, $key->type]);
    }

    public function testFetchRsaBothSuccessSwitched()
    {
        $ks = new KeyStore(['rsabothswitch' => [TestKeys::rsaKey, TestKeys::rsaCert]]);
        $key = $ks->fetch('rsabothswitch');
        $this->assertEquals('rsabothswitch', $key->id);
        openssl_x509_export(TestKeys::rsaCert, $certificate);
        openssl_x509_export($key->certificate, $inCert);
        openssl_pkey_export(TestKeys::rsaKey, $privateKey);
        openssl_pkey_export($key->privateKey, $inKey);
        $this->assertEquals([ 'rsabothswitch', null, $privateKey, $certificate, 'rsa'], [
          $key->id, $key->secret, $inKey, $inCert, $key->type]);
    }

    /**
     * @expectedException HttpSignatures\KeyException
     */
     public function testRsaMismatch()
    {
        $privateKey = openssl_pkey_new();
        $ks = new Key('badpki', [TestKeys::rsaCert, $privateKey]);
    }
}
