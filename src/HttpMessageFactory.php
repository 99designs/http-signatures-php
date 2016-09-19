<?php

namespace HttpSignatures;

use Psr\Http\Message\UploadedFileInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Request;
use Zend\Diactoros\ServerRequest;
use Zend\Diactoros\ServerRequestFactory as DiactorosRequestFactory;
use Zend\Diactoros\Stream as DiactorosStream;
use Zend\Diactoros\UploadedFile as DiactorosUploadedFile;

/**
 * Modified version of Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory (by Kévin Dunglas <dunglas@gmail.com>)
 *
 * Builds Psr\HttpMessage instances using the Zend Diactoros implementation.
 * But keeps the query string ordering in tact from the original request
 */
class HttpMessageFactory extends DiactorosFactory
{
    /**
     * {@inheritdoc}
     */
    public function createRequest(Request $symfonyRequest)
    {
        $server = DiactorosRequestFactory::normalizeServer($symfonyRequest->server->all());
        $headers = $symfonyRequest->headers->all();

        try {
            $body = new DiactorosStream($symfonyRequest->getContent(true));
        } catch (\LogicException $e) {
            $body = new DiactorosStream('php://temp', 'wb+');
            $body->write($symfonyRequest->getContent());
        }

        // use raw QUERY_STRING to avoid normalizing it
        if (null !== $qs = $symfonyRequest->server->get('QUERY_STRING')) {
            $qs = '?'.$qs;
        }

        $uri = $symfonyRequest->getSchemeAndHttpHost().$symfonyRequest->getBaseUrl().$symfonyRequest->getPathInfo().$qs;

        $request = new ServerRequest(
            $server,
            DiactorosRequestFactory::normalizeFiles($this->getFiles($symfonyRequest->files->all())),
            $uri,
            $symfonyRequest->getMethod(),
            $body,
            $headers
        );

        $request = $request
            ->withCookieParams($symfonyRequest->cookies->all())
            ->withQueryParams($symfonyRequest->query->all())
            ->withParsedBody($symfonyRequest->request->all())
        ;

        foreach ($symfonyRequest->attributes->all() as $key => $value) {
            $request = $request->withAttribute($key, $value);
        }

        return $request;
    }

    /**
     * Converts Symfony uploaded files array to the PSR one.
     *
     * @param array $uploadedFiles
     *
     * @return array
     */
    private function getFiles(array $uploadedFiles)
    {
        $files = [];

        foreach ($uploadedFiles as $key => $value) {
            if ($value instanceof UploadedFile) {
                $files[$key] = $this->createUploadedFile($value);
            } else {
                $files[$key] = $this->getFiles($value);
            }
        }

        return $files;
    }

    /**
     * Creates a PSR-7 UploadedFile instance from a Symfony one.
     *
     * @param UploadedFile $symfonyUploadedFile
     *
     * @return UploadedFileInterface
     */
    private function createUploadedFile(UploadedFile $symfonyUploadedFile)
    {
        return new DiactorosUploadedFile(
            $symfonyUploadedFile->getRealPath(),
            $symfonyUploadedFile->getSize(),
            $symfonyUploadedFile->getError(),
            $symfonyUploadedFile->getClientOriginalName(),
            $symfonyUploadedFile->getClientMimeType()
        );
    }
}
