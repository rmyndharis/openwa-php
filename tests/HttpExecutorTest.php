<?php

declare(strict_types=1);

namespace OpenWA\Tests;

use PHPUnit\Framework\TestCase;

class HttpExecutorTest extends TestCase
{
    /**
     * The path is appended to the base URL, so one without a leading "/" could move the
     * host and carry the API key elsewhere. It is refused before anything is sent.
     */
    public function testPathWithoutLeadingSlashIsRefusedBeforeSending(): void
    {
        $backend = new MockBackend();
        $client = $backend->makeClient();
        foreach (['.evil.example/x', '@evil.example/x', 'api/sessions'] as $path) {
            try {
                $client->request('GET', $path);
                $this->fail("Expected InvalidArgumentException for {$path}");
            } catch (\InvalidArgumentException $e) {
                $this->assertStringContainsString('path must begin with "/"', $e->getMessage());
            }
        }
        $this->assertSame([], $backend->calls());
    }

    /**
     * A client that is dumped while a call is debugged must not write its bearer-equivalent key out.
     */
    public function testTheApiKeyDoesNotAppearWhenTheClientIsDumped(): void
    {
        $key = 'owa_k1_do_not_print';
        $client = (new MockBackend())->makeClient('http://localhost:2785', $key);

        $this->assertStringNotContainsString($key, print_r($client, true));
        ob_start();
        var_dump($client);
        $this->assertStringNotContainsString($key, (string) ob_get_clean());
        // The other ways a value is written out: an export, a cast, and what a framework dumper reads.
        $this->assertStringNotContainsString($key, var_export($client, true));
        $executor = (new \ReflectionObject($client))->getProperty('http')->getValue($client);
        $this->assertStringNotContainsString($key, var_export($executor, true));
        $this->assertStringNotContainsString($key, json_encode((array) $executor, JSON_PARTIAL_OUTPUT_ON_ERROR) ?: '');
        $this->assertStringNotContainsString($key, print_r((array) $executor, true));
        // and the key is still what goes out on the wire
        $backend = (new MockBackend())->on(200, []);
        $backend->makeClient('http://localhost:2785', $key)->request('GET', '/api/anything');
        $this->assertSame($key, $backend->lastCall()['headers']['x-api-key'] ?? null);
    }

    /**
     * A default header often carries the credential of a proxy in front of the gateway: it is held out of
     * the property table with the key, and only its name shows.
     */
    public function testDefaultHeaderValuesDoNotAppearWhenTheClientIsDumpedEither(): void
    {
        $secret = 'PROXYSECRET';
        $backend = (new MockBackend())->on(200, []);
        $client = new \OpenWA\Client([
            'baseUrl' => 'http://localhost:2785',
            'apiKey' => 'owa_k1_test',
            'httpClient' => $backend->httpClient(),
            'defaultHeaders' => ['CF-Access-Client-Secret' => $secret],
        ]);
        $executor = (new \ReflectionObject($client))->getProperty('http')->getValue($client);

        $this->assertStringNotContainsString($secret, print_r($client, true));
        $this->assertStringContainsString('CF-Access-Client-Secret', print_r($client, true));
        $this->assertStringNotContainsString($secret, var_export($client, true));
        $this->assertStringNotContainsString($secret, var_export($executor, true));
        $this->assertStringNotContainsString($secret, print_r((array) $executor, true));
        // and the value is still what goes out on the wire
        $client->request('GET', '/api/anything');
        $this->assertSame($secret, $backend->lastCall()['headers']['cf-access-client-secret'] ?? null);
    }

    /** A copy would have no key and no headers, since both belong to the object they were given to. */
    public function testAnExecutorCannotBeCloned(): void
    {
        $client = (new MockBackend())->makeClient();
        $executor = (new \ReflectionObject($client))->getProperty('http')->getValue($client);

        $this->expectException(\Error::class);
        $copy = clone $executor;
        $this->assertNotSame($executor, $copy);
    }

    public function testQueryParamsExtendAQueryAlreadyInThePath(): void
    {
        $backend = (new MockBackend())->on(200, [])->on(200, []);
        $client = $backend->makeClient();

        $client->request('GET', '/api/anything?a=1', ['b' => 2, 'skip' => null]);
        $this->assertSame('/api/anything', $backend->lastCall()['path']);
        $this->assertSame('a=1&b=2', $backend->lastCall()['query']);

        $client->request('GET', '/api/anything', ['q' => 'a b']);
        $this->assertSame('q=a%20b', $backend->lastCall()['query']);
    }
}
