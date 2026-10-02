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
}
