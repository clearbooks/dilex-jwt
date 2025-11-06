<?php
/**
 * Created by PhpStorm.
 * User: daniel
 * Date: 03/09/15
 * Time: 11:44
 */

namespace Clearbooks\Dilex;

use Clearbooks\Dilex\JwtGuard\MockNoJwtRequiredController;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

class JwtGuardTest extends TestCase
{
    private $request;

    public function setUp(): void
    {
        $this->request = new Request();
        $this->request->headers->set('Authorization', 'Token');
    }

    private function assert403(JsonResponse $jsonResponse)
    {
        $this->assertEquals(403, $jsonResponse->getStatusCode());
    }

    #[Test]
    public function givenUnauthorisedRequest_return403()
    {
        $guard = new JwtGuard( new JwtGuard\RequestAuthoriserStub( false ) );
        $this->assert403( $guard->execute( new Request ) );
    }

    #[Test]
    public function givenUnauthorisedRequest_returnError()
    {
        $guard = new JwtGuard( new JwtGuard\RequestAuthoriserStub( false ) );
        $this->assertContains( 'error', array_keys( json_decode( $guard->execute( new Request )->getContent(), true ) ) );
    }

    #[Test]
    public function givenValidRequest_whenExecuting_returnNull()
    {
        $guard = new JwtGuard( new JwtGuard\RequestAuthoriserStub( true ) );
        $this->assertNull($guard->execute($this->request));
    }

    #[Test]
    public function givenInvalidRequest_AndControllerDoesNotRequireJwt_whenExecuting_returnNull()
    {
        $guard = new JwtGuard( new JwtGuard\RequestAuthoriserStub( false ) );
        $this->request->attributes->set('_controller', MockNoJwtRequiredController::class );
        $this->assertNull($guard->execute($this->request));
    }
}
