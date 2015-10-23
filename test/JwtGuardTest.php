<?php
/**
 * Created by PhpStorm.
 * User: daniel
 * Date: 03/09/15
 * Time: 11:44
 */

namespace Clearbooks\Dilex\JwtGuard;


use Clearbooks\Dilex\JwtGuard;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

class JwtGuardTest extends \PHPUnit_Framework_TestCase
{

    private $request;

    public function setUp()
    {
        $this->request = new Request();
        $this->request->headers->set('Authorization', 'Token');
    }

    private function assert403(JsonResponse $jsonResponse)
    {
        $this->assertEquals(403, $jsonResponse->getStatusCode());
    }

    /**
     * @test
     */
    public function givenUnauthorisedRequest_return403()
    {
        $guard = new JwtGuard( new JwtGuard\RequestAuthoriserStub( false ) );
        $this->assert403( $guard->execute( new Request ) );
    }

    /**
     * @test
     */
    public function givenUnauthorisedRequest_returnError()
    {
        $guard = new JwtGuard( new JwtGuard\RequestAuthoriserStub( false ) );
        $this->assertContains( 'error', array_keys( json_decode( $guard->execute( new Request )->getContent(), true ) ) );

    }

    /**
     * @test
     */
    public function givenValidRequest_whenExecuting_returnNull()
    {
        $guard = new JwtGuard( new JwtGuard\RequestAuthoriserStub( true ) );
        $this->assertNull($guard->execute($this->request));
    }

    /**
     * @test
     */
    public function givenInvalidRequest_AndControllerDoesNotRequireJwt_whenExecuting_returnNull()
    {
        $guard = new JwtGuard( new JwtGuard\RequestAuthoriserStub( false ) );
        $this->request->attributes->set('_controller', MockNoJwtRequiredController::class );
        $this->assertNull($guard->execute($this->request));
    }

}
