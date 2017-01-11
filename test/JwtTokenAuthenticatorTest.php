<?php
/**
 * Created by PhpStorm.
 * User: daniel
 * Date: 02/09/15
 * Time: 14:07
 */

namespace Clearbooks\Dilex\JwtGuard;

use DateTime;
use Emarref\Jwt\Algorithm\Hs512;
use Emarref\Jwt\Algorithm\None;
use Emarref\Jwt\Claim\PublicClaim;
use Emarref\Jwt\Encryption\Factory as EncryptionFactory;
use Emarref\Jwt\Jwt;
use Emarref\Jwt\Token;
use Symfony\Component\HttpFoundation\Request;

class JwtTokenAuthenticatorTest extends \PHPUnit_Framework_TestCase
{
    const USER_ID = '1';
    const GROUP_ID = '1';
    const APP_ID = 'test';
    const IS_ADMIN = true;

    const WITH = 0;

    const WITHOUT = 1;

    const VALID_USER_ID = 0;

    const VALID_APP_ID = 1;

    const VALID_GROUP_ID = 2;

    const VALID_EXPIRY_DATE = 3;

    const VALID_IS_ADMIN = 4;

    const VALID_SEGMENTS = 5;


    /**
     * @var Hs512
     */
    private $algorithm;

    /**
     * @var JwtTokenAuthenticator
     */
    private $auth;

    /**
     * @var Token
     */
    private $token;

    /**
     * @var AppIdProvider
     */
    private $appIds;

    /**
     * @var array
     */
    private $testSegments;

    /**
     * @return string
     */
    private function getNonExpiredDate()
    {
        $expDate = new DateTime();
        $expDate->modify('+1 day');
        return $expDate->format('U');
    }

    /**
     * @return string
     */
    private function getExpiredDate()
    {
        $date = new DateTime();
        $date->modify('-1 day');
        return $date->format('U');
    }

    /**
     * @param array $spec
     * @return Token
     */
    private function getTokenWithout( array $spec )
    {
        $mappings = [
            self::VALID_USER_ID => new PublicClaim( 'userId', self::USER_ID ),
            self::VALID_GROUP_ID => new PublicClaim( 'groupId', self::GROUP_ID ),
            self::VALID_APP_ID => new PublicClaim( 'appId', self::APP_ID ),
            self::VALID_EXPIRY_DATE => new PublicClaim('exp', $this->getNonExpiredDate()),
            self::VALID_IS_ADMIN => new PublicClaim('isAdmin', self::IS_ADMIN),
            self::VALID_SEGMENTS => new PublicClaim('segments', $this->testSegments)
        ];

        $spec = array_diff( array_keys( $mappings ), $spec );

        $token = new Token;
        foreach ( $spec as $desiredClaim ) {
            $token->addClaim( $mappings[$desiredClaim] );
        }
        return $token;
    }

    /**
     * @return Token
     */
    private function getTokenWithNoAppId()
    {
        return $this->getTokenWithout( [self::VALID_APP_ID] );
    }

    /**
     * @return Token
     */
    private function getTokenWithNoUserId()
    {
        return $this->getTokenWithout( [self::VALID_USER_ID] );
    }

    /**
     * @return Token
     */
    private function getTokenWithNoGroupId()
    {
        return $this->getTokenWithout( [self::VALID_GROUP_ID] );
    }

    /**
     * @return Token
     */
    private function getTokenWithoutSegments()
    {
        return $this->getTokenWithout( [self::VALID_SEGMENTS] );
    }

    /**
     * @return Token
     */
    private function getTokenWithInvalidAppId()
    {
        $token = $this->getTokenWithout( [self::VALID_APP_ID] );
        $token->addClaim( new PublicClaim( 'appId', 'dogs' ) );
        return $token;
    }

    /**
     * @return Token
     */
    private function getValidToken()
    {
        return $this->getTokenWithout( [] );
    }

    /**
     * @return Token
     */
    private function getExpiredToken()
    {
        $token = $this->getTokenWithout( [self::VALID_EXPIRY_DATE] );
        $token->addClaim(new PublicClaim('exp', $this->getExpiredDate()));
        return $token;
    }

    /**
     * @param Token $token
     * @return bool
     */
    private function authoriseToken( Token $token )
    {
        return $this->auth->isAuthorised( new MockTokenRequest( $this->serialiseToken( $token ) ) );
    }

    /**
     * @param $token
     * @return string
     */
    private function serialiseToken( $token )
    {
        return ( new Jwt )->serialize( $token, EncryptionFactory::create( $this->algorithm ) );
    }

    /**
     * Set up
     */
    public function setUp()
    {
        $this->appIds = new StaticAppIdProvider( [self::APP_ID] );
        $this->algorithm = new Hs512( "shhh... it's a secret" );
        $this->auth = new JwtTokenAuthenticator( new Jwt, $this->algorithm, $this->appIds );
        $this->token = new Token();
        $this->testSegments = [ [ 'segmentId' => 1, 'isLocked' => false, 'priority' => 10 ] ];
    }

    /**
     * @test
     */
    public function givenNoneAlgorithm_returnFalse()
    {
        $auth = new JwtTokenAuthenticator( $jwt = new Jwt, new None, $this->appIds );
        $this->assertFalse( $auth->isAuthorised( new MockTokenRequest( $jwt->serialize( new Token, EncryptionFactory::create( new None ) ) ) ) );
    }

    /**
     * @test
     */
    public function givenNoAuthorizationHeader_whenCallingVerifyToken_returnFalse()
    {
        $this->assertFalse( $this->auth->isAuthorised( new Request ) );
    }

    /**
     * @test
     */
    public function givenNoAuthorisationAttempted_whenGettingCredentials_returnNull()
    {
        $this->assertNull( $this->auth->getGroupId() );
        $this->assertNull( $this->auth->getUserId() );
    }

    /**
     * @test
     */
    public function givenFailedAuthorisation_whenGettingCredentials_returnNull()
    {
        $this->assertFalse( $this->auth->isAuthorised( new Request ) );
        $this->assertNull( $this->auth->getGroupId() );
        $this->assertNull( $this->auth->getUserId() );
    }

    /**
     * @test
     */
    public function givenValidToken_whenVerifyingToken_returnTrue()
    {
        $this->assertTrue( $this->authoriseToken( $this->getValidToken() ) );
    }

    /**
     * @test
     */
    public function givenTokenWithoutGroupId_whenVerifyingToken_returnTrue()
    {
        $this->assertTrue( $this->authoriseToken( $this->getTokenWithNoGroupId() ) );
    }

    /**
     * @test
     */
    public function givenTokenWithoutSegments_whenVerifyingToken_returnTrue()
    {
        $this->assertTrue( $this->authoriseToken( $this->getTokenWithoutSegments() ) );
    }

    /**
     * @test
     */
    public function givenExpiredToken_whenVerifyingToken_returnFalse()
    {
        $this->assertFalse( $this->authoriseToken( $this->getExpiredToken() ) );
    }

    /**
     * @test
     */
    public function givenTokenWithoutUserId_whenVerifyingToken_returnFalse()
    {
        $this->assertFalse( $this->authoriseToken( $this->getTokenWithNoUserId() ) );
    }

    /**
     * @test
     */
    public function givenTokenWithInvalidAppId_whenVerifyingToken_returnFalse()
    {
        $this->assertFalse( $this->authoriseToken( $this->getTokenWithInvalidAppId() ) );
    }

    /**
     * @test
     */
    public function givenTokenWithNoAppId_whenVerifyingToken_returnFalse()
    {
        $this->assertFalse( $this->authoriseToken( $this->getTokenWithNoAppId() ) );
    }

    /**
     * @test
     */
    public function givenTokenWithInvalidSignature_whenValidatingToken_returnFalse()
    {
        $this->auth = new JwtTokenAuthenticator( new Jwt, new Hs512( 'Nope' ), $this->appIds );
        $this->assertFalse( $this->authoriseToken( $this->getValidToken() ) );
    }

    /**
     * @test
     */
    public function givenTokenWithoutIsAdmin_whenGettingIsAdmin_returnFalse()
    {
        $this->authoriseToken($this->getTokenWithout([self::VALID_IS_ADMIN]));
        $this->assertFalse($this->auth->getIsAdmin());
    }

    /**
     * @test
     */
    public function givenTokenWithoutSegments_whenGettingSegments_returnsEmptyArray()
    {
        $this->authoriseToken($this->getTokenWithout([self::VALID_SEGMENTS]));
        $this->assertEmpty($this->auth->getSegments());
    }

    /**
     * @test
     */
    public function givenValidToken_whenSettingToken_getCorrectUserAndGroupIdAndIsAdmin()
    {
        $this->authoriseToken( $this->getValidToken() );
        $this->assertEquals(self::GROUP_ID, $this->auth->getGroupId());
        $this->assertEquals(self::USER_ID, $this->auth->getUserId());
        $this->assertEquals(self::IS_ADMIN, $this->auth->getIsAdmin());
        $this->assertEquals($this->testSegments, $this->auth->getSegments());
    }

    /**
     * @test
     */
    public function givenValidTokenAndBearerStringPresentInRequestHeader_WhenCallingIsAuthorised_ThenAuthorisationPasses()
    {
        $this->auth->isAuthorised( new MockTokenRequest( "Bearer ". $this->serialiseToken( $this->getValidToken() ) ) );
    }
}
