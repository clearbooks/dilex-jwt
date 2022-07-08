<?php
/**
 * Created by PhpStorm.
 * User: daniel
 * Date: 02/09/15
 * Time: 14:07
 */

namespace Clearbooks\Dilex\JwtGuard;

use DateTime;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use PHPUnit\Framework\TestCase;
use stdClass;
use Symfony\Component\HttpFoundation\Request;

class JwtTokenAuthenticatorTest extends TestCase
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
     * @var Key
     */
    private $key;

    /**
     * @var JwtTokenAuthenticator
     */
    private $auth;

    /**
     * @var stdClass
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
     * @return stdClass
     */
    private function getTokenWithout( array $spec )
    {
        $mappings = [
            self::VALID_USER_ID => [ 'userId', self::USER_ID ],
            self::VALID_GROUP_ID => [ 'groupId', self::GROUP_ID ],
            self::VALID_APP_ID => [ 'appId', self::APP_ID ],
            self::VALID_EXPIRY_DATE => ['exp', $this->getNonExpiredDate()],
            self::VALID_IS_ADMIN => ['isAdmin', self::IS_ADMIN],
            self::VALID_SEGMENTS => ['segments', $this->testSegments]
        ];

        $spec = array_diff( array_keys( $mappings ), $spec );

        $token = new stdClass();
        foreach ( $spec as $desiredClaim ) {
            $claim = $mappings[$desiredClaim];
            $token->{$claim[0]} = $claim[1];
        }
        return $token;
    }

    /**
     * @return stdClass
     */
    private function getTokenWithNoAppId()
    {
        return $this->getTokenWithout( [self::VALID_APP_ID] );
    }

    /**
     * @return stdClass
     */
    private function getTokenWithNoUserId()
    {
        return $this->getTokenWithout( [self::VALID_USER_ID] );
    }

    /**
     * @return stdClass
     */
    private function getTokenWithNoGroupId()
    {
        return $this->getTokenWithout( [self::VALID_GROUP_ID] );
    }

    /**
     * @return stdClass
     */
    private function getTokenWithoutSegments()
    {
        return $this->getTokenWithout( [self::VALID_SEGMENTS] );
    }

    /**
     * @return stdClass
     */
    private function getTokenWithInvalidAppId()
    {
        $token = $this->getTokenWithout( [self::VALID_APP_ID] );
        $token->appId = 'dogs';
        return $token;
    }

    /**
     * @return stdClass
     */
    private function getValidToken()
    {
        return $this->getTokenWithout( [] );
    }

    /**
     * @return stdClass
     */
    private function getExpiredToken()
    {
        $token = $this->getTokenWithout( [self::VALID_EXPIRY_DATE] );
        $token->exp = $this->getExpiredDate();
        return $token;
    }

    /**
     * @param stdClass $token
     * @return bool
     */
    private function authoriseToken( stdClass $token )
    {
        return $this->auth->isAuthorised( new MockTokenRequest( $this->serialiseToken( $token ) ) );
    }

    /**
     * @param $token
     * @return string
     */
    private function serialiseToken( $token )
    {
        return JWT::encode((array) $token, $this->key->getKeyMaterial(), $this->key->getAlgorithm());
    }

    /**
     * Set up
     */
    public function setUp(): void
    {
        $this->appIds = new StaticAppIdProvider( [self::APP_ID] );
        $this->key = new Key( "shhh... it's a secret", 'HS512' );
        $this->auth = new JwtTokenAuthenticator( $this->key, $this->appIds );
        $this->token = new stdClass();
        $this->testSegments = [ [ 'segmentId' => 1, 'isLocked' => false, 'priority' => 10 ] ];
    }

    /**
     * @test
     */
    public function givenNoneAlgorithm_throwsException()
    {
        self::expectException(\DomainException::class);
        $auth = new JwtTokenAuthenticator( new Key(' ', 'None'), $this->appIds );
        $auth->isAuthorised( new MockTokenRequest( JWT::encode([], ' ', 'None')) );
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
        $this->auth = new JwtTokenAuthenticator( new Key( 'Nope', 'HS512' ), $this->appIds );
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
        $this->assertTrue( $this->auth->isAuthorised( new MockTokenRequest( "Bearer ". $this->serialiseToken( $this->getValidToken() ) ) ) );
    }

    /**
     * @test
     */
    public function givenValidTokenButHeaderIsInvalid_WhenCallingIsAuthorised_ThenAuthorisationFails()
    {
        $this->assertFalse( $this->auth->isAuthorised( new MockTokenRequest( " 🐟 should be broken ". $this->serialiseToken( $this->getValidToken() ) ) ) );
    }
}
