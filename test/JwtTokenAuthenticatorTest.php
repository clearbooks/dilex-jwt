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
    const IS_ADMIN = true;

    const WITH = 0;

    const WITHOUT = 1;

    const VALID_USER_ID = 0;

    const VALID_APP_ID = 1;

    const VALID_GROUP_ID = 2;

    const VALID_EXPIRY_DATE = 3;

    const VALID_IS_ADMIN = 4;


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
            self::VALID_APP_ID => new PublicClaim( 'appId', 'labs' ),
            self::VALID_EXPIRY_DATE => new PublicClaim('exp', $this->getNonExpiredDate()),
            self::VALID_IS_ADMIN => new PublicClaim('isAdmin', self::IS_ADMIN)
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
        $serialised = ( new Jwt )->serialize( $token, EncryptionFactory::create( $this->algorithm ) );
        return $this->auth->isAuthorised( new MockTokenRequest( $serialised ) );
    }

    /**
     * Set up
     */
    public function setUp()
    {
        $this->algorithm = new Hs512( "shhh... it's a secret" );
        $this->auth = new JwtTokenAuthenticator( new Jwt, $this->algorithm );
        $this->token = new Token();
    }

    /**
     * @test
     */
    public function givenNoneAlgorithm_returnFalse()
    {
        $auth = new JwtTokenAuthenticator( $jwt = new Jwt, new None );
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
        $this->auth = new JwtTokenAuthenticator( new Jwt, new Hs512( 'Nope' ) );
        $this->assertFalse( $this->authoriseToken( $this->getValidToken() ) );
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
    }
}
